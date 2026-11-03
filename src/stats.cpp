#include "stats.hpp"

#include <sys/time.h>
#include <algorithm>
#include <cstring>
#include <vector>

// Batch-evict the least recently active entries (by monotonic last_seq)
// when a table hits its cap, trimming down to 7/8 of the cap. One O(n)
// selection pass per batch instead of a scan per event, and no dependence
// on wall clock (ties / clock rollback cannot misorder). `evictable`
// may veto individual victims (e.g. configured monitor paths).
// Probe happens before inserting a NEW key, so the key being processed
// is never displaced.
static const size_t EVICT_TARGET_FRAC = 8; // trim back to 7/8 of cap

template <typename Map, typename Evictable>
static void evict_lru(Map &m, size_t cap, Evictable evictable)
{
    size_t target = cap - cap / EVICT_TARGET_FRAC;
    if (m.size() <= target) {
        return;
    }
    std::vector<uint64_t> seqs;
    seqs.reserve(m.size());
    for (const auto &kv : m) {
        if (evictable(kv)) {
            seqs.push_back(kv.second.last_seq);
        }
    }
    if (seqs.empty()) {
        return;
    }
    size_t excess = std::min(m.size() - target, seqs.size());
    std::nth_element(seqs.begin(), seqs.begin() + excess - 1, seqs.end());
    uint64_t threshold = seqs[excess - 1];
    for (auto it = m.begin(); it != m.end() && excess > 0;) {
        if (it->second.last_seq <= threshold && evictable(*it)) {
            it = m.erase(it);
            excess--;
        } else {
            ++it;
        }
    }
}

// per_file entries carry no seq; trim the least-touched ones instead.
// `evictable` may veto victims (configured monitor paths are protected).
template <typename Evictable>
static void evict_cold_files(std::map<std::string, uint64_t> &m, size_t cap,
                             Evictable evictable)
{
    size_t target = cap - cap / EVICT_TARGET_FRAC;
    if (m.size() <= target) {
        return;
    }
    std::vector<uint64_t> counts;
    counts.reserve(m.size());
    for (const auto &kv : m) {
        if (evictable(kv)) {
            counts.push_back(kv.second);
        }
    }
    if (counts.empty()) {
        return;
    }
    size_t excess = std::min(m.size() - target, counts.size());
    std::nth_element(counts.begin(), counts.begin() + excess - 1, counts.end());
    uint64_t threshold = counts[excess - 1];
    for (auto it = m.begin(); it != m.end() && excess > 0;) {
        if (it->second <= threshold && evictable(*it)) {
            it = m.erase(it);
            excess--;
        } else {
            ++it;
        }
    }
}

static uint64_t classify_flag(int flag)
{
    switch (flag) {
        case SYS_write:            return 1 << 0;
        case SYS_copy_file_range:  return 1 << 0;
        case SYS_openat:     return 1 << 1;
        case SYS_unlinkat:   return 1 << 2;
        case SYS_rename:
        case SYS_renameat:
        case SYS_renameat2:  return 1 << 3;
        default:             return 1 << 4;
    }
}

uint64_t TraceStats::now_ms()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

std::string TraceStats::event_path(const struct event &e)
{
    // rename/renameat events carry the absolute destination in filename;
    // when it is already absolute, it IS the path and the dir chain
    // (which describes the source directory) must not be prepended
    if (e.filename[0] == '/') {
        return std::string(e.filename);
    }
    std::string fullpath;
    // dirs + filename are fixed-size arrays; one reservation avoids
    // repeated reallocation while appending
    fullpath.reserve(sizeof(e.dir4) + sizeof(e.dir3) + sizeof(e.dir2) +
                     sizeof(e.dir1) + sizeof(e.filename) + 4);
    const char *parts[] = {e.dir4, e.dir3, e.dir2, e.dir1, e.filename};
    for (const char *part : parts) {
        if (part[0] == '\0' || (part[0] == '/' && part[1] == '\0')) {
            continue;
        }
        if (!fullpath.empty()) {
            fullpath.push_back('/');
        }
        fullpath += part;
    }
    if (!fullpath.empty() && fullpath.front() != '/') {
        fullpath.insert(fullpath.begin(), '/');
    }
    // no path information at all: return "" (same as exporter's
    // get_full_path); on_event() counts such events as dropped
    return fullpath;
}

TraceStats::TraceStats(std::vector<std::string> monitor_paths)
{
    for (auto &p : monitor_paths) {
        if (p.empty()) {
            // an empty configured path is meaningless input, not "/"
            continue;
        }
        std::string norm = p;
        while (norm.size() > 1 && norm.back() == '/') {
            norm.pop_back();
        }
        paths_.push_back(norm);
        if (!monitor_paths_.insert(norm).second) {
            // duplicate configured path: one devices_ entry is enough
            paths_.pop_back();
            continue;
        }
    }
}

void TraceStats::on_event(const struct event &e, const std::string &path)
{
    // normalize the incoming path the same way the constructor normalizes
    // configured paths, so both build identical aggregate keys. Events on
    // paths outside the configured monitor set still aggregate under
    // their own key (the snapshot shows them as unconfigured entries);
    // only events with no path information at all are dropped.
    std::string norm = path;
    while (norm.size() > 1 && norm.back() == '/') {
        norm.pop_back();
    }
    if (norm.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_dropped_events_++;
        return;
    }

    // Keep the producer critical section O(1): just enqueue the event.
    // The actual aggregation runs on the snapshot() builder thread.
    std::lock_guard<std::mutex> lock(mutex_);
    if (pending_.size() >= kMaxPendingEvents) {
        // bounded queue: drop the oldest event rather than grow without
        // limit when the consumer stalls; it counts as dropped.
        pending_.pop_front();
        pending_dropped_events_++;
    }
    PendingEvent pe;
    pe.e = e;
    pe.path = std::move(norm);
    pending_.push_back(std::move(pe));
    pending_total_events_++;
}

// Fold one queued feed event into the aggregate. Runs on the snapshot()
// builder thread, never under the producer mutex. `monitor_paths` is
// immutable after construction, so it is read without locking.
void TraceStats::apply_event(TraceStats::Aggregate &agg, const struct event &e,
                        const std::string &norm,
                        const std::set<std::string> &monitor_paths,
                        uint64_t now)
{
    uint64_t kind = classify_flag(e.flag);

    // process aggregate
    if (agg.procs.size() >= MAX_PROC_ENTRIES && agg.procs.find(e.pid) == agg.procs.end()) {
        evict_lru(agg.procs, MAX_PROC_ENTRIES,
                  [](const auto &kv) { return true; });
    }
    ProcStat &p = agg.procs[e.pid];
    p.pid = e.pid;
    p.ppid = e.ppid;
    {
        // refresh cmd on change (exec / pid reuse) without allocating on
        // the hot path when the name is unchanged. Note: cmd is a thread
        // comm while the key is tgid, and the event carries no process
        // start identity, so counters stay accumulated across exec/pid
        // reuse under the same pid (display shows the latest name).
        size_t len = strnlen(e.cmd, sizeof(e.cmd));
        if (len != p.cmd.size() || memcmp(p.cmd.data(), e.cmd, len) != 0) {
            p.cmd.assign(e.cmd, len);
        }
    }
    p.uid = e.uid;
    p.ops++;
    if (p.per_file.size() >= MAX_PER_FILE_ENTRIES &&
        p.per_file.find(norm) == p.per_file.end()) {
        // configured monitor paths are never trimmed from per_file
        evict_cold_files(p.per_file, MAX_PER_FILE_ENTRIES, [&monitor_paths](const auto &kv) {
            return monitor_paths.count(kv.first) == 0;
        });
    }
    p.per_file[norm]++;
    p.last_active_ms = now;
    p.last_seq = ++agg.seq;

    // device aggregate; configured monitor paths are never evicted
    if (agg.devices.size() >= MAX_DEVICE_ENTRIES && agg.devices.find(norm) == agg.devices.end()) {
        evict_lru(agg.devices, MAX_DEVICE_ENTRIES, [&monitor_paths](const auto &kv) {
            return monitor_paths.count(kv.first) == 0;
        });
    }
    DeviceStat &d = agg.devices[norm];
    if (d.path.empty()) {
        d.path = norm;
    }
    d.last_active_ms = now;
    d.last_seq = ++agg.seq;
    d.ops++;
    if (kind & (1 << 0)) d.writes++;
    else if (kind & (1 << 1)) d.opens++;
    else if (kind & (1 << 2)) d.unlinks++;
    else if (kind & (1 << 3)) d.renames++;
    else d.others++;

    // publish a new generation so the next snapshot() rebuilds the cache
    gen_.fetch_add(1, std::memory_order_release);
}

// Called with mutex_ held. Every per_file table is at most
// MAX_PER_FILE_ENTRIES entries, so a hostile fan-out (many processes, many
// paths each) could still hold MAX_PROC_ENTRIES x MAX_PER_FILE_ENTRIES
// entries. This keeps the sum under MAX_TOTAL_PER_FILE_ENTRIES by halving
// the tables of the least recently active processes, coldest paths first.
// keep_pid (the process being updated by the caller) is skipped so the
// entry just counted can never be its own victim.
//
// Trimming stops at 7/8 of the budget rather than at the budget itself:
// each enforcement then frees ~2k entries, which is how many new entries
// must arrive before the (O(P log P)) victim ordering is paid for again.
// That amortization only works if a pass can actually free something, so
// the pass is guaranteed to make progress: see the second sweep below.
void TraceStats::enforce_per_file_budget(unsigned int keep_pid)
{
    if (per_file_entries_ <= MAX_TOTAL_PER_FILE_ENTRIES) {
        return;
    }
    const size_t target =
        MAX_TOTAL_PER_FILE_ENTRIES - MAX_TOTAL_PER_FILE_ENTRIES / EVICT_TARGET_FRAC;

    std::vector<std::pair<uint64_t, unsigned int>> order; // last_seq, pid
    order.reserve(procs_.size());
    for (const auto &kv : procs_) {
        if (kv.first != keep_pid && kv.second.per_file && !kv.second.per_file->empty()) {
            order.push_back({kv.second.last_seq, kv.first});
        }
    }
    // oldest first; ties broken by pid so the trim order is deterministic
    std::sort(order.begin(), order.end());

    auto veto = [this](const auto &kv) { return monitor_paths_.count(kv.first) == 0; };
    auto all = [](const auto &) { return true; };

    // First sweep: keep configured monitor paths visible, as usual. Each
    // table keeps at least one entry (halving never empties it), which is
    // what lets the second sweep below reach the target.
    for (const auto &victim : order) {
        if (per_file_entries_ <= target) {
            return;
        }
        ProcStat &p = procs_[victim.second];
        size_t keep = std::max<size_t>(p.per_file->size() / 2, 1);
        per_file_entries_ -= trim_table(p.per_file, keep, veto);
    }

    // Second sweep: the veto is a preference, not a guarantee. A table made
    // up entirely of configured paths would otherwise keep the budget
    // unreachable, which would cost this whole O(P log P) pass on *every*
    // following event. Dropping the coldest protected entries instead
    // keeps the budget satisfiable; by the static_assert in stats.hpp the
    // one-entry-per-table floor is always below the target.
    for (const auto &victim : order) {
        if (per_file_entries_ <= target) {
            return;
        }
        ProcStat &p = procs_[victim.second];
        size_t keep = std::max<size_t>(p.per_file->size() / 2, 1);
        per_file_entries_ -= trim_table(p.per_file, keep, all);
    }
}

std::shared_ptr<const StatsSnapshot> TraceStats::snapshot_shared() const
{
    // Publishers serialize here, not on the producer mutex: one build per
    // mutation generation, shared by every reader that arrives meanwhile.
    // Lock order is cache_mutex_ -> mutex_; producers only ever take
    // mutex_, so no cycle is possible.
    std::lock_guard<std::mutex> publish(cache_mutex_);
    if (cache_ && cache_gen_ == gen_.load(std::memory_order_acquire)) {
        // nothing changed since the last publish: no lock on mutex_, no
        // rebuild, not even a copy of the shells -- just a refcount bump
        return cache_;
    }

    auto pub = std::make_shared<StatsSnapshot>();
    uint64_t captured;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        pub->total_events = total_events_;
        pub->dropped_events = dropped_events_;
        pub->devices.reserve(devices_.size());
        for (const auto &kv : devices_) {
            pub->devices.push_back(kv.second);
        }
        pub->procs.reserve(procs_.size());
        for (const auto &kv : procs_) {
            // copies the ProcStat shell and shares its per_file table;
            // the producer clones that table on its next write
            pub->procs.push_back(kv.second);
        }
        // read the generation under the same lock, so a mutation that
        // lands right after the unlock is seen as a newer generation and
        // forces a rebuild instead of being served stale
        captured = gen_.load(std::memory_order_relaxed);
    }
    cache_ = std::move(pub);
    cache_gen_ = captured;
    return cache_;
}

StatsSnapshot TraceStats::snapshot() const
{
    // One builder at a time: the drain/build/publish sequence below takes
    // sole ownership of the published state, so concurrent builders would
    // otherwise base their copy on a detached aggregate.
    std::lock_guard<std::mutex> build(build_mutex_);

    std::deque<PendingEvent> batch;
    uint64_t ev = 0, dr = 0;
    {
        // short critical section: swap out the queue, take the deltas
        std::lock_guard<std::mutex> lock(mutex_);
        batch.swap(pending_);
        ev = pending_total_events_;
        dr = pending_dropped_events_;
        pending_total_events_ = pending_dropped_events_ = 0;
    }

    // Take sole ownership of the published aggregate (O(1)); producers
    // never touch it, so everything from here on runs lock-free.
    std::shared_ptr<Aggregate> owned;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        owned = std::const_pointer_cast<Aggregate>(last_);
        last_.reset();
    }
    if (!owned) {
        owned = std::make_shared<Aggregate>();
    }
    // configured paths always appear in the snapshot, even before their
    // first event (the aggregate is created once and reused, so seeding
    // here covers every later snapshot as well)
    for (const auto &p : paths_) {
        DeviceStat &d = owned->devices[p];
        if (d.path.empty()) {
            d.path = p;
        }
    }
    owned->total_events += ev;
    owned->dropped_events += dr;
    uint64_t now = now_ms();
    for (auto &pe : batch) {
        apply_event(*owned, pe.e, pe.path, monitor_paths_, now);
    }

    // Build the TUI-facing vectors off the producer path.
    StatsSnapshot snap;
    snap.total_events = owned->total_events;
    snap.dropped_events = owned->dropped_events;
    snap.devices.reserve(owned->devices.size());
    for (const auto &kv : owned->devices) {
        snap.devices.push_back(kv.second);
    }
    snap.procs.reserve(owned->procs.size());
    for (const auto &kv : owned->procs) {
        snap.procs.push_back(kv.second);
    }

    // Publish via an O(1) pointer swap.
    std::shared_ptr<const Aggregate> published = owned;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_ = published;
    }
    return snap;
}
