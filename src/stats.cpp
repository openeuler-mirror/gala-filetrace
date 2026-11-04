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
        devices_[norm].path = norm;
    }
}

void TraceStats::on_event(const struct event &e, const std::string &path)
{
    // normalize the incoming path the same way the constructor normalizes
    // configured paths, so both build identical devices_ keys (a configured
    // "/var/log/" and events on it must not create two entries)
    std::string norm = path;
    while (norm.size() > 1 && norm.back() == '/') {
        norm.pop_back();
    }
    if (norm.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        dropped_events_++;
        gen_.fetch_add(1, std::memory_order_release);
        return;
    }

    uint64_t now = now_ms();
    uint64_t kind = classify_flag(e.flag);

    std::lock_guard<std::mutex> lock(mutex_);
    total_events_++;

    // process aggregate
    if (procs_.size() >= MAX_PROC_ENTRIES && procs_.find(e.pid) == procs_.end()) {
        evict_lru(procs_, MAX_PROC_ENTRIES,
                  [](const auto &kv) { return true; });
    }
    ProcStat &p = procs_[e.pid];
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
    // per_file is copy-on-write: clone it only when a published snapshot
    // still holds a reference (use_count() > 1). This keeps the table
    // mutation off any shared copy and bounds the clone work to one
    // process per refresh interval, instead of snapshot() deep-copying
    // every process under the producer mutex. The map is never declared
    // const, so in-place mutation at refcount 1 is well-defined; all
    // copies are made and dropped under this same mutex.
    if (!p.per_file || p.per_file.use_count() > 1) {
        p.per_file = std::make_shared<std::map<std::string, uint64_t>>(
            p.per_file ? *p.per_file : std::map<std::string, uint64_t>());
    }
    std::map<std::string, uint64_t> &files = *p.per_file;
    if (files.size() >= MAX_PER_FILE_ENTRIES &&
        files.find(path) == files.end()) {
        // configured monitor paths are never trimmed from per_file
        evict_cold_files(files, MAX_PER_FILE_ENTRIES, [this](const auto &kv) {
            return monitor_paths_.count(kv.first) == 0;
        });
    }
    files[path]++;
    p.last_active_ms = now;
    p.last_seq = ++seq_;

    // device aggregate; configured monitor paths are never evicted
    if (devices_.size() >= MAX_DEVICE_ENTRIES && devices_.find(path) == devices_.end()) {
        evict_lru(devices_, MAX_DEVICE_ENTRIES, [this](const auto &kv) {
            return monitor_paths_.count(kv.first) == 0;
        });
    }
    DeviceStat &d = devices_[path];
    if (d.path.empty()) {
        d.path = path;
    }
    d.last_active_ms = now;
    d.last_seq = ++seq_;
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
    // convenience wrapper: same view, handed out as a value
    return *snapshot_shared();
}
