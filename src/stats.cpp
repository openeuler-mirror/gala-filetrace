#include "stats.hpp"

#include <sys/time.h>
#include <algorithm>
#include <cstring>
#include <utility>
#include <vector>

// Batch-evict the least recently active entries (by monotonic last_seq)
// when a table hits its cap, trimming down to 7/8 of the cap. One O(n)
// selection pass per batch instead of a scan per event, and no dependence
// on wall clock (ties / clock rollback cannot misorder). `evictable`
// may veto individual victims (e.g. configured monitor paths); `on_erase`
// runs on each victim just before it is removed, so callers can keep
// derived bookkeeping (the per-file entry budget) in sync.
// Probe happens before inserting a NEW key, so the key being processed
// is never displaced.
static const size_t EVICT_TARGET_FRAC = 8; // trim back to 7/8 of cap

template <typename Map, typename Evictable, typename OnErase>
static void evict_lru(Map &m, size_t cap, Evictable evictable, OnErase on_erase)
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
            on_erase(it->second);
            it = m.erase(it);
            excess--;
        } else {
            ++it;
        }
    }
}

// Trim a per_file table down to `target` entries, dropping the coldest
// (least touched) ones first. `evictable` may veto victims (configured
// monitor paths are protected). Returns the number of entries removed so
// the caller can keep the global entry budget in sync.
template <typename Evictable>
static size_t trim_cold_files(std::map<std::string, uint64_t> &m, size_t target,
                              Evictable evictable)
{
    if (m.size() <= target) {
        return 0;
    }
    std::vector<uint64_t> counts;
    counts.reserve(m.size());
    for (const auto &kv : m) {
        if (evictable(kv)) {
            counts.push_back(kv.second);
        }
    }
    if (counts.empty()) {
        return 0;
    }
    size_t excess = std::min(m.size() - target, counts.size());
    std::nth_element(counts.begin(), counts.begin() + excess - 1, counts.end());
    uint64_t threshold = counts[excess - 1];
    size_t removed = 0;
    for (auto it = m.begin(); it != m.end() && excess > 0;) {
        if (it->second <= threshold && evictable(*it)) {
            it = m.erase(it);
            excess--;
            removed++;
        } else {
            ++it;
        }
    }
    return removed;
}

// Trim one process's table down to `target` entries and return how many
// were dropped. The table may be shared with a published snapshot, in
// which case it is cloned first (copy-on-write).
//
// The `pick` pre-scan is deliberate: cloning costs a full table copy
// (~4 us for a full 128-entry table), so a table whose entries are all
// vetoed must not pay for a copy that could never be used -- that is the
// difference between "budget unreachable" costing one scan per event and
// costing one clone per event.
template <typename Pick>
static size_t trim_table(std::shared_ptr<std::map<std::string, uint64_t>> &table,
                         size_t target, Pick pick)
{
    if (!table || table->size() <= target) {
        return 0;
    }
    bool droppable = false;
    for (const auto &kv : *table) {
        if (pick(kv)) {
            droppable = true;
            break;
        }
    }
    if (!droppable) {
        return 0;
    }
    if (table.use_count() > 1) {
        table = std::make_shared<std::map<std::string, uint64_t>>(*table);
    }
    return trim_cold_files(*table, target, pick);
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
                  [](const auto &) { return true; },
                  [this](const ProcStat &victim) {
                      // its per_file table leaves with it
                      if (victim.per_file) {
                          per_file_entries_ -= victim.per_file->size();
                      }
                  });
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

    // per_file is copy-on-write: a published snapshot shares this table,
    // so clone it before the in-place update while a snapshot still holds
    // a reference (use_count() > 1). Exactly one clone per process per
    // published generation at most, and the cost is paid here by the
    // producer instead of a deep copy of every process inside snapshot().
    if (!p.per_file || p.per_file.use_count() > 1) {
        p.per_file = p.per_file
                         ? std::make_shared<std::map<std::string, uint64_t>>(*p.per_file)
                         : std::make_shared<std::map<std::string, uint64_t>>();
    }
    std::map<std::string, uint64_t> &files = *p.per_file;

    if (files.size() >= MAX_PER_FILE_ENTRIES && files.find(norm) == files.end()) {
        const size_t keep =
            MAX_PER_FILE_ENTRIES - MAX_PER_FILE_ENTRIES / EVICT_TARGET_FRAC;
        // configured monitor paths normally survive the trim
        size_t removed = trim_cold_files(
            files, keep, [this](const auto &kv) { return monitor_paths_.count(kv.first) == 0; });
        if (removed == 0) {
            // every entry is a protected monitor path: the cap still has
            // to hold, or the table grows with the configured path set
            removed = trim_cold_files(files, keep, [](const auto &) { return true; });
        }
        per_file_entries_ -= removed;
    }
    auto ins = files.emplace(norm, uint64_t{0});
    if (ins.second) {
        per_file_entries_++;
    }
    ins.first->second++;
    // the per-process cap alone still allows MAX_PROC_ENTRIES x
    // MAX_PER_FILE_ENTRIES entries; keep the global footprint bounded
    enforce_per_file_budget(e.pid);
    p.last_active_ms = now;
    p.last_seq = ++seq_;

    // device aggregate; configured monitor paths are never evicted.
    // Every configured path is seeded into devices_ by the constructor and
    // survives every eviction (the veto), so when the table holds nothing
    // but configured paths there is nothing to trim — checking
    // devices_.size() > monitor_paths_.size() is O(1) and avoids paying a
    // full evict_lru scan (which would find no victim) for every new-path
    // event once the configured set alone fills the table.
    if (devices_.size() >= MAX_DEVICE_ENTRIES && devices_.find(norm) == devices_.end() &&
        devices_.size() > monitor_paths_.size()) {
        evict_lru(devices_, MAX_DEVICE_ENTRIES,
                  [this](const auto &kv) {
                      return monitor_paths_.count(kv.first) == 0;
                  },
                  [](const DeviceStat &) {});
    }
    DeviceStat &d = devices_[norm];
    if (d.path.empty()) {
        d.path = norm;
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
