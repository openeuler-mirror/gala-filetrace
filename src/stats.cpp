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
    if (p.per_file.size() >= MAX_PER_FILE_ENTRIES &&
        p.per_file.find(norm) == p.per_file.end()) {
        // configured monitor paths are never trimmed from per_file
        evict_cold_files(p.per_file, MAX_PER_FILE_ENTRIES, [this](const auto &kv) {
            return monitor_paths_.count(kv.first) == 0;
        });
    }
    p.per_file[norm]++;
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
        evict_lru(devices_, MAX_DEVICE_ENTRIES, [this](const auto &kv) {
            return monitor_paths_.count(kv.first) == 0;
        });
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
}

StatsSnapshot TraceStats::snapshot() const
{
    StatsSnapshot snap;
    std::lock_guard<std::mutex> lock(mutex_);
    snap.total_events = total_events_;
    snap.dropped_events = dropped_events_;
    snap.devices.reserve(devices_.size());
    for (const auto &kv : devices_) {
        snap.devices.push_back(kv.second);
    }
    snap.procs.reserve(procs_.size());
    for (const auto &kv : procs_) {
        snap.procs.push_back(kv.second);
    }
    return snap;
}
