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
static void evict_cold_files(std::map<std::string, uint64_t> &m, size_t cap)
{
    size_t target = cap - cap / EVICT_TARGET_FRAC;
    if (m.size() <= target) {
        return;
    }
    std::vector<uint64_t> counts;
    counts.reserve(m.size());
    for (const auto &kv : m) {
        counts.push_back(kv.second);
    }
    size_t excess = m.size() - target;
    std::nth_element(counts.begin(), counts.begin() + excess - 1, counts.end());
    uint64_t threshold = counts[excess - 1];
    for (auto it = m.begin(); it != m.end() && excess > 0;) {
        if (it->second <= threshold) {
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
    std::string fullpath;
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
    if (fullpath.empty()) {
        fullpath = "/";
    }
    return fullpath;
}

TraceStats::TraceStats(std::vector<std::string> monitor_paths)
{
    for (auto &p : monitor_paths) {
        std::string norm = p;
        while (norm.size() > 1 && norm.back() == '/') {
            norm.pop_back();
        }
        if (norm.empty()) {
            norm = "/";
        }
        paths_.push_back(norm);
        devices_[norm].path = norm;
    }
}

void TraceStats::on_event(const struct event &e, const std::string &path)
{
    if (path.empty()) {
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
        // refresh cmd on change (pid reuse / exec) without allocating on
        // the hot path when the name is unchanged
        size_t len = strnlen(e.cmd, sizeof(e.cmd));
        if (len != p.cmd.size() || memcmp(p.cmd.data(), e.cmd, len) != 0) {
            p.cmd.assign(e.cmd, len);
        }
    }
    p.uid = e.uid;
    p.ops++;
    if (p.per_file.size() >= MAX_PER_FILE_ENTRIES &&
        p.per_file.find(path) == p.per_file.end()) {
        evict_cold_files(p.per_file, MAX_PER_FILE_ENTRIES);
    }
    p.per_file[path]++;
    p.last_active_ms = now;
    p.last_seq = ++seq_;

    // device aggregate; configured monitor paths are never evicted
    if (devices_.size() >= MAX_DEVICE_ENTRIES && devices_.find(path) == devices_.end()) {
        evict_lru(devices_, MAX_DEVICE_ENTRIES, [this](const auto &kv) {
            return std::find(paths_.begin(), paths_.end(), kv.first) == paths_.end();
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
