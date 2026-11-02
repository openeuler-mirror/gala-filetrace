#include "stats.hpp"

#include <sys/time.h>
#include <algorithm>
#include <cstring>

static uint64_t classify_flag(int flag)
{
    switch (flag) {
        case SYS_write:      return 1 << 0;
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
    ProcStat &p = procs_[e.pid];
    p.pid = e.pid;
    p.ppid = e.ppid;
    p.cmd = std::string(e.cmd, strnlen(e.cmd, sizeof(e.cmd)));
    p.uid = e.uid;
    p.ops++;
    p.per_file[path]++;
    p.last_active_ms = now;

    // device aggregate
    DeviceStat &d = devices_[path];
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
