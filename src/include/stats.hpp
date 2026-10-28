#ifndef STATS_HPP
#define STATS_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "filetrace.h"

// Aggregated statistics for one monitored file (device/file panel).
struct DeviceStat {
    std::string path;        // configured monitor path
    uint64_t ops = 0;        // total operations on this path
    uint64_t writes = 0;
    uint64_t opens = 0;
    uint64_t unlinks = 0;
    uint64_t renames = 0;
    uint64_t others = 0;
};

// Aggregated statistics for one process touching monitored files.
struct ProcStat {
    unsigned int pid = 0;
    unsigned int ppid = 0;
    std::string cmd;
    unsigned int uid = 0;
    uint64_t ops = 0;                       // total operations by this process
    std::map<std::string, uint64_t> per_file; // ops per monitored path
    uint64_t last_active_ms = 0;            // wall clock ms of last event
};

// Snapshot of the aggregated state, handed to the TUI each refresh.
struct StatsSnapshot {
    std::vector<ProcStat> procs;    // sorted by caller
    std::vector<DeviceStat> devices;
    uint64_t total_events = 0;
    uint64_t dropped_events = 0;
};

// Thread-safe aggregator fed from the ring-buffer callback.
class TraceStats {
public:
    explicit TraceStats(std::vector<std::string> monitor_paths);

    // Feed one BPF event; path must be a normalized monitored path.
    void on_event(const struct event &e, const std::string &path);

    // Copy the current aggregate state under lock.
    StatsSnapshot snapshot() const;

    // Full monitored path list (normalized), used for path matching.
    const std::vector<std::string> &monitor_paths() const { return paths_; }

    // Build the full path "dir4/dir3/dir2/dir1/filename" from an event,
    // then match it against the configured monitor paths. Returns the
    // matched configured path, or "" when the event is not monitored.
    static std::string event_path(const struct event &e);

    static uint64_t now_ms();

private:
    mutable std::mutex mutex_;
    std::vector<std::string> paths_;       // configured monitor paths
    std::map<unsigned int, ProcStat> procs_; // keyed by pid
    std::map<std::string, DeviceStat> devices_; // keyed by configured path
    uint64_t total_events_ = 0;
    uint64_t dropped_events_ = 0;
};

#endif // STATS_HPP
