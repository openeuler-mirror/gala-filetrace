#ifndef STATS_HPP
#define STATS_HPP

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "filetrace.h"

// Hard caps on aggregate table entry counts; when exceeded the least
// recently active entries are evicted (batch-wise). Worst-case memory
// is the product of the caps (MAX_PROC_ENTRIES x MAX_PER_FILE_ENTRIES
// per-path strings) plus the devices_ table, so lower MAX_PER_FILE_
// ENTRIES if resident size matters more than per-path detail.
static const size_t MAX_PROC_ENTRIES = 4096;
static const size_t MAX_DEVICE_ENTRIES = 4096;
static const size_t MAX_PER_FILE_ENTRIES = 1024;

// Aggregated statistics for one monitored file (device/file panel).
struct DeviceStat {
    std::string path;        // configured monitor path
    uint64_t ops = 0;        // total operations on this path
    uint64_t writes = 0;
    uint64_t opens = 0;
    uint64_t unlinks = 0;
    uint64_t renames = 0;
    uint64_t others = 0;
    uint64_t last_active_ms = 0;             // wall clock ms of last event
    uint64_t last_seq = 0;                   // monotonic event seq for LRU
};

// Aggregated statistics for one process touching monitored files.
struct ProcStat {
    unsigned int pid = 0;
    unsigned int ppid = 0;
    std::string cmd;
    unsigned int uid = 0;
    uint64_t ops = 0;                       // total operations by this process
    // Per-path op counts: monitor path for matched events, rebuilt event
    // path otherwise. Copy-on-write: a published snapshot shares the table
    // with the live aggregate, and on_event() clones it before an in-place
    // update only when a snapshot still holds a reference. Publishing a
    // snapshot therefore copies this pointer, never the table.
    // The deferred clone is paid by the producer (the ring-buffer callback
    // thread) and is bounded: one table of at most MAX_PER_FILE_ENTRIES
    // entries per process per published generation, ~4 us worst case.
    //
    // Never null for entries produced by on_event(). The pointee is
    // deliberately NOT const-qualified: writing through a pointer that was
    // de-consted from a const-declared object is UB, so the "read only"
    // contract for snapshot holders is by convention instead.
    std::shared_ptr<std::map<std::string, uint64_t>> per_file;
    uint64_t last_active_ms = 0;            // wall clock ms of last event
    uint64_t last_seq = 0;                  // monotonic event seq for LRU
};

// Snapshot of the aggregated state, handed to the TUI each refresh.
struct StatsSnapshot {
    std::vector<ProcStat> procs;    // sorted by pid (map key order)
    std::vector<DeviceStat> devices;
    uint64_t total_events = 0;
    uint64_t dropped_events = 0;
};

// Thread-safe aggregator fed from the ring-buffer callback.
class TraceStats {
public:
    explicit TraceStats(std::vector<std::string> monitor_paths);

    // Feed one BPF event. path is the rebuilt event path (see event_path());
    // only configured monitor paths aggregate; empty paths and non-empty
    // paths outside the monitor set count as dropped.
    void on_event(const struct event &e, const std::string &path);

    // Copy the current aggregate state. Producers only enqueue the event
    // under a short critical section; the heavy aggregation and deep copy
    // run here, outside the producer mutex (drain-and-build, published via
    // an O(1) pointer swap), so the ring-buffer consumer is never stalled
    // by a snapshot.
    StatsSnapshot snapshot() const;

    // Full monitored path list (normalized), used for path matching.
    const std::vector<std::string> &monitor_paths() const { return paths_; }

    // Build the absolute event path "/dir4/dir3/dir2/dir1/filename"
    // from an event (the leading '/' is always present for non-empty
    // results, so configured absolute paths can be prefix-matched).
    // Pure path reconstruction: the result is NOT matched against the
    // configured monitor paths here. The caller decides whether the
    // event is monitored; on_event() aggregates only configured monitor
    // paths, everything else (unmatched, unrebuildable) counts as dropped.
    static std::string event_path(const struct event &e);

    static uint64_t now_ms();

private:
    // Aggregated state, built off the producer path and published via an
    // O(1) shared_ptr swap; producers never touch a published instance.
    struct Aggregate {
        std::map<unsigned int, ProcStat> procs; // keyed by pid
        std::map<std::string, DeviceStat> devices; // keyed by rebuilt path
        uint64_t seq = 0;                      // monotonic counter for LRU
        uint64_t total_events = 0;
        uint64_t dropped_events = 0;
    };

    // Feed event queued by on_event(), aggregated by snapshot() off the
    // producer path.
    struct PendingEvent {
        struct event e;
        std::string path;   // normalized feed path (never empty)
    };

    // Cap on queued events: past this the oldest events are dropped (and
    // counted as dropped) so the queue cannot grow without bound when the
    // consumer stalls.
    static const size_t kMaxPendingEvents = 65536;

    mutable std::mutex mutex_;             // guards the queue + deltas below
    mutable std::mutex build_mutex_;       // serializes snapshot() builders
    mutable std::deque<PendingEvent> pending_;
    mutable uint64_t pending_total_events_ = 0;    // deltas not yet folded into last_
    mutable uint64_t pending_dropped_events_ = 0;
    mutable std::shared_ptr<const Aggregate> last_; // latest published state
    std::vector<std::string> paths_;       // configured monitor paths
    std::set<std::string> monitor_paths_;  // same as paths_, set for O(logP) lookups

    // Fold one queued feed event into the aggregate. Runs on the
    // snapshot() builder thread, never under the producer mutex.
    static void apply_event(Aggregate &agg, const struct event &e,
                            const std::string &norm,
                            const std::set<std::string> &monitor_paths,
                            uint64_t now);
};

#endif // STATS_HPP
