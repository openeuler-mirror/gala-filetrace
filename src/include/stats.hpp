#ifndef STATS_HPP
#define STATS_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "filetrace.h"

// Hard caps on aggregate table entry counts; when exceeded the least
// recently active entries are evicted (batch-wise). The per-file tables
// are NOT bounded by MAX_PROC_ENTRIES x MAX_PER_FILE_ENTRIES alone: that
// product (4096 x 1024 at the previous caps) is up to ~4M std::map nodes,
// i.e. hundreds of MB of resident memory, which is far too much for a
// monitor that is expected to stay loaded. A global budget is enforced on
// top of the per-process cap, so total memory stays bounded regardless of
// how many processes the workload fans out to (sizes measured on x86-64):
//   procs_   2048 x 88 B                                 ~ 180 KB
//   devices_ 2048 x 96 B + path strings                  ~ 250 KB
//   per_file 16384 x (map node + key string, ~160 B)     ~ 2.6 MB
// Worst case is therefore ~3 MB, not hundreds, and is independent of the
// event rate (measured: 120k events over 600 processes x 200 distinct long
// paths -> 2.7 MB). Both caps hold even when the entries are configured
// monitor paths: such entries are only *preferred* victims, not immune
// ones. Each sweep honors the veto first, and when that cannot free
// anything (or not enough) it degrades to veto-blind LRU eviction -- see
// the two-pass devices_ handling in on_event and the second sweep of
// enforce_per_file_budget in stats.cpp. Neither the device cap, the
// per-process cap nor the global budget can be defeated by the configured
// path set. A published snapshot shares the tables instead of copying
// them, so while one generation is published the live aggregate can hold a
// second copy of a table it is writing to: peak ≈ 2x.
static const size_t MAX_PROC_ENTRIES = 2048;
static const size_t MAX_DEVICE_ENTRIES = 2048;
static const size_t MAX_PER_FILE_ENTRIES = 128;          // per process
static const size_t MAX_TOTAL_PER_FILE_ENTRIES = 16384;  // all processes

// The budget trim cannot empty a table (each keeps at least one entry), so
// the worst case it must be able to reach is one entry per process. If the
// budget were below that floor it could never be satisfied and every event
// would redo the trim pass for nothing.
static_assert(MAX_TOTAL_PER_FILE_ENTRIES - MAX_TOTAL_PER_FILE_ENTRIES / 8 >
                  MAX_PROC_ENTRIES,
              "per-file budget must stay above the one-entry-per-process floor");

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
    // any path is accepted: paths outside the configured monitor set get
    // their own devices_ entry, and an empty path counts as dropped.
    void on_event(const struct event &e, const std::string &path);

    // Publish the current aggregate state.
    //
    // Publishing never walks the per-file aggregate and never copies a
    // table: a snapshot takes shared ownership of each process's table and
    // copies only the shells (ProcStat = 88 B, DeviceStat = 96 B). The work
    // is therefore O(#procs + #devices), capped by MAX_PROC_ENTRIES +
    // MAX_DEVICE_ENTRIES -- measured ~60 us with both tables at their caps
    // -- and independent of how many paths or events are tracked. With no
    // event since the last publish the cached generation is returned as-is:
    // no producer mutex, no rebuild, measured ~0.07 us.
    //
    // Sharing defers a copy rather than eliminating it, and the deferred
    // part is paid by the producer, not by the consumer of these methods:
    // on_event() clones a table (copy-on-write) the first time it writes to
    // one a snapshot still references. That costs ~4 us for a full
    // 128-entry table, at most once per process per published generation,
    // so no single call -- publish or on_event() -- is ever O(all per-file
    // entries); the cloning per generation is bounded by the entry budget
    // (16384 entries, i.e. well under a millisecond in total).
    //
    // snapshot_shared() is the cheap path (a refcount bump on a hit);
    // snapshot() returns a value copy of the same view and adds one shell
    // copy (~40 us at the caps), which a caller that wants an owned object
    // pays deliberately, while a TUI refreshing on a timer should hold the
    // shared view instead.
    std::shared_ptr<const StatsSnapshot> snapshot_shared() const;
    StatsSnapshot snapshot() const;

    // Full monitored path list (normalized), used for path matching.
    const std::vector<std::string> &monitor_paths() const { return paths_; }

    // How many configured paths were dropped at construction because the
    // device table already held MAX_DEVICE_ENTRIES of them. Non-zero means
    // the config is larger than the aggregate can represent; the caller is
    // expected to surface it (the TUI warns at startup). Final once the
    // constructor returns, so it needs no lock.
    size_t ignored_monitor_paths() const { return ignored_monitor_paths_; }

    // Build the full path "dir4/dir3/dir2/dir1/filename" from an event.
    // Pure path reconstruction: the result is NOT matched against the
    // configured monitor paths here. The caller decides whether the
    // event is monitored; on_event() counts non-matching paths under
    // their own key, and empty-path events are counted as dropped.
    static std::string event_path(const struct event &e);

    static uint64_t now_ms();

private:
    // Trim per_file tables, least recently active process first, until the
    // global entry budget (MAX_TOTAL_PER_FILE_ENTRIES) is met again.
    // keep_pid is never trimmed: the caller is inserting into it. Caller
    // holds mutex_.
    void enforce_per_file_budget(unsigned int keep_pid);

    mutable std::mutex mutex_;
    std::vector<std::string> paths_;       // configured monitor paths
    std::set<std::string> monitor_paths_;  // same as paths_, set for O(logP) lookups
    std::map<unsigned int, ProcStat> procs_; // keyed by pid
    std::map<std::string, DeviceStat> devices_; // keyed by rebuilt event path;
                                                // seeded with configured paths,
                                                // never above MAX_DEVICE_ENTRIES
    size_t ignored_monitor_paths_ = 0;     // configured paths dropped at ctor
    size_t per_file_entries_ = 0;          // sum of per_file sizes, budgeted
    uint64_t total_events_ = 0;
    uint64_t dropped_events_ = 0;
    uint64_t seq_ = 0;                     // monotonic counter for LRU order
    std::atomic<uint64_t> gen_{0};         // bumped on every mutation

    // Last published snapshot, keyed by the generation it captured. Holds
    // shared ownership of the per-file tables, which is what makes the
    // producer's next update copy-on-write instead of in-place.
    // Publish ordering is cache_mutex_ -> mutex_; producers only ever take
    // mutex_, so the two can never deadlock.
    mutable std::mutex cache_mutex_;
    mutable std::shared_ptr<StatsSnapshot> cache_;
    // The invariant: cache_ is a valid view of the current state iff
    // cache_ is set AND cache_gen_ == gen_. The initial cache_gen_ must
    // therefore NOT collide with gen_'s initial 0 -- otherwise "same
    // generation" would read as "cache valid" before the first publish
    // ever happened. The sentinel marks "never published" and can only
    // equal gen_ after a wrap-around of 2^64 mutations, i.e. never.
    static constexpr uint64_t kNeverPublishedGen =
        std::numeric_limits<uint64_t>::max();
    mutable uint64_t cache_gen_ = kNeverPublishedGen;
};

#endif // STATS_HPP
