#undef NDEBUG  // keep every assert active even if built with -DNDEBUG
#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <atomic>
#include <thread>
#include <vector>

#include "stats.hpp"

static struct event make_event(unsigned int pid, const char *cmd,
                               const char *filename, int flag)
{
    struct event e;
    memset(&e, 0, sizeof(e));
    e.pid = pid;
    e.ppid = 1;
    e.uid = 1000;
    snprintf(e.cmd, sizeof(e.cmd), "%s", cmd);
    snprintf(e.filename, sizeof(e.filename), "%s", filename);
    e.flag = flag;
    return e;
}

static void test_event_path_rebuild()
{
    struct event e = make_event(1, "test", "hosts", SYS_write);
    snprintf(e.dir1, sizeof(e.dir1), "etc");
    std::string path = TraceStats::event_path(e);
    assert(path == "/etc/hosts");
    std::cout << "test_event_path_rebuild passed" << std::endl;
}

static void test_event_path_absolute_filename()
{
    // rename events carry the absolute destination in filename: it IS
    // the path and the dir chain must not be prepended
    struct event e = make_event(1, "test", "/tmp/newname", SYS_rename);
    snprintf(e.dir1, sizeof(e.dir1), "etc");
    snprintf(e.dir2, sizeof(e.dir2), "log");
    assert(TraceStats::event_path(e) == "/tmp/newname");
    std::cout << "test_event_path_absolute_filename passed" << std::endl;
}

static void test_event_path_root()
{
    struct event e = make_event(1, "test", "", SYS_write);
    snprintf(e.dir1, sizeof(e.dir1), "/");
    // no path information at all: "" (same as exporter's get_full_path),
    // so on_event() can count it as dropped
    assert(TraceStats::event_path(e) == "");
    std::cout << "test_event_path_root passed" << std::endl;
}

static void test_aggregation()
{
    TraceStats stats({"/etc/hosts"});

    struct event e = make_event(100, "bash", "hosts", SYS_write);
    stats.on_event(e, "/etc/hosts");
    stats.on_event(e, "/etc/hosts");

    struct event e2 = make_event(100, "bash", "hosts", SYS_openat);
    stats.on_event(e2, "/etc/hosts");

    struct event e3 = make_event(200, "vim", "hosts", SYS_unlinkat);
    stats.on_event(e3, "/etc/hosts");

    // empty path means unmatched/unmonitored, counts as dropped
    stats.on_event(e3, "");

    StatsSnapshot snap = stats.snapshot();
    assert(snap.total_events == 4);
    assert(snap.dropped_events == 1);

    assert(snap.procs.size() == 2);
    // procs keyed by pid, order is ascending pid in the map
    assert(snap.procs[0].pid == 100);
    assert(snap.procs[0].ops == 3);
    assert(snap.procs[0].cmd == "bash");
    assert(snap.procs[0].per_file->at("/etc/hosts") == 3);
    assert(snap.procs[1].pid == 200);
    assert(snap.procs[1].ops == 1);

    assert(snap.devices.size() == 1);
    assert(snap.devices[0].path == "/etc/hosts");
    assert(snap.devices[0].ops == 4);
    assert(snap.devices[0].writes == 2);
    assert(snap.devices[0].opens == 1);
    assert(snap.devices[0].unlinks == 1);
    assert(snap.devices[0].renames == 0);
    std::cout << "test_aggregation passed" << std::endl;
}

static void test_trailing_slash_normalized()
{
    TraceStats stats({"/etc/hosts/"});
    assert(stats.monitor_paths()[0] == "/etc/hosts");

    struct event e = make_event(100, "bash", "hosts", SYS_write);
    stats.on_event(e, "/etc/hosts");
    StatsSnapshot snap = stats.snapshot();
    assert(snap.devices.size() == 1);
    assert(snap.devices[0].ops == 1);
    std::cout << "test_trailing_slash_normalized passed" << std::endl;
}

static void test_copy_file_range_is_write()
{
    TraceStats stats({"/etc/hosts"});

    struct event e = make_event(100, "cp", "hosts", SYS_copy_file_range);
    stats.on_event(e, "/etc/hosts");

    StatsSnapshot snap = stats.snapshot();
    assert(snap.devices.size() == 1);
    assert(snap.devices[0].writes == 1);
    assert(snap.devices[0].others == 0);
    std::cout << "test_copy_file_range_is_write passed" << std::endl;
}

static void test_classification()
{
    TraceStats stats({"/etc/hosts"});

    struct event e = make_event(100, "mv", "hosts", SYS_rename);
    stats.on_event(e, "/etc/hosts");
    struct event e2 = make_event(100, "mv", "hosts", SYS_renameat2);
    stats.on_event(e2, "/etc/hosts");
    struct event e3 = make_event(100, "sh", "hosts", SYS_dup2);
    stats.on_event(e3, "/etc/hosts");

    StatsSnapshot snap = stats.snapshot();
    assert(snap.devices.size() == 1);
    assert(snap.devices[0].renames == 2);
    assert(snap.devices[0].others == 1);
    std::cout << "test_classification passed" << std::endl;
}

static void test_cmd_refresh_on_exec()
{
    TraceStats stats({"/etc/hosts"});

    struct event e = make_event(100, "bash", "hosts", SYS_write);
    stats.on_event(e, "/etc/hosts");
    stats.on_event(e, "/etc/hosts");

    // same pid re-executes into a new name; snapshot must not go stale
    struct event e2 = make_event(100, "python", "hosts", SYS_openat);
    stats.on_event(e2, "/etc/hosts");

    StatsSnapshot snap = stats.snapshot();
    assert(snap.procs.size() == 1);
    // display shows the latest name; counters stay accumulated (cmd is a
    // thread comm, the key is tgid — no process identity to reset on)
    assert(snap.procs[0].cmd == "python");
    assert(snap.procs[0].ops == 3);
    assert(snap.procs[0].per_file->at("/etc/hosts") == 3);
    std::cout << "test_cmd_refresh_on_exec passed" << std::endl;
}

static void test_per_file_capped()
{
    TraceStats stats({"/etc/hosts"});

    struct event e = make_event(100, "walk", "hosts", SYS_write);
    // monitored path gets a single hit; without the protection veto the
    // flood below (all count 1) would trim it away first
    stats.on_event(e, "/etc/hosts");
    for (int i = 0; i < 1100; i++) {
        stats.on_event(e, "/wander/path" + std::to_string(i));
    }

    StatsSnapshot snap = stats.snapshot();
    assert(snap.procs.size() == 1);
    assert(snap.procs[0].per_file->size() <= MAX_PER_FILE_ENTRIES);
    // the configured monitor path must survive the trim with its count
    assert(snap.procs[0].per_file->count("/etc/hosts") == 1);
    assert(snap.procs[0].per_file->at("/etc/hosts") == 1);
    std::cout << "test_per_file_capped passed" << std::endl;
}

static void test_per_file_cap_with_protected_entries()
{
    // one process touching nothing but configured paths: the veto rejects
    // every entry, so only the fallback trim can enforce the cap
    std::vector<std::string> paths;
    for (size_t i = 0; i < MAX_PER_FILE_ENTRIES + 64; i++) {
        paths.push_back("/mon/" + std::to_string(i));
    }
    TraceStats stats(paths);

    struct event e = make_event(7, "walker", "hosts", SYS_write);
    for (const auto &p : paths) {
        stats.on_event(e, p);
    }

    StatsSnapshot snap = stats.snapshot();
    assert(snap.procs.size() == 1);
    assert(snap.procs[0].per_file->size() <= MAX_PER_FILE_ENTRIES);
    std::cout << "test_per_file_cap_with_protected_entries passed" << std::endl;
}

static void test_per_file_budget_with_protected_entries()
{
    // same fan-out as test_per_file_global_budget, but every path is a
    // configured one. The veto can never satisfy the budget here, so the
    // last-resort sweep has to drop protected entries -- otherwise the
    // budget would stay unreachable and every event would redo the pass.
    std::vector<std::string> paths;
    for (int i = 0; i < 200; i++) {
        paths.push_back("/mon/path/" + std::to_string(i));
    }
    TraceStats stats(paths);

    for (unsigned int pid = 1; pid <= 200; pid++) {
        struct event ev = make_event(pid, "walker", "hosts", SYS_write);
        for (const auto &p : paths) {
            stats.on_event(ev, p);
        }
    }

    StatsSnapshot snap = stats.snapshot();
    size_t total = 0;
    for (const auto &p : snap.procs) {
        assert(p.per_file->size() <= MAX_PER_FILE_ENTRIES);
        total += p.per_file->size();
    }
    assert(total <= MAX_TOTAL_PER_FILE_ENTRIES);
    std::cout << "test_per_file_budget_with_protected_entries passed ("
              << total << " entries)" << std::endl;
}

static void test_event_path_multi_dir()
{
    struct event e = make_event(1, "test", "file.txt", SYS_write);
    snprintf(e.dir4, sizeof(e.dir4), "dir4");
    snprintf(e.dir3, sizeof(e.dir3), "dir3");
    snprintf(e.dir2, sizeof(e.dir2), "dir2");
    snprintf(e.dir1, sizeof(e.dir1), "dir1");
    // parts must join outermost-first: dir4/dir3/dir2/dir1/filename
    assert(TraceStats::event_path(e) == "/dir4/dir3/dir2/dir1/file.txt");
    std::cout << "test_event_path_multi_dir passed" << std::endl;
}

// The snapshot cache must be usable from the very first call: an empty
// snapshot before any event, then a snapshot that sees the first event,
// then a cache hit that reports the same view. This exercises the gen_ 0
// -> 1 transition against the "never published" cache sentinel.
static void test_cache_first_use()
{
    TraceStats stats({"/etc/hosts"});

    StatsSnapshot empty = stats.snapshot();
    // no event yet: only the seeded configured path, no process rows
    assert(empty.procs.empty());
    assert(empty.devices.size() == 1);
    assert(empty.devices[0].ops == 0);
    assert(empty.total_events == 0 && empty.dropped_events == 0);

    // the empty snapshot must not be served after a mutation
    struct event e = make_event(100, "bash", "hosts", SYS_write);
    stats.on_event(e, "/etc/hosts");

    StatsSnapshot snap = stats.snapshot();
    assert(snap.total_events == 1);
    assert(snap.devices.size() == 1 && snap.devices[0].ops == 1);
    assert(snap.procs.size() == 1);

    // a second call hits the published generation and sees the same view
    StatsSnapshot again = stats.snapshot();
    assert(again.total_events == snap.total_events);
    assert(again.dropped_events == snap.dropped_events);
    assert(again.devices.size() == snap.devices.size());
    assert(again.procs.size() == snap.procs.size());
    std::cout << "test_cache_first_use passed" << std::endl;
}

static void test_empty_monitor_path_ignored()
{
    // an empty configured path is skipped, not normalized to "/"
    TraceStats stats({""});
    assert(stats.monitor_paths().empty());

    struct event e = make_event(1, "t", "hosts", SYS_write);
    stats.on_event(e, "/etc/hosts");
    StatsSnapshot snap = stats.snapshot();
    assert(snap.devices.size() == 1);
    assert(snap.devices[0].path == "/etc/hosts");
    std::cout << "test_empty_monitor_path_ignored passed" << std::endl;
}

static void test_table_eviction()
{
    TraceStats stats({"/etc/hosts"});

    struct event e = make_event(1, "init", "hosts", SYS_write);
    stats.on_event(e, "/etc/hosts");

    // flood with fresh pids/paths to overflow both tables; the pre-seeded
    // least recently active entries must be evicted, not the current one
    for (unsigned int pid = 2; pid < 10 + MAX_PROC_ENTRIES; pid++) {
        struct event e2 = make_event(pid, "p", "hosts", SYS_write);
        std::string path = "/path" + std::to_string(pid);
        stats.on_event(e2, path);
    }

    StatsSnapshot snap = stats.snapshot();
    assert(snap.procs.size() <= MAX_PROC_ENTRIES);
    assert(snap.devices.size() <= MAX_DEVICE_ENTRIES);

    // pid 1 was the oldest and must have been evicted
    for (const auto &p : snap.procs) {
        assert(p.pid != 1);
    }
    // the configured monitor path is protected from eviction
    bool found = false;
    for (const auto &d : snap.devices) {
        if (d.path == "/etc/hosts") {
            found = true;
        }
    }
    assert(found);
    std::cout << "test_table_eviction passed" << std::endl;
}

static void test_devices_cap_under_config_saturation()
{
    // the configured set alone saturates devices_: every entry is
    // veto-protected, so the veto-respecting sweep can free nothing and
    // eviction must degrade to plain LRU or the cap would be defeated
    std::vector<std::string> paths;
    paths.reserve(MAX_DEVICE_ENTRIES);
    for (size_t i = 0; i < MAX_DEVICE_ENTRIES; i++) {
        paths.push_back("/cfg" + std::to_string(i));
    }
    TraceStats stats(paths);
    assert(stats.snapshot().devices.size() == MAX_DEVICE_ENTRIES);

    // flood with fresh unconfigured paths; enough of them to run the
    // degradation sweep several times (it trims back to 7/8 of the cap,
    // so the table refills and saturates again every cap/8 insertions)
    for (unsigned int pid = 2; pid < 700; pid++) {
        struct event e = make_event(pid, "p", "hosts", SYS_write);
        stats.on_event(e, "/new" + std::to_string(pid));
        if (pid % 64 == 0) {
            // spot-check the cap mid-flood: it must never be exceeded
            assert(stats.snapshot().devices.size() <= MAX_DEVICE_ENTRIES);
        }
    }

    // a configured path touched again becomes recently active and must
    // survive further degradation sweeps
    struct event rewarm = make_event(100000, "w", "cfg0", SYS_write);
    stats.on_event(rewarm, "/cfg0");
    for (unsigned int pid = 200000; pid < 200000 + 300; pid++) {
        struct event e = make_event(pid, "p", "hosts", SYS_write);
        stats.on_event(e, "/new2" + std::to_string(pid));
    }

    StatsSnapshot snap = stats.snapshot();
    assert(snap.devices.size() <= MAX_DEVICE_ENTRIES);
    bool cfg0 = false;
    size_t unconfigured = 0;
    for (const auto &d : snap.devices) {
        if (d.path == "/cfg0") {
            cfg0 = true;
        }
        if (d.path.rfind("/cfg", 0) != 0) {
            unconfigured++;
        }
    }
    assert(cfg0);
    // the degradation must actually admit unconfigured entries, not just
    // silently drop every event on an unconfigured path
    assert(unconfigured > 0);
    std::cout << "test_devices_cap_under_config_saturation passed" << std::endl;
}

static void test_concurrent_access()
{
    TraceStats stats({"/etc/hosts"});

    const int kThreads = 4;
    const int kEvents = 2000;

    std::atomic<bool> stop{false};
    std::thread reader([&]() {
        while (!stop.load(std::memory_order_relaxed)) {
            StatsSnapshot snap = stats.snapshot();
            uint64_t ops_sum = 0;
            for (const auto &p : snap.procs) {
                ops_sum += p.ops;
            }
            // snapshot internal consistency: per-process ops can never
            // exceed the total events counted so far
            assert(ops_sum <= snap.total_events);
            uint64_t dev_ops = 0;
            for (const auto &d : snap.devices) {
                dev_ops += d.ops;
            }
            assert(dev_ops <= snap.total_events);
        }
    });

    std::vector<std::thread> writers;
    for (int t = 0; t < kThreads; t++) {
        writers.emplace_back([&stats, t]() {
            unsigned int pid = 1000 + (unsigned int)t;
            for (int i = 0; i < kEvents; i++) {
                struct event e = make_event(pid, "worker", "hosts", SYS_write);
                stats.on_event(e, "/etc/hosts");
            }
        });
    }
    for (auto &th : writers) {
        th.join();
    }
    stop = true;
    reader.join();

    StatsSnapshot snap = stats.snapshot();
    assert(snap.total_events == (uint64_t)kThreads * kEvents);
    assert(snap.dropped_events == 0);
    assert(snap.procs.size() == (size_t)kThreads);
    assert(snap.devices.size() == 1);
    assert(snap.devices[0].ops == (uint64_t)kThreads * kEvents);
    std::cout << "test_concurrent_access passed" << std::endl;
}

static void test_per_file_global_budget()
{
    // the per-process cap alone allows MAX_PROC_ENTRIES x MAX_PER_FILE_
    // ENTRIES path strings, i.e. hundreds of MB; the global budget must
    // keep the total bounded no matter how far the workload fans out
    TraceStats stats({"/etc/hosts"});

    const unsigned int kProcs = 200;
    const int kPaths = 200; // > MAX_PER_FILE_ENTRIES, so each table caps out
    for (unsigned int pid = 1; pid <= kProcs; pid++) {
        struct event ev = make_event(pid, "walker", "hosts", SYS_write);
        for (int i = 0; i < kPaths; i++) {
            stats.on_event(ev, "/wander/" + std::to_string(pid) + "/" +
                                    std::to_string(i));
        }
    }

    StatsSnapshot snap = stats.snapshot();
    size_t total = 0;
    for (const auto &p : snap.procs) {
        assert(p.per_file->size() <= MAX_PER_FILE_ENTRIES);
        total += p.per_file->size();
    }
    assert(total <= MAX_TOTAL_PER_FILE_ENTRIES);
    std::cout << "test_per_file_global_budget passed (" << total
              << " entries)" << std::endl;
}

static void test_snapshot_copy_on_write()
{
    TraceStats stats({"/etc/hosts"});
    struct event e = make_event(100, "bash", "hosts", SYS_write);

    stats.on_event(e, "/etc/hosts");
    StatsSnapshot snap1 = stats.snapshot();
    assert(snap1.procs[0].per_file->at("/etc/hosts") == 1);

    // no event in between: the published generation is reused as-is, the
    // per-file table is shared rather than re-copied, and the shared view
    // is literally the same object (no rebuild at all)
    auto shared1 = stats.snapshot_shared();
    auto shared2 = stats.snapshot_shared();
    assert(shared1 == shared2);
    StatsSnapshot snap1b = stats.snapshot();
    assert(snap1b.procs[0].per_file == snap1.procs[0].per_file);
    assert(snap1b.total_events == snap1.total_events);

    // a later event must not mutate a table that was already handed out:
    // the producer clones it on write and the old snapshot stays valid
    stats.on_event(e, "/etc/hosts");
    StatsSnapshot snap2 = stats.snapshot();
    assert(snap1.procs[0].per_file->at("/etc/hosts") == 1);
    assert(snap2.procs[0].per_file->at("/etc/hosts") == 2);
    assert(snap1.procs[0].per_file != snap2.procs[0].per_file);

    // dropped events also publish a generation, or the cached snapshot
    // would keep reporting a stale dropped counter
    stats.on_event(e, "");
    assert(stats.snapshot().dropped_events == 1);
    std::cout << "test_snapshot_copy_on_write passed" << std::endl;
}

static void test_config_saturation_reports_ignored()
{
    // The ctor caps its seeding at MAX_DEVICE_ENTRIES. Silently dropping the
    // rest would leave the TUI showing a device panel that is missing
    // entries with no hint why, so the dropped count is exposed and must be
    // exact: one path over the cap, one reported.
    std::vector<std::string> paths;
    paths.reserve(MAX_DEVICE_ENTRIES + 16);
    for (size_t i = 0; i < MAX_DEVICE_ENTRIES; i++) {
        paths.push_back("/fit" + std::to_string(i));
    }
    TraceStats fit(paths);
    assert(fit.ignored_monitor_paths() == 0);
    assert(fit.monitor_paths().size() == MAX_DEVICE_ENTRIES);
    assert(fit.snapshot().devices.size() == MAX_DEVICE_ENTRIES);

    const size_t extra = 16;
    for (size_t i = 0; i < extra; i++) {
        paths.push_back("/over" + std::to_string(i));
    }
    TraceStats over(paths);
    // exactly the surplus is reported, not the whole trailing run
    assert(over.ignored_monitor_paths() == extra);
    // ... and the seeding itself stays at the cap
    assert(over.snapshot().devices.size() == MAX_DEVICE_ENTRIES);
    // the full configured set is still retained for matching and the
    // eviction veto; only the devices_ seeding is truncated
    assert(over.monitor_paths().size() == MAX_DEVICE_ENTRIES + extra);

    // a dropped path is still attributable: an event on it lands under its
    // own key instead of being lost
    struct event e = make_event(4242, "p", "over0", SYS_write);
    over.on_event(e, "/over0");
    StatsSnapshot snap = over.snapshot();
    bool seen = false;
    for (const auto &d : snap.devices) {
        if (d.path == "/over0" && d.ops == 1) {
            seen = true;
        }
    }
    assert(seen);
    std::cout << "test_config_saturation_reports_ignored passed" << std::endl;
}

static void test_match_monitor_path_overlap()
{
    const std::vector<std::string> shallow_first = {"/etc", "/etc/nginx", "/var/log"};
    assert(TraceStats::match_monitor_path(shallow_first, "/etc/nginx/nginx.conf") == "/etc/nginx");
    assert(TraceStats::match_monitor_path(shallow_first, "/etc/nginx") == "/etc/nginx");
    assert(TraceStats::match_monitor_path(shallow_first, "/etc/hosts") == "/etc");
    assert(TraceStats::match_monitor_path(shallow_first, "/var/log/syslog") == "/var/log");

    // config order must not matter
    const std::vector<std::string> deep_first = {"/etc/nginx", "/etc"};
    assert(TraceStats::match_monitor_path(deep_first, "/etc/nginx/nginx.conf") == "/etc/nginx");
    assert(TraceStats::match_monitor_path(deep_first, "/etc/passwd") == "/etc");

    // deeper nesting still wins
    const std::vector<std::string> nested = {"/etc/nginx", "/etc/nginx/conf.d"};
    assert(TraceStats::match_monitor_path(nested, "/etc/nginx/conf.d/site.conf") == "/etc/nginx/conf.d");

    // matches sit on a component boundary: /etc must not swallow /etcetera
    assert(TraceStats::match_monitor_path({"/etc"}, "/etcetera/hosts") == "");
    assert(TraceStats::match_monitor_path({"/etc"}, "/etc") == "/etc");
    std::cout << "test_match_monitor_path_overlap passed" << std::endl;
}

static void test_match_monitor_path_catch_all()
{
    // "/" is the catch-all: it only wins when nothing more specific matches
    const std::vector<std::string> paths = {"/", "/var/log"};
    assert(TraceStats::match_monitor_path(paths, "/var/log/syslog") == "/var/log");
    assert(TraceStats::match_monitor_path(paths, "/tmp/x") == "/");

    // without a catch-all an unmonitored path is attributed to nothing
    assert(TraceStats::match_monitor_path({"/var/log"}, "/tmp/x") == "");
    assert(TraceStats::match_monitor_path({}, "/tmp/x") == "");
    assert(TraceStats::match_monitor_path(paths, "") == "");

    // A catch-all must not short-circuit the basename fallback: a bare
    // "/log" belongs to the unique configured path ending in "/log", not to
    // "/". The old prefix loop returned "/" before the fallback could run.
    assert(TraceStats::match_monitor_path(paths, "/log") == "/var/log");
    // When several paths share the basename it stays ambiguous, so the
    // catch-all legitimately wins again.
    const std::vector<std::string> ambiguous = {"/", "/var/log", "/srv/log"};
    assert(TraceStats::match_monitor_path(ambiguous, "/log") == "/");
    // A catch-all alone still handles a bare basename.
    assert(TraceStats::match_monitor_path({"/"}, "/log") == "/");
    std::cout << "test_match_monitor_path_catch_all passed" << std::endl;
}

static void test_match_monitor_path_basename()
{
    // write/copy_file_range events may rebuild to a bare "/name": accepted
    // only when exactly one configured path ends with that suffix
    assert(TraceStats::match_monitor_path({"/etc/nginx/nginx.conf"}, "/nginx.conf") ==
           "/etc/nginx/nginx.conf");
    assert(TraceStats::match_monitor_path({"/etc/a/x.conf", "/srv/b/x.conf"}, "/x.conf") == "");

    // the fallback only applies to single-component paths
    assert(TraceStats::match_monitor_path({"/a/b/hosts"}, "/b/hosts") == "");
    std::cout << "test_match_monitor_path_basename passed" << std::endl;
}

int main()
{
    test_event_path_rebuild();
    test_event_path_absolute_filename();
    test_event_path_root();
    test_event_path_multi_dir();
    test_aggregation();
    test_trailing_slash_normalized();
    test_copy_file_range_is_write();
    test_classification();
    test_match_monitor_path_overlap();
    test_match_monitor_path_catch_all();
    test_match_monitor_path_basename();
    test_empty_monitor_path_ignored();
    test_cache_first_use();
    test_cmd_refresh_on_exec();
    test_per_file_capped();
    test_per_file_cap_with_protected_entries();
    test_per_file_global_budget();
    test_per_file_budget_with_protected_entries();
    test_snapshot_copy_on_write();
    test_table_eviction();
    test_devices_cap_under_config_saturation();
    test_config_saturation_reports_ignored();
    test_concurrent_access();
    std::cout << "All TraceStats tests passed" << std::endl;
    return 0;
}
