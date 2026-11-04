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
    test_empty_monitor_path_ignored();
    test_cmd_refresh_on_exec();
    test_per_file_capped();
    test_table_eviction();
    test_concurrent_access();
    std::cout << "All TraceStats tests passed" << std::endl;
    return 0;
}
