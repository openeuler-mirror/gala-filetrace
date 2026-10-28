#include <cassert>
#include <cstring>
#include <iostream>

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

static void test_event_path_root()
{
    struct event e = make_event(1, "test", "", SYS_write);
    snprintf(e.dir1, sizeof(e.dir1), "/");
    std::string path = TraceStats::event_path(e);
    assert(path == "/");
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
    assert(snap.procs[0].per_file.at("/etc/hosts") == 3);
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

int main()
{
    test_event_path_rebuild();
    test_event_path_root();
    test_aggregation();
    test_trailing_slash_normalized();
    std::cout << "All TraceStats tests passed" << std::endl;
    return 0;
}
