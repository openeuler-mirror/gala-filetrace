// Unit tests for src/filetrace.cpp: handle_event() (both PostData and TUI
// stats modes), running_kernel_at_least(), and sig_handler().
//
// filetrace.cpp is compiled directly into the test binary (its main() is
// renamed via #define) so the static helpers and globals can be exercised
// without loading any eBPF program.
//
// This file is #included from test_postdata.cpp (it defines no main() of its
// own); its tests run via run_filetrace_*_tests().

#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <sys/utsname.h>

#include "stats.hpp"
#define private public
#include "tui.hpp"
#undef private

#define main filetrace_main
#include "../src/filetrace.cpp"
#undef main

static struct event make_event(unsigned int pid, const char *cmd, const char *filename,
                               const char *dir1, int flag, unsigned int uid, unsigned int gid,
                               const char *dir2 = nullptr)
{
    struct event e;
    memset(&e, 0, sizeof(e));
    e.pid = pid;
    e.ppid = 1;
    strncpy(e.cmd, cmd, sizeof(e.cmd) - 1);
    strncpy(e.filename, filename, sizeof(e.filename) - 1);
    if (dir1) {
        strncpy(e.dir1, dir1, sizeof(e.dir1) - 1);
    }
    if (dir2) {
        strncpy(e.dir2, dir2, sizeof(e.dir2) - 1);
    }
    e.flag = flag;
    e.uid = uid;
    e.gid = gid;
    e.i_ino = 100;
    return e;
}

static const DeviceStat *find_device(const StatsSnapshot &snap, const std::string &path)
{
    for (const auto &d : snap.devices) {
        if (d.path == path) {
            return &d;
        }
    }
    return nullptr;
}

static const ProcStat *find_proc(const StatsSnapshot &snap, unsigned int pid)
{
    for (const auto &p : snap.procs) {
        if (p.pid == pid) {
            return &p;
        }
    }
    return nullptr;
}

static int run_filetrace_handle_event_tests()
{
    std::cout << "Running filetrace handle_event unit tests..." << std::endl;

    Logger::init("/tmp/gala_test_filetrace.log", "info", 0);

    PostData post;
    // Single owner: PostData deletes exporter_ptr in its destructor, matching
    // the real exporter_start() path (no second unique_ptr owner).
    post.exporter_ptr = new PrometheusExporter("127.0.0.1:19300", 30);
    post.cache_data = true;
    post.max_event_queue_size = 100;
    post.verbose = false;
    post.conf_list = {"/etc/hosts"};
    post.skip_processes = {};

    struct event e = make_event(100, "bash", "hosts", "etc", SYS_write, 0, 0);

    // null data is rejected
    assert(handle_event(nullptr, nullptr, sizeof(struct event)) == -1);

    // null PostData instance is rejected
    PostData *saved = postdata_i;
    postdata_i = nullptr;
    assert(handle_event(nullptr, &e, sizeof(struct event)) == -1);

    // undersized event is rejected
    postdata_i = &post;
    assert(handle_event(nullptr, &e, sizeof(struct event) - 1) == -1);

    // verbose + valid: event is only printed, not sent or cached
    post.verbose = true;
    assert(handle_event(nullptr, &e, sizeof(struct event)) == 0);
    {
        auto arr = post.get_events_from_queue(10);
        assert(arr.is_array());
        assert(arr.size() == 0);
    }

    // verbose + invalid: dropped by validation, so nothing is printed, sent
    // or cached (process_event() validates before dispatching any effect)
    struct event bad = make_event(200, "bash", "shadow", "etc", SYS_write, 0, 0);
    assert(handle_event(nullptr, &bad, sizeof(struct event)) == 0);
    {
        auto arr = post.get_events_from_queue(10);
        assert(arr.is_array());
        assert(arr.size() == 0);
    }

    // non-verbose valid: full path send + cache_event
    post.verbose = false;
    assert(handle_event(nullptr, &e, sizeof(struct event)) == 0);
    {
        auto arr = post.get_events_from_queue(10);
        assert(arr.is_array());
        assert(arr.size() == 1);
        assert(arr[0]["pid"] == 100);
    }

    // non-verbose valid SYS_renameat2: matched through the rebuilt (absolute)
    // destination path and cached
    struct event ren = make_event(300, "mv", "/etc/hosts", nullptr, SYS_renameat2, 0, 0);
    assert(handle_event(nullptr, &ren, sizeof(struct event)) == 0);
    {
        auto arr = post.get_events_from_queue(10);
        assert(arr.is_array());
        assert(arr.size() == 1);
        assert(arr[0]["pid"] == 300);
        assert(arr[0]["filename"] == "/etc/hosts");
    }

    postdata_i = saved;
    std::cout << "All filetrace handle_event unit tests passed." << std::endl;
    return 0;
}

static int run_filetrace_tui_stats_tests()
{
    std::cout << "Running filetrace handle_event TUI stats unit tests..." << std::endl;

    PostData *saved_post = postdata_i;
    TraceStats *saved_stats = tui_stats;
    postdata_i = nullptr;

    // Configure "/etc" before "/etc/nginx" to verify nested events attribute
    // to the deepest matching path rather than the first entry in config order.
    TraceStats stats({"/etc", "/etc/nginx", "/var/log/app.log"});
    tui_stats = &stats;

    struct event e_hosts = make_event(401, "vim", "hosts", "etc", SYS_write, 0, 0);

    // Null data and undersized buffer are still rejected in TUI mode
    assert(handle_event(nullptr, nullptr, sizeof(struct event)) == -1);
    assert(handle_event(nullptr, &e_hosts, sizeof(struct event) - 1) == -1);

    // Event under /etc attributes to /etc
    assert(handle_event(nullptr, &e_hosts, sizeof(struct event)) == 0);
    {
        StatsSnapshot snap = stats.snapshot();
        assert(snap.total_events == 1);
        assert(snap.dropped_events == 0);
        const DeviceStat *etc_dev = find_device(snap, "/etc");
        const DeviceStat *nginx_dev = find_device(snap, "/etc/nginx");
        assert(etc_dev != nullptr && etc_dev->ops == 1 && etc_dev->writes == 1);
        assert(nginx_dev != nullptr && nginx_dev->ops == 0);
        const ProcStat *proc = find_proc(snap, 401);
        assert(proc != nullptr && proc->ops == 1);
        assert(proc->per_file && proc->per_file->at("/etc") == 1);
    }

    // Event under /etc/nginx attributes to deepest match /etc/nginx, not /etc
    struct event e_nginx = make_event(402, "nginx", "nginx.conf", "nginx", SYS_openat, 0, 0, "etc");
    assert(handle_event(nullptr, &e_nginx, sizeof(struct event)) == 0);
    {
        StatsSnapshot snap = stats.snapshot();
        assert(snap.total_events == 2);
        assert(snap.dropped_events == 0);
        const DeviceStat *etc_dev = find_device(snap, "/etc");
        const DeviceStat *nginx_dev = find_device(snap, "/etc/nginx");
        assert(etc_dev != nullptr && etc_dev->ops == 1);
        assert(nginx_dev != nullptr && nginx_dev->ops == 1 && nginx_dev->opens == 1);
        const ProcStat *proc = find_proc(snap, 402);
        assert(proc != nullptr && proc->ops == 1);
        assert(proc->per_file && proc->per_file->at("/etc/nginx") == 1);
        assert(proc->per_file->count("/etc") == 0);
    }

    // Rename with absolute destination bypasses source dir1 and attributes to /etc/nginx
    struct event e_ren = make_event(403, "mv", "/etc/nginx/site.conf", "tmp", SYS_renameat2, 0, 0);
    assert(handle_event(nullptr, &e_ren, sizeof(struct event)) == 0);
    {
        StatsSnapshot snap = stats.snapshot();
        assert(snap.total_events == 3);
        assert(snap.dropped_events == 0);
        const DeviceStat *nginx_dev = find_device(snap, "/etc/nginx");
        assert(nginx_dev != nullptr && nginx_dev->ops == 2 && nginx_dev->renames == 1);
    }

    // Basename-only event uniquely matching /var/log/app.log
    struct event e_base = make_event(404, "logger", "app.log", nullptr, SYS_write, 0, 0);
    assert(handle_event(nullptr, &e_base, sizeof(struct event)) == 0);
    {
        StatsSnapshot snap = stats.snapshot();
        assert(snap.total_events == 4);
        assert(snap.dropped_events == 0);
        const DeviceStat *app_dev = find_device(snap, "/var/log/app.log");
        assert(app_dev != nullptr && app_dev->ops == 1 && app_dev->writes == 1);
    }

    // Unmatched paths (unrelated path and component-boundary prefix trap) count as dropped
    struct event e_unmatched1 = make_event(405, "cat", "other", "tmp", SYS_openat, 0, 0);
    struct event e_unmatched2 = make_event(406, "cat", "hosts", "etcetera", SYS_openat, 0, 0);
    assert(handle_event(nullptr, &e_unmatched1, sizeof(struct event)) == 0);
    assert(handle_event(nullptr, &e_unmatched2, sizeof(struct event)) == 0);
    {
        StatsSnapshot snap = stats.snapshot();
        assert(snap.total_events == 4);
        assert(snap.dropped_events == 2);
        assert(find_device(snap, "/tmp/other") == nullptr);
        assert(find_device(snap, "/etcetera/hosts") == nullptr);
        assert(find_proc(snap, 405) == nullptr);
        assert(find_proc(snap, 406) == nullptr);
    }

    // Unrebuildable (empty path) event also counts as dropped
    struct event e_empty = make_event(407, "cat", "", nullptr, SYS_write, 0, 0);
    assert(handle_event(nullptr, &e_empty, sizeof(struct event)) == 0);
    {
        StatsSnapshot snap = stats.snapshot();
        assert(snap.total_events == 4);
        assert(snap.dropped_events == 3);
    }

    postdata_i = saved_post;
    tui_stats = saved_stats;
    std::cout << "All filetrace handle_event TUI stats unit tests passed." << std::endl;
    return 0;
}

static int run_filetrace_kernel_version_tests()
{
    std::cout << "Running filetrace running_kernel_at_least unit tests..." << std::endl;

    struct utsname info;
    assert(uname(&info) == 0);
    int cur_major = 0;
    int cur_minor = 0;
    assert(std::sscanf(info.release, "%d.%d", &cur_major, &cur_minor) == 2);

    // Exact running version matches
    assert(running_kernel_at_least(cur_major, cur_minor) == true);

    // Same major, lower minor matches
    if (cur_minor > 0) {
        assert(running_kernel_at_least(cur_major, cur_minor - 1) == true);
    }
    assert(running_kernel_at_least(cur_major, -1) == true);

    // Lower major matches regardless of wanted minor
    assert(running_kernel_at_least(cur_major - 1, cur_minor + 99) == true);
    assert(running_kernel_at_least(0, 0) == true);

    // Higher minor on same major or higher major does not match
    assert(running_kernel_at_least(cur_major, cur_minor + 1) == false);
    assert(running_kernel_at_least(cur_major + 1, 0) == false);

    // Matches the (6, 6) fentry cutoff used by select_kernel_version_probes()
    bool expected_6_6 = (cur_major > 6) || (cur_major == 6 && cur_minor >= 6);
    assert(running_kernel_at_least(6, 6) == expected_6_6);

    std::cout << "All filetrace running_kernel_at_least unit tests passed." << std::endl;
    return 0;
}

static int run_filetrace_sig_handler_tests()
{
    std::cout << "Running filetrace sig_handler unit tests..." << std::endl;

    bool saved_running = tui_running.load();
    TuiApp *saved_tui = g_tui.load(std::memory_order_acquire);

    // When g_tui is null, sig_handler sets tui_running = false without crashing
    tui_running.store(true);
    g_tui.store(nullptr, std::memory_order_release);
    sig_handler(SIGINT);
    assert(tui_running.load() == false);
    assert(g_tui.load(std::memory_order_acquire) == nullptr);

    // When g_tui is published, sig_handler also calls g_tui->request_stop()
    TraceStats stats({"/etc/hosts"});
    TuiOptions opts;
    TuiApp tui(stats, opts);
    assert(tui.running_.load() == true);

    tui_running.store(true);
    g_tui.store(&tui, std::memory_order_release);
    sig_handler(SIGTERM);
    assert(tui_running.load() == false);
    assert(tui.running_.load() == false);

    g_tui.store(saved_tui, std::memory_order_release);
    tui_running.store(saved_running);
    std::cout << "All filetrace sig_handler unit tests passed." << std::endl;
    return 0;
}
