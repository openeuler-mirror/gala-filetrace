// Unit tests for src/filetrace.cpp: the ring-buffer callback handle_event().
//
// filetrace.cpp is compiled directly into the test binary (its main() is
// renamed via #define) so the static handle_event() and the postdata_i
// global can be exercised without loading any eBPF program.
//
// This file is #included from test_postdata.cpp (it defines no main() of its
// own); its tests run via run_filetrace_handle_event_tests().

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

#define main filetrace_main
#include "../src/filetrace.cpp"
#undef main

static struct event make_event(unsigned int pid, const char *cmd, const char *filename,
                               const char *dir1, int flag, unsigned int uid, unsigned int gid)
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
    e.flag = flag;
    e.uid = uid;
    e.gid = gid;
    e.i_ino = 100;
    return e;
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

    postdata_i = saved;
    std::cout << "All filetrace handle_event unit tests passed." << std::endl;
    return 0;
}
