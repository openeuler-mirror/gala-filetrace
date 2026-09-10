#include <cassert>
#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <chrono>
#include "exporter.hpp"

// Helper: build an event with the given fields
static struct event make_event(unsigned int pid, unsigned int ppid,
                               const char* cmd, const char* filename,
                               const char* dir1, const char* dir2,
                               const char* dir3, const char* dir4,
                               int flag, unsigned int uid, unsigned int gid,
                               unsigned long ino)
{
    struct event e;
    memset(&e, 0, sizeof(e));
    e.pid = pid;
    e.ppid = ppid;
    strncpy(e.cmd, cmd, sizeof(e.cmd) - 1);
    strncpy(e.filename, filename, sizeof(e.filename) - 1);
    if (dir1) strncpy(e.dir1, dir1, sizeof(e.dir1) - 1);
    if (dir2) strncpy(e.dir2, dir2, sizeof(e.dir2) - 1);
    if (dir3) strncpy(e.dir3, dir3, sizeof(e.dir3) - 1);
    if (dir4) strncpy(e.dir4, dir4, sizeof(e.dir4) - 1);
    e.flag = flag;
    e.uid = uid;
    e.gid = gid;
    e.i_ino = ino;
    return e;
}

// ---- Test: constructor with valid address ----
static void test_constructor_valid()
{
    PrometheusExporter exp("127.0.0.1:19090", 30);
    assert(exp.registry != nullptr);
    std::cout << "  PASS: constructor with valid address" << std::endl;
}

// ---- Test: constructor with empty address throws ----
static void test_constructor_empty_address()
{
    bool threw = false;
    try {
        PrometheusExporter exp("", 30);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw);
    std::cout << "  PASS: constructor with empty address throws" << std::endl;
}

// ---- Test: add_counter and inc_counter ----
static void test_add_counter_and_inc()
{
    PrometheusExporter exp("127.0.0.1:19091", 30);
    auto& c = exp.add_counter("test_counter", "A test counter", {{"env", "test"}});

    exp.inc_counter(c, 1.0);
    exp.inc_counter(c, 2.5);
    assert(c.Value() == 3.5);

    exp.inc_counter(c);  // default v=1.0
    assert(c.Value() == 4.5);

    std::cout << "  PASS: add_counter and inc_counter" << std::endl;
}

// ---- Test: add_gauge ----
static void test_add_gauge()
{
    PrometheusExporter exp("127.0.0.1:19092", 30);
    auto& g = exp.add_gauge("test_gauge", "A test gauge", {{"host", "node1"}});

    g.Set(42.0);
    assert(g.Value() == 42.0);

    g.Set(0.0);
    assert(g.Value() == 0.0);

    std::cout << "  PASS: add_gauge" << std::endl;
}

// ---- Test: add_histogram ----
static void test_add_histogram()
{
    PrometheusExporter exp("127.0.0.1:19093", 30);
    prometheus::Histogram::BucketBoundaries buckets = {1, 5, 10, 50, 100};
    auto& h = exp.add_histogram("test_histogram", "A test histogram", buckets, {{"svc", "filetrace"}});

    h.Observe(3.0);
    h.Observe(7.0);
    h.Observe(99.0);

    auto sum = h.sum();
    assert(sum == 109.0);
    assert(h.sample_count() == 3);

    std::cout << "  PASS: add_histogram" << std::endl;
}

// ---- Test: get_full_path with all dirs ----
static void test_get_full_path_all_dirs()
{
    PrometheusExporter exp("127.0.0.1:19094", 30);
    struct event e = make_event(1, 0, "cmd", "file.txt", "dir1", "dir2", "dir3", "dir4",
                                SYS_write, 0, 0, 100);
    std::string path = exp.get_full_path(&e);
    assert(path == "/dir4/dir3/dir2/dir1/file.txt");

    std::cout << "  PASS: get_full_path with all dirs" << std::endl;
}

// ---- Test: get_full_path with partial dirs ----
static void test_get_full_path_partial_dirs()
{
    PrometheusExporter exp("127.0.0.1:19095", 30);
    struct event e = make_event(1, 0, "cmd", "test.conf", "etc", "", "", "",
                                SYS_write, 0, 0, 200);
    std::string path = exp.get_full_path(&e);
    assert(path == "/etc/test.conf");

    std::cout << "  PASS: get_full_path with partial dirs" << std::endl;
}

// ---- Test: get_full_path with empty dirs ----
static void test_get_full_path_no_dirs()
{
    PrometheusExporter exp("127.0.0.1:19096", 30);
    struct event e = make_event(1, 0, "cmd", "root.txt", "", "", "", "",
                                SYS_write, 0, 0, 300);
    std::string path = exp.get_full_path(&e);
    assert(path == "/root.txt");

    std::cout << "  PASS: get_full_path with no dirs" << std::endl;
}

// ---- Test: get_full_path with slash-only dir ----
static void test_get_full_path_slash_dir()
{
    PrometheusExporter exp("127.0.0.1:19097", 30);
    struct event e = make_event(1, 0, "cmd", "file", "/", "", "", "",
                                SYS_write, 0, 0, 400);
    std::string path = exp.get_full_path(&e);
    assert(path == "/file");

    std::cout << "  PASS: get_full_path with slash-only dir" << std::endl;
}

// ---- Test: set_metrics for SYS_write event ----
static void test_set_metrics_write()
{
    PrometheusExporter exp("127.0.0.1:19098", 30);
    struct event e = make_event(100, 1, "bash", "output.log", "var", "log", "", "",
                                SYS_write, 1000, 1000, 5000);
    exp.set_metrics(e);

    // file_access_counter should have been incremented
    // (set_metrics increments it if non-null; it is nullptr by default, so skip that check)

    // A gauge should be created for pid=100
    // The gauge_cache is private, so we verify indirectly by calling set_metrics again
    // without crashing (reuses the cached gauge).
    exp.set_metrics(e);

    std::cout << "  PASS: set_metrics for SYS_write event" << std::endl;
}

// ---- Test: set_metrics for non-write event (e.g. openat) ----
static void test_set_metrics_openat()
{
    PrometheusExporter exp("127.0.0.1:19099", 30);
    struct event e = make_event(200, 1, "vim", "edit.conf", "etc", "", "", "",
                                SYS_openat, 0, 0, 6000);
    exp.set_metrics(e);

    std::cout << "  PASS: set_metrics for SYS_openat event" << std::endl;
}

// ---- Test: cache timeout thread starts and stops cleanly ----
static void test_cache_timeout_thread()
{
    PrometheusExporter exp("127.0.0.1:19100", 1);
    // Give the thread a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    assert(exp.cache_timeout_thread_.joinable());
    exp.stop_cache_timeout_thread();
    assert(!exp.cache_timeout_thread_.joinable());

    std::cout << "  PASS: cache timeout thread starts and stops" << std::endl;
}

// ---- Test: destructor stops thread without crash ----
static void test_destructor_stops_thread()
{
    {
        PrometheusExporter exp("127.0.0.1:19101", 2);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        // destructor will be called here
    }
    std::cout << "  PASS: destructor stops thread without crash" << std::endl;
}

int main()
{
    std::cout << "Running PrometheusExporter unit tests..." << std::endl;

    test_constructor_valid();
    test_constructor_empty_address();
    test_add_counter_and_inc();
    test_add_gauge();
    test_add_histogram();
    test_get_full_path_all_dirs();
    test_get_full_path_partial_dirs();
    test_get_full_path_no_dirs();
    test_get_full_path_slash_dir();
    test_set_metrics_write();
    test_set_metrics_openat();
    test_cache_timeout_thread();
    test_destructor_stops_thread();

    std::cout << "All PrometheusExporter unit tests passed." << std::endl;
    return 0;
}
