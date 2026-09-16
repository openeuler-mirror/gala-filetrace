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

static size_t info_metric_count(PrometheusExporter& exp)
{
    size_t count = 0;
    for (const auto& family : exp.registry->Collect()) {
        if (family.name == "filetrace_info_record") {
            count += family.metric.size();
        }
    }
    return count;
}

// Expiration must remove the series from the Registry, including after the
// same PID returns with a new timestamp label.
static void test_expired_gauge_removed()
{
    PrometheusExporter exp("127.0.0.1:19095", 0);
    auto e = make_event(123, 1, "cmd", "file.txt", nullptr, nullptr,
                        nullptr, nullptr, SYS_openat, 0, 0, 100);
    for (int cycle = 0; cycle < 2; ++cycle) {
        exp.set_metrics(e);
        assert(info_metric_count(exp) == 1);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (info_metric_count(exp) != 0 && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        assert(info_metric_count(exp) == 0);
    }
    std::cout << "  PASS: expired gauge removed from Registry across repeated cycles" << std::endl;
}

int main()
{
    std::cout << "Running PrometheusExporter unit tests..." << std::endl;

    test_constructor_valid();
    test_constructor_empty_address();
    test_add_counter_and_inc();
    test_get_full_path_all_dirs();
    test_expired_gauge_removed();

    std::cout << "All PrometheusExporter unit tests passed." << std::endl;
    return 0;
}
