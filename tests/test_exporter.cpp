#include <cassert>
#include <cstdlib>
#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <chrono>
#include <vector>
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

    // The installed prometheus-cpp exposes no direct sum()/sample_count()
    // accessors, so verify the observed values through Collect().
    auto cm = h.Collect();
    assert(cm.histogram.sample_count == 3);
    assert(cm.histogram.sample_sum == 109.0);

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

static const prometheus::ClientMetric& find_info_metric_by_pid(
    const std::vector<prometheus::MetricFamily>& families,
    unsigned int pid)
{
    const std::string pid_str = std::to_string(pid);
    for (const auto& family : families) {
        if (family.name != "filetrace_info_record") {
            continue;
        }
        assert(family.type == prometheus::MetricType::Gauge);
        for (const auto& metric : family.metric) {
            for (const auto& label : metric.label) {
                if (label.name == "pid" && label.value == pid_str) {
                    return metric;
                }
            }
        }
    }
    assert(false && "Expected filetrace_info_record metric for pid not found");
    std::abort();
}

static std::string get_label_value(const prometheus::ClientMetric& metric,
                                   const std::string& name)
{
    for (const auto& label : metric.label) {
        if (label.name == name) {
            return label.value;
        }
    }
    assert(false && "Expected label not found on metric");
    return "";
}

static void assert_info_metric_labels(PrometheusExporter& exp,
                                      const struct event& e,
                                      const std::string& expected_file,
                                      const std::string& expected_operation)
{
    const auto families = exp.registry->Collect();
    const auto& metric = find_info_metric_by_pid(families, e.pid);

    assert(metric.gauge.value == static_cast<double>(e.pid));
    assert(get_label_value(metric, "file") == expected_file);
    assert(get_label_value(metric, "operation") == expected_operation);
    assert(get_label_value(metric, "pid") == std::to_string(e.pid));
    assert(get_label_value(metric, "ppid") == std::to_string(e.ppid));
    assert(get_label_value(metric, "uid") == std::to_string(e.uid));
    assert(get_label_value(metric, "gid") == std::to_string(e.gid));
    assert(get_label_value(metric, "inode") == std::to_string(e.i_ino));
    assert(get_label_value(metric, "cmd") == std::string(e.cmd));
    assert(!get_label_value(metric, "ts").empty());
}

// Expiration must remove the series from the Registry, including after the
// same PID returns with a new timestamp label.
static void test_expired_gauge_removed()
{
    PrometheusExporter exp("127.0.0.1:19102", 0);
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
                                SYS_write, 1000, 2000, 5000);
    exp.set_metrics(e);
    assert(info_metric_count(exp) == 1);
    assert_info_metric_labels(exp, e, "/log/var/output.log", "sys_enter_write");

    // Calling set_metrics again for the same PID reuses the cached gauge.
    exp.set_metrics(e);
    assert(info_metric_count(exp) == 1);
    assert_info_metric_labels(exp, e, "/log/var/output.log", "sys_enter_write");

    std::cout << "  PASS: set_metrics for SYS_write event" << std::endl;
}

// ---- Test: set_metrics for SYS_unlinkat event ----
static void test_set_metrics_unlinkat()
{
    PrometheusExporter exp("127.0.0.1:19105", 30);
    struct event e = make_event(150, 10, "rm", "stale.tmp", "tmp", "app", "var", "",
                                SYS_unlinkat, 1001, 2001, 5500);
    exp.set_metrics(e);
    assert(info_metric_count(exp) == 1);
    assert_info_metric_labels(exp, e, "/var/app/tmp/stale.tmp", "sys_enter_unlinkat");

    struct event e_all = make_event(151, 11, "unlink", "lock", "run", "svc", "opt", "mnt",
                                    SYS_unlinkat, 1002, 2002, 5501);
    exp.set_metrics(e_all);
    assert(info_metric_count(exp) == 2);
    assert_info_metric_labels(exp, e_all, "/mnt/opt/svc/run/lock", "sys_enter_unlinkat");

    std::cout << "  PASS: set_metrics for SYS_unlinkat event" << std::endl;
}

// ---- Test: set_metrics for SYS_copy_file_range event ----
static void test_set_metrics_copy_file_range()
{
    PrometheusExporter exp("127.0.0.1:19106", 30);
    struct event e = make_event(160, 12, "cp", "dest.bin", "dst", "data", "mnt", "",
                                SYS_copy_file_range, 1003, 2003, 5600);
    exp.set_metrics(e);
    assert(info_metric_count(exp) == 1);
    assert_info_metric_labels(exp, e, "/mnt/data/dst/dest.bin", "sys_enter_copy_file_range");

    std::cout << "  PASS: set_metrics for SYS_copy_file_range event" << std::endl;
}

// ---- Test: set_metrics for non-write event (e.g. openat) ----
static void test_set_metrics_openat()
{
    PrometheusExporter exp("127.0.0.1:19099", 30);
    // e.filename should be used directly without get_full_path alteration
    struct event e = make_event(200, 1, "vim", "edit.conf", "etc", "", "", "",
                                SYS_openat, 1004, 2004, 6000);
    exp.set_metrics(e);
    assert(info_metric_count(exp) == 1);
    assert_info_metric_labels(exp, e, "edit.conf", "sys_enter_openat");

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

// ---- Test: set_metrics increments file_access_counter when configured ----
static void test_set_metrics_file_access_counter()
{
    PrometheusExporter exp("127.0.0.1:19103", 30);
    auto& c = exp.add_counter("file_access_total", "File access events", {});
    exp.file_access_counter = &c;

    struct event e = make_event(300, 1, "bash", "access.log", "var", "log", "", "",
                                SYS_write, 0, 0, 7000);
    exp.set_metrics(e);
    assert(c.Value() == 1.0);

    exp.set_metrics(e);
    assert(c.Value() == 2.0);

    std::cout << "  PASS: set_metrics increments file_access_counter" << std::endl;
}

// ---- Test: set_metrics for rename events (SYS_rename, SYS_renameat, SYS_renameat2) ----
static void test_set_metrics_rename()
{
    // The caller resolves the reported side (same path as the JSON "file"
    // field) and passes it in: the metric must use it, not the destination.
    PrometheusExporter exp("127.0.0.1:19104", 30);
    const struct {
        int flag;
        const char* op;
    } rename_cases[] = {
        {SYS_rename, "sys_enter_rename"},
        {SYS_renameat, "sys_enter_renameat"},
        {SYS_renameat2, "sys_enter_renameat2"},
    };
    for (size_t i = 0; i < sizeof(rename_cases) / sizeof(rename_cases[0]); ++i) {
        // Use distinct PIDs so each path case registers its own cached gauge.
        unsigned int pid = 400 + 2 * static_cast<unsigned int>(i);
        struct event e = make_event(pid, 1, "mv", "/tmp/hosts.bak", "dir_a", "dir_b", "", "",
                                    rename_cases[i].flag, 1010 + static_cast<unsigned int>(i),
                                    2010 + static_cast<unsigned int>(i), 8000 + 2 * i);
        exp.set_metrics(e, "/etc/hosts");
        assert_info_metric_labels(exp, e, "/etc/hosts", rename_cases[i].op);

        // Without an explicit path the historical destination fallback remains.
        struct event f = make_event(pid + 1, 1, "mv", "/tmp/hosts.bak", nullptr, nullptr,
                                    nullptr, nullptr, rename_cases[i].flag, e.uid, e.gid,
                                    8001 + 2 * i);
        exp.set_metrics(f);
        assert_info_metric_labels(exp, f, "/tmp/hosts.bak", rename_cases[i].op);
    }
    assert(info_metric_count(exp) == 6);
    std::cout << "  PASS: set_metrics for SYS_rename* events" << std::endl;
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
    test_expired_gauge_removed();
    test_get_full_path_partial_dirs();
    test_get_full_path_no_dirs();
    test_get_full_path_slash_dir();
    test_set_metrics_write();
    test_set_metrics_unlinkat();
    test_set_metrics_copy_file_range();
    test_set_metrics_openat();
    test_set_metrics_rename();
    test_cache_timeout_thread();
    test_destructor_stops_thread();
    test_set_metrics_file_access_counter();

    std::cout << "All PrometheusExporter unit tests passed." << std::endl;
    return 0;
}
