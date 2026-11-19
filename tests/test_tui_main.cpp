// ******************************************************************************
// Copyright (c) Huawei Technologies Co., Ltd. 2021-2023. All rights reserved.
// licensed under the Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//     http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
// PURPOSE.
// See the Mulan PSL v2 for more details.
// ******************************************************************************/
// Unit tests for the filetrace-tui entry point helpers (load_config_list,
// demo_feed, tui_sig_handler). The entry file's main() is renamed at include
// time so its static helpers and g_tui global become linkable from this test
// binary.
//
// Checks go through CHECK(), not assert(): assert() compiles away under
// -DNDEBUG, which would leave a binary that prints "passed" without checking
// anything (and that reads paths[0]/devices[0] unchecked if they are empty).

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include <sys/types.h>
#include <unistd.h>

#include "stats.hpp"

// Open TuiApp::running_ before tui_main.cpp includes tui.hpp (all data members
// live in one contiguous private block, so layout matches tui.o).
#define private public
#include "tui.hpp"
#undef private

#define main tui_unused_main
#include "../src/tui_main.cpp"
#undef main

namespace {

int g_failures = 0;

// Reports the failing expression and keeps going, so one run lists every
// broken check instead of stopping at the first.
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " \
                      << #cond << std::endl;                               \
            g_failures++;                                                  \
        }                                                                  \
    } while (0)

// A temp directory that removes itself, so a run leaves nothing behind in
// /tmp and a failing check cannot skip the cleanup.
class TempDir {
public:
    TempDir()
    {
        char pattern[] = "/tmp/tui_main_test_XXXXXX";
        char *dir = mkdtemp(pattern);
        path_ = dir ? std::string(dir) : std::string();
    }

    ~TempDir()
    {
        if (path_.empty()) {
            return;
        }
        // every file these tests create lives directly in the directory
        for (const std::string &name : files_) {
            unlink(name.c_str());
        }
        rmdir(path_.c_str());
    }

    TempDir(const TempDir &) = delete;
    TempDir &operator=(const TempDir &) = delete;

    const std::string &path() const { return path_; }

    // Writes content to <dir>/<name> and returns the full path. A short write
    // or a failed close would otherwise make a parse test degrade to "empty
    // result" for the wrong reason, so the file is reported as unusable
    // (empty path) instead of being handed to the parser.
    std::string write_file(const std::string &name, const std::string &content)
    {
        if (path_.empty()) {
            return std::string();
        }
        std::string full = path_ + "/" + name;
        FILE *f = fopen(full.c_str(), "wb");
        if (!f) {
            return std::string();
        }
        size_t written = fwrite(content.data(), 1, content.size(), f);
        int close_rc = fclose(f);
        if (written != content.size() || close_rc != 0) {
            unlink(full.c_str());
            return std::string();
        }
        files_.push_back(full);
        return full;
    }

private:
    std::string path_;
    std::vector<std::string> files_;
};

// Polls until pred() is true or the deadline passes; returns whether pred()
// held. Lets a test wait for the state it cares about instead of sleeping for
// a fixed amount and hoping it got there.
template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout)
{
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

// Device entries that were aggregated under path (empty when there is none).
std::vector<DeviceStat> devices_for(const StatsSnapshot &snap,
                                    const std::string &path)
{
    std::vector<DeviceStat> found;
    for (const DeviceStat &d : snap.devices) {
        if (d.path == path) {
            found.push_back(d);
        }
    }
    return found;
}

std::string write_config(TempDir &dir, const std::string &content)
{
    return dir.write_file("cfg.json", content);
}

// Restores g_tui and SIGINT/SIGTERM dispositions when leaving a test scope,
// so a failing check cannot leave the signal handler pointing at a dead TuiApp.
class SignalGuard {
public:
    SignalGuard()
        : have_int_(sigaction(SIGINT, nullptr, &prev_int_) == 0),
          have_term_(sigaction(SIGTERM, nullptr, &prev_term_) == 0)
    {}

    ~SignalGuard()
    {
        g_tui.store(nullptr, std::memory_order_release);
        if (have_int_) {
            sigaction(SIGINT, &prev_int_, nullptr);
        }
        if (have_term_) {
            sigaction(SIGTERM, &prev_term_, nullptr);
        }
    }

    SignalGuard(const SignalGuard &) = delete;
    SignalGuard &operator=(const SignalGuard &) = delete;

private:
    struct sigaction prev_int_{};
    struct sigaction prev_term_{};
    bool have_int_;
    bool have_term_;
};

}  // namespace

static void test_load_config_list_should_return_empty_when_file_missing()
{
    auto paths = load_config_list("/tmp/tui_main_test_no_such_file.json");
    CHECK(paths.empty());
    std::cout << "test_load_config_list_should_return_empty_when_file_missing passed" << std::endl;
}

static void test_load_config_list_should_parse_config_list_array()
{
    TempDir dir;
    std::string path = write_config(dir, R"({"config_list": ["/etc/hosts", "/var/log"]})");
    CHECK(!path.empty());

    auto paths = load_config_list(path);
    CHECK(paths.size() == 2);
    if (paths.size() == 2) {
        CHECK(paths[0] == "/etc/hosts");
        CHECK(paths[1] == "/var/log");
    }
    std::cout << "test_load_config_list_should_parse_config_list_array passed" << std::endl;
}

static void test_load_config_list_should_return_empty_when_key_missing()
{
    TempDir dir;
    std::string path = write_config(dir, R"({"something": ["/etc/hosts"]})");
    CHECK(!path.empty());

    auto paths = load_config_list(path);
    CHECK(paths.empty());
    std::cout << "test_load_config_list_should_return_empty_when_key_missing passed" << std::endl;
}

static void test_load_config_list_should_return_empty_when_not_array()
{
    TempDir dir;
    std::string path = write_config(dir, R"({"config_list": "/etc/hosts"})");
    CHECK(!path.empty());

    auto paths = load_config_list(path);
    CHECK(paths.empty());
    std::cout << "test_load_config_list_should_return_empty_when_not_array passed" << std::endl;
}

static void test_load_config_list_should_return_empty_on_malformed_json()
{
    TempDir dir;
    std::string path = write_config(dir, "{config_list: [");
    CHECK(!path.empty());

    auto paths = load_config_list(path);
    CHECK(paths.empty());
    std::cout << "test_load_config_list_should_return_empty_on_malformed_json passed" << std::endl;
}

static void test_load_config_list_should_return_empty_on_non_string_entries()
{
    TempDir dir;
    std::string path = write_config(dir, R"({"config_list": ["/etc/hosts", 123]})");
    CHECK(!path.empty());

    // get<std::vector<std::string>>() throws on non-string entries and the
    // helper degrades to an empty result
    auto paths = load_config_list(path);
    CHECK(paths.empty());
    std::cout << "test_load_config_list_should_return_empty_on_non_string_entries passed" << std::endl;
}

static void test_demo_feed_should_do_nothing_when_not_running()
{
    TraceStats stats({"/etc/hosts"});
    std::atomic<bool> running{false};
    std::vector<std::string> paths = {"/etc/hosts"};

    demo_feed(stats, paths, running);

    StatsSnapshot snap = stats.snapshot();
    CHECK(snap.total_events == 0);
    std::cout << "test_demo_feed_should_do_nothing_when_not_running passed" << std::endl;
}

static void test_demo_feed_should_generate_events_while_running()
{
    TraceStats stats({"/etc/hosts"});
    std::atomic<bool> running{true};
    std::vector<std::string> paths = {"/etc/hosts"};

    std::thread feeder(demo_feed, std::ref(stats), std::cref(paths), std::ref(running));

    // demo_feed emits its first burst immediately and then sleeps 200 ms
    // between bursts. Wait for the event to be visible instead of sleeping a
    // fixed 500 ms: a fixed sleep fails on a loaded CI box (and passes for the
    // wrong reason if the pacing changes). The timeout only bounds the wait --
    // it is the failure bound, not the signal.
    bool produced = wait_for(
        [&stats] { return stats.snapshot().total_events > 0; },
        std::chrono::milliseconds(5000));
    running = false;
    feeder.join();

    StatsSnapshot snap = stats.snapshot();
    CHECK(produced);
    CHECK(snap.total_events > 0);

    // Look the path up instead of asserting the table holds exactly one
    // entry: the count would break the moment the demo fixture gains a second
    // path, which says nothing about whether the configured one was summed.
    // Existence, not an exact count: if the demo fixture ever splits one path
    // into several aggregates the test would fail while the tested behaviour
    // (this path's ops are counted) is still fine.
    auto hosts = devices_for(snap, "/etc/hosts");
    CHECK(!hosts.empty());
    if (!hosts.empty()) {
        CHECK(hosts[0].ops > 0);
    }
    std::cout << "test_demo_feed_should_generate_events_while_running passed" << std::endl;
}

static void test_tui_sig_handler_should_return_safely_when_g_tui_is_null()
{
    SignalGuard guard;
    g_tui.store(nullptr, std::memory_order_release);

    tui_sig_handler(SIGINT);
    tui_sig_handler(SIGTERM);

    CHECK(signal(SIGINT, tui_sig_handler) != SIG_ERR);
    CHECK(raise(SIGINT) == 0);
    CHECK(signal(SIGTERM, tui_sig_handler) != SIG_ERR);
    CHECK(raise(SIGTERM) == 0);
    CHECK(g_tui.load(std::memory_order_acquire) == nullptr);
    std::cout << "test_tui_sig_handler_should_return_safely_when_g_tui_is_null passed" << std::endl;
}

static void test_tui_sig_handler_should_request_stop_when_g_tui_published()
{
    SignalGuard guard;
    TraceStats stats({"/etc/hosts"});
    TuiOptions opts;

    CHECK(signal(SIGINT, tui_sig_handler) != SIG_ERR);
    CHECK(signal(SIGTERM, tui_sig_handler) != SIG_ERR);

    TuiApp tui_int(stats, opts);
    CHECK(tui_int.running_.load());
    g_tui.store(&tui_int, std::memory_order_release);
    CHECK(raise(SIGINT) == 0);
    CHECK(!tui_int.running_.load());

    TuiApp tui_term(stats, opts);
    CHECK(tui_term.running_.load());
    g_tui.store(&tui_term, std::memory_order_release);
    CHECK(raise(SIGTERM) == 0);
    CHECK(!tui_term.running_.load());

    // After unpublishing g_tui, subsequent signals must no longer touch tui_term.
    tui_term.running_.store(true);
    g_tui.store(nullptr, std::memory_order_release);
    CHECK(raise(SIGINT) == 0);
    CHECK(tui_term.running_.load());
    std::cout << "test_tui_sig_handler_should_request_stop_when_g_tui_published passed" << std::endl;
}

int main()
{
    test_load_config_list_should_return_empty_when_file_missing();
    test_load_config_list_should_parse_config_list_array();
    test_load_config_list_should_return_empty_when_key_missing();
    test_load_config_list_should_return_empty_when_not_array();
    test_load_config_list_should_return_empty_on_malformed_json();
    test_load_config_list_should_return_empty_on_non_string_entries();
    test_demo_feed_should_do_nothing_when_not_running();
    test_demo_feed_should_generate_events_while_running();
    test_tui_sig_handler_should_return_safely_when_g_tui_is_null();
    test_tui_sig_handler_should_request_stop_when_g_tui_published();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed" << std::endl;
        return 1;
    }
    std::cout << "All filetrace-tui unit tests passed" << std::endl;
    return 0;
}
