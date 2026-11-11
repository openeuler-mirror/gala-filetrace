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
// demo_feed). The entry file's main() is renamed at include time so its
// static helpers become linkable from this test binary.

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <atomic>

#define main tui_unused_main
#include "../src/tui_main.cpp"
#undef main

namespace {

std::string make_temp_dir()
{
    char pattern[] = "/tmp/tui_main_test_XXXXXX";
    char *dir = mkdtemp(pattern);
    assert(dir != nullptr);
    return std::string(dir);
}

std::string write_file(const std::string &dir, const std::string &name, const std::string &content)
{
    std::string path = dir + "/" + name;
    FILE *f = fopen(path.c_str(), "w");
    assert(f != nullptr);
    fwrite(content.data(), 1, content.size(), f);
    fclose(f);
    return path;
}

}  // namespace

static void test_load_config_list_should_return_empty_when_file_missing()
{
    auto paths = load_config_list("/tmp/tui_main_test_no_such_file.json");
    assert(paths.empty());
    std::cout << "test_load_config_list_should_return_empty_when_file_missing passed" << std::endl;
}

static void test_load_config_list_should_parse_config_list_array()
{
    std::string dir = make_temp_dir();
    std::string path = write_file(dir, "cfg.json",
                                  R"({"config_list": ["/etc/hosts", "/var/log"]})");

    auto paths = load_config_list(path);
    assert(paths.size() == 2);
    assert(paths[0] == "/etc/hosts");
    assert(paths[1] == "/var/log");
    std::cout << "test_load_config_list_should_parse_config_list_array passed" << std::endl;
}

static void test_load_config_list_should_return_empty_when_key_missing()
{
    std::string dir = make_temp_dir();
    std::string path = write_file(dir, "cfg.json", R"({"something": ["/etc/hosts"]})");

    auto paths = load_config_list(path);
    assert(paths.empty());
    std::cout << "test_load_config_list_should_return_empty_when_key_missing passed" << std::endl;
}

static void test_load_config_list_should_return_empty_when_not_array()
{
    std::string dir = make_temp_dir();
    std::string path = write_file(dir, "cfg.json", R"({"config_list": "/etc/hosts"})");

    auto paths = load_config_list(path);
    assert(paths.empty());
    std::cout << "test_load_config_list_should_return_empty_when_not_array passed" << std::endl;
}

static void test_load_config_list_should_return_empty_on_malformed_json()
{
    std::string dir = make_temp_dir();
    std::string path = write_file(dir, "cfg.json", "{config_list: [");

    auto paths = load_config_list(path);
    assert(paths.empty());
    std::cout << "test_load_config_list_should_return_empty_on_malformed_json passed" << std::endl;
}

static void test_load_config_list_should_return_empty_on_non_string_entries()
{
    std::string dir = make_temp_dir();
    std::string path = write_file(dir, "cfg.json", R"({"config_list": ["/etc/hosts", 123]})");

    // get<std::vector<std::string>>() throws on non-string entries and the
    // helper degrades to an empty result
    auto paths = load_config_list(path);
    assert(paths.empty());
    std::cout << "test_load_config_list_should_return_empty_on_non_string_entries passed" << std::endl;
}

static void test_demo_feed_should_do_nothing_when_not_running()
{
    TraceStats stats({"/etc/hosts"});
    std::atomic<bool> running{false};
    std::vector<std::string> paths = {"/etc/hosts"};

    demo_feed(stats, paths, running);

    StatsSnapshot snap = stats.snapshot();
    assert(snap.total_events == 0);
    std::cout << "test_demo_feed_should_do_nothing_when_not_running passed" << std::endl;
}

static void test_demo_feed_should_generate_events_while_running()
{
    TraceStats stats({"/etc/hosts"});
    std::atomic<bool> running{true};
    std::vector<std::string> paths = {"/etc/hosts"};

    std::thread feeder(demo_feed, std::ref(stats), std::cref(paths), std::ref(running));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    running = false;
    feeder.join();

    StatsSnapshot snap = stats.snapshot();
    assert(snap.total_events > 0);
    assert(snap.devices.size() == 1);
    assert(snap.devices[0].path == "/etc/hosts");
    std::cout << "test_demo_feed_should_generate_events_while_running passed" << std::endl;
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
    std::cout << "All filetrace-tui unit tests passed" << std::endl;
    return 0;
}
