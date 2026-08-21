#include <cassert>
#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include "post.hpp"
#include "filetrace.h"

using json = nlohmann::json;

int main()
{
    PostData p; // use test constructor

    // is_valid_ip
    assert(p.is_valid_ip("127.0.0.1") == true);
    assert(p.is_valid_ip("0.0.0.0") == true);
    assert(p.is_valid_ip("256.0.0.1") == false);

    // is_valid_filename
    assert(p.is_valid_filename("") == false);
    assert(p.is_valid_filename(".hidden") == false);
    assert(p.is_valid_filename("file.txt") == true);

    // match_process_name
    p.skip_processes = {"bash", "verylongprocessname12345"};
    assert(p.match_process_name(p.skip_processes, "/usr/bin/bash") == true);
    assert(p.match_process_name(p.skip_processes, "/usr/bin/other") == false);

    // split_stat_line
    std::string stat_line = "123 (bash) 456 789 0 0";
    auto fields = p.split_stat_line(stat_line);
    assert(fields.size() >= 3);
    assert(fields[0] == "123");
    assert(fields[1].find("(bash)") != std::string::npos);

    // get_dir_level
    assert(p.get_dir_level("/a/b/c") == 3);
    assert(p.get_dir_level("/") == 0);
    assert(p.get_dir_level("relative/path") == -1);

    // get_full_path
    struct event e;
    memset(&e, 0, sizeof(e));
    strncpy(e.dir1, "c", sizeof(e.dir1)-1);
    strncpy(e.dir2, "b", sizeof(e.dir2)-1);
    strncpy(e.dir3, "a", sizeof(e.dir3)-1);
    strncpy(e.filename, "file", sizeof(e.filename)-1);
    std::string full = p.get_full_path(&e);
    assert(full == "/a/b/c/file");

    // compare_config_file (verbose monitor path check)
    p.verbose = true;
    p.monitor_file_path = "/tmp/monitor.conf";
    assert(p.compare_config_file(std::vector<std::string>{}, "/tmp/monitor.conf") == true);

    // add_ptrace
    json j;
    j["ptrace"] = json::array();
    p.add_ptrace(j, "cmdline", 42);
    assert(j["ptrace"].is_array());
    assert(j["ptrace"][0]["cmd"] == "cmdline");
    assert(j["ptrace"][0]["pid"] == 42);

    // get_events_from_queue
    {
        json ev = json::object();
        ev["pid"] = 1;
        std::lock_guard<std::mutex> lk(p.event_queue_mutex);
        p.event_queue.push(ev);
    }
    auto arr = p.get_events_from_queue(1);
    assert(arr.is_array());
    assert(arr.size() == 1);

    // is_valid_event for SYS_write
    p.conf_list.clear();
    p.conf_list.push_back("/a/b/c/file");
    p.skip_processes.clear();
    e.pid = 100;
    e.flag = SYS_write;
    // reuse filename and dirs from above
    assert(p.is_valid_event(e) == true);

    std::cout << "All PostData unit tests passed." << std::endl;
    return 0;
}
