#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>
#include <nlohmann/json.hpp>
#include "post.hpp"
#include "filetrace.h"
#include "logger.hpp"

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

    // Rejected events must not write a log entry: the logger's write is also
    // observed by the BPF program and would otherwise feed events back into
    // this path indefinitely.
    {
        const std::string log_path = "/tmp/gala_test_filtered_event.log";
        unlink(log_path.c_str());
        Logger::init(log_path, "info", 0);

        struct event rejected_event{};
        assert(p.send(rejected_event) == 0);

        std::ifstream log(log_path, std::ios::binary | std::ios::ate);
        assert(log.is_open());
        assert(log.tellg() == 0);
        unlink(log_path.c_str());
    }

    // update_config must persist the whole config object, not the request body
    {
        PostData p2;
        const std::string cfg_path = "/tmp/gala_test_update_config.json";
        {
            std::ofstream out(cfg_path);
            out << "{\n"
                << "  \"host_id\": \"1\",\n"
                << "  \"domain_name\": \"zone1\",\n"
                << "  \"ragdoll_api\": \"http://localhost:8080/conftrace/data\",\n"
                << "  \"config_list\": [\"/etc/hosts\"]\n"
                << "}\n";
        }
        p2.config_json = cfg_path;
        {
            std::ifstream in(cfg_path);
            in >> p2.config_json_obj;
        }
        p2.conf_list = {"/etc/hosts"};

        // add: unrelated keys must survive the write-back
        json req;
        req["conf"] = "/etc/profile";
        req["action"] = "add";
        assert(p2.update_config(req) == 0);

        {
            std::ifstream in(cfg_path);
            json saved;
            in >> saved;
            assert(saved.value("host_id", std::string()) == "1");
            assert(saved.value("domain_name", std::string()) == "zone1");
            assert(saved.value("ragdoll_api", std::string()) ==
                   "http://localhost:8080/conftrace/data");
            assert(saved["config_list"].size() == 2);
            assert(saved["config_list"][1] == "/etc/profile");
        }
        // in-memory state must stay in sync with the file
        assert(p2.conf_list.size() == 2);
        assert(p2.config_json_obj["config_list"].size() == 2);

	// remove: must also preserve unrelated keys
	json req2;
	req2["conf"] = "/etc/profile";
	req2["action"] = "remove";
	assert(p2.update_config(req2) == 0);
	{
	    std::ifstream in(cfg_path);
	    json saved;
	    in >> saved;
	    assert(saved["config_list"].size() == 1);
	    assert(saved["config_list"][0] == "/etc/hosts");
	    assert(saved.value("host_id", std::string()) == "1");
	}

        // The HTTP request contract uses conf/action. It must not try to read a
        // non-existent "key", and client-side JSON errors must return 400.
        httplib::Response response;
        p2.handle_update_config_request(
            R"({"conf":"/etc/bashrc","action":"add"})", response);
        assert(response.status == 200);
        assert(p2.conf_list.back() == "/etc/bashrc");

        response = httplib::Response();
        p2.handle_update_config_request("not-json", response);
        assert(response.status == 400);

        response = httplib::Response();
        p2.handle_update_config_request(
            R"({"conf":42,"action":"add"})", response);
        assert(response.status == 400);

        response = httplib::Response();
        p2.handle_update_config_request(
            R"({"conf":"/etc/profile"})", response);
        assert(response.status == 400);

        unlink(cfg_path.c_str());
    }

    std::cout << "All PostData unit tests passed." << std::endl;
    return 0;
}
