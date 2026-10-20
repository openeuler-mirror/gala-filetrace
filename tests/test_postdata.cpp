#include <cassert>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <nlohmann/json.hpp>
#include "post.hpp"
#include "filetrace.h"
#include "logger.hpp"

// The filetrace.cpp handle_event() tests live in test_filetrace.cpp. That file
// is included here (it defines no main() of its own) so they run inside this
// binary without any Makefile changes.
#include "test_filetrace.cpp"

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

    // copy_file_range events carry only the basename in filename and rebuild
    // the path from dir1..dir4, so they must be matched against the full path.
    // Comparing the bare basename with an absolute conf_list entry silently
    // dropped every cp event.
    struct event cfr{};
    cfr.pid = 100;
    cfr.flag = SYS_copy_file_range;
    strncpy(cfr.dir1, "etc", sizeof(cfr.dir1) - 1);
    strncpy(cfr.filename, "hosts", sizeof(cfr.filename) - 1);

    p.conf_list = {"/etc/hosts"};
    assert(p.is_valid_event(cfr) == true);

    // a copy destination outside the monitored list must still be rejected
    strncpy(cfr.filename, "shadow", sizeof(cfr.filename) - 1);
    assert(p.is_valid_event(cfr) == false);
    strncpy(cfr.filename, "hosts", sizeof(cfr.filename) - 1);

    // the reported path must be the string that was matched
    json reported = json::parse(p.convert_to_string(cfr));
    assert(reported["file"].get<std::string>() == "/etc/hosts");

    // Rejected events must not write a log entry: the logger's write is also
    // observed by the BPF program and would otherwise feed events back into
    // this path indefinitely.
    {
        const std::string log_path = "/tmp/gala_test_filtered_event.log";
        unlink(log_path.c_str());
        Logger::init(log_path, "info", 0);

        struct event rejected_event{};
        assert(p.process_event(rejected_event) == 0);

        std::ifstream log(log_path, std::ios::binary | std::ios::ate);
        assert(log.is_open());
        assert(log.tellg() == 0);
        unlink(log_path.c_str());
    }

    // Rejected events must never reach any output or evict an accepted event,
    // including in verbose mode. A null exporter also catches accidental sends.
    {
        PostData dispatch;
        dispatch.cache_data = true;
        dispatch.max_event_queue_size = 1;
        dispatch.conf_list = {"/etc/hosts"};
        struct event accepted{};
        accepted.pid = 1;
        accepted.flag = SYS_write;
        strncpy(accepted.cmd, "writer", sizeof(accepted.cmd) - 1);
        strncpy(accepted.dir1, "etc", sizeof(accepted.dir1) - 1);
        strncpy(accepted.filename, "hosts", sizeof(accepted.filename) - 1);

        json sentinel = {{"filename", "hosts"}};
        for (bool verbose : {false, true}) {
            dispatch.verbose = verbose;
            dispatch.event_queue.push(sentinel);
            std::ostringstream rejected_output;
            auto *original = std::cout.rdbuf(rejected_output.rdbuf());

            struct event unrelated = accepted;
            strncpy(unrelated.filename, "shadow", sizeof(unrelated.filename) - 1);
            assert(dispatch.process_event(unrelated) == 0);

            dispatch.skip_processes = {"writer"};
            assert(dispatch.process_event(accepted) == 0);
            dispatch.skip_processes.clear();

            struct event unsupported = accepted;
            unsupported.flag = SYS_NR_MAX;
            assert(dispatch.process_event(unsupported) == 0);

            struct event invalid{};
            assert(dispatch.process_event(invalid) == 0);
            std::cout.rdbuf(original);
            assert(rejected_output.str().empty());
            assert(dispatch.get_events_from_queue(10) == json::array({sentinel}));
        }

        // Verbose mode prints accepted events without publishing or caching.
        std::ostringstream printed;
        auto *original = std::cout.rdbuf(printed.rdbuf());
        assert(dispatch.process_event(accepted) == 0);
        std::cout.rdbuf(original);
        assert(printed.str().find("Filename: hosts") != std::string::npos);
        assert(dispatch.get_events_from_queue(10).empty());

        // Normal mode still caches accepted events when publishing is disabled.
        dispatch.verbose = false;
        dispatch.exporter_ptr = new PrometheusExporter("127.0.0.1:0", 30);
        assert(dispatch.process_event(accepted) == 0);
        auto cached = dispatch.get_events_from_queue(10);
        assert(cached.size() == 1);
        assert(cached[0]["filename"] == "hosts");

        dispatch.cache_data = false;
        assert(dispatch.process_event(accepted) == 0);
        assert(dispatch.get_events_from_queue(10).empty());
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

        // unknown action must be rejected without touching the file
        json req3;
        req3["conf"] = "/etc/fstab";
        req3["action"] = "frobnicate";
        assert(p2.update_config(req3) == -1);
        {
            std::ifstream in(cfg_path);
            json saved;
            in >> saved;
            assert(saved["config_list"].size() == 1);
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

    // load_config: full validation matrix
    {
        Logger::init("/tmp/gala_test_loadcfg.log", "info", 0);

        const std::string good_cfg = "/tmp/gala_test_loadcfg_good.json";
        {
            std::ofstream out(good_cfg);
            out << R"({
  "host_id": "h1",
  "domain_name": "d1",
  "ragdoll_api": "http://127.0.0.1:1/api",
  "config_list": ["/etc/hosts"],
  "skip_processes_list": ["bash"],
  "log_level": "debug",
  "log_file": "/tmp/gala_test_loadcfg.out.log",
  "server": "127.0.0.1"
})";
        }
        PostData pc;
        assert(pc.load_config(good_cfg) == 0);
        assert(pc.host_id == "h1");
        assert(pc.domain_name == "d1");
        assert(pc.ragdoll_api == "http://127.0.0.1:1/api");
        assert(pc.conf_list.size() == 1);
        assert(pc.conf_list[0] == "/etc/hosts");
        assert(pc.skip_processes.size() == 1);
        assert(pc.skip_processes[0] == "bash");
        assert(pc.server == "127.0.0.1");
        assert(pc.port == 8080);
        assert(pc.max_dir_level == 4);
        assert(pc.log_level == "debug");

        PostData pc2;
        assert(pc2.load_config("/tmp/gala_test_loadcfg_missing.json") == -1);

        const std::string bad_json = "/tmp/gala_test_loadcfg_badjson.json";
        {
            std::ofstream out(bad_json);
            out << "not a json";
        }
        PostData pc3;
        assert(pc3.load_config(bad_json) == -1);

        const std::string empty_list = "/tmp/gala_test_loadcfg_emptylist.json";
        {
            std::ofstream out(empty_list);
            out << R"({"host_id":"h","domain_name":"d","ragdoll_api":"u","config_list":[]})";
        }
        PostData pc4;
        assert(pc4.load_config(empty_list) == -1);

        const std::string rel_path = "/tmp/gala_test_loadcfg_relpath.json";
        {
            std::ofstream out(rel_path);
            out << R"({"host_id":"h","domain_name":"d","ragdoll_api":"u","config_list":["etc/hosts"],"skip_processes_list":[]})";
        }
        PostData pc5;
        assert(pc5.load_config(rel_path) == -1);

        const std::string deep_path = "/tmp/gala_test_loadcfg_deeppath.json";
        {
            std::ofstream out(deep_path);
            out << R"({"host_id":"h","domain_name":"d","ragdoll_api":"u","config_list":["/a/b/c/d/e/file"],"skip_processes_list":[]})";
        }
        PostData pc6;
        assert(pc6.load_config(deep_path) == -1);

        const std::string empty_host = "/tmp/gala_test_loadcfg_emptyhost.json";
        {
            std::ofstream out(empty_host);
            out << R"({"host_id":"","domain_name":"d","ragdoll_api":"u","config_list":["/etc/hosts"],"skip_processes_list":[]})";
        }
        PostData pc7;
        assert(pc7.load_config(empty_host) == -1);

        const std::string bad_server = "/tmp/gala_test_loadcfg_badserver.json";
        {
            std::ofstream out(bad_server);
            out << R"({"host_id":"h","domain_name":"d","ragdoll_api":"u","config_list":["/etc/hosts"],"skip_processes_list":[],"server":"300.1.1.1"})";
        }
        PostData pc8;
        assert(pc8.load_config(bad_server) == -1);

        const std::string no_api = "/tmp/gala_test_loadcfg_noapi.json";
        {
            std::ofstream out(no_api);
            out << R"({"host_id":"h","domain_name":"d","config_list":["/etc/hosts"],"skip_processes_list":[]})";
        }
        PostData pc9;
        assert(pc9.load_config(no_api) == -1);

        unlink(good_cfg.c_str());
        unlink(bad_json.c_str());
        unlink(empty_list.c_str());
        unlink(rel_path.c_str());
        unlink(deep_path.c_str());
        unlink(empty_host.c_str());
        unlink(bad_server.c_str());
        unlink(no_api.c_str());
    }

    // cache_event: disabled, and FIFO eviction beyond max_event_queue_size
    {
        PostData pc;
        struct event ce;
        memset(&ce, 0, sizeof(ce));
        ce.ppid = 0;
        ce.flag = SYS_write;
        strncpy(ce.cmd, "bash", sizeof(ce.cmd) - 1);
        strncpy(ce.filename, "f", sizeof(ce.filename) - 1);

        // cache_data disabled: nothing is cached
        pc.cache_data = false;
        ce.pid = 1;
        pc.cache_event(&ce);
        assert(pc.get_events_from_queue(10).size() == 0);

        // enabled: oldest event evicted once the queue exceeds max size
        pc.cache_data = true;
        pc.max_event_queue_size = 2;
        for (unsigned int i = 2; i <= 4; ++i) {
            ce.pid = i;
            pc.cache_event(&ce);
        }
        auto arr = pc.get_events_from_queue(10);
        assert(arr.is_array());
        assert(arr.size() == 2);
        assert(arr[0]["pid"] == 3);
        assert(arr[1]["pid"] == 4);
    }

    // WriteCallback appends curl payload to the caller's buffer
    {
        std::string buf;
        const char payload[] = "hello";
        assert(PostData::WriteCallback(const_cast<char *>(payload), 1, 5, &buf) == 5);
        assert(buf == "hello");
    }

    // get_username_by_uid / get_groupname_by_gid
    {
        PostData pc;
        unsigned int uid = static_cast<unsigned int>(getuid());
        assert(!pc.get_username_by_uid(uid).empty());
        unsigned int uid_missing = 54321;
        if (getpwuid(uid_missing) == nullptr) {
            assert(pc.get_username_by_uid(uid_missing) == "54321");
        }
        unsigned int gid = static_cast<unsigned int>(getgid());
        assert(!pc.get_groupname_by_gid(gid).empty());
        unsigned int gid_missing = 54321;
        if (getgrgid(gid_missing) == nullptr) {
            assert(pc.get_groupname_by_gid(gid_missing) == "54321");
        }
    }

    // get_procinfo_by_pid_from_system: own process and invalid pids
    {
        PostData pc;
        struct pinfo_t pi;
        memset(&pi, 0, sizeof(pi));
        unsigned int my_pid = static_cast<unsigned int>(getpid());
        assert(pc.get_procinfo_by_pid_from_system(&pi, my_pid) == 0);
        assert(pi.pid == static_cast<unsigned int>(getppid()));
        assert(strlen(pi.comm) > 0);

        unsigned int zero_pid = 0;
        assert(pc.get_procinfo_by_pid_from_system(&pi, zero_pid) == -1);
        unsigned int huge_pid = PID_MAX_LIMIT + 1;
        assert(pc.get_procinfo_by_pid_from_system(&pi, huge_pid) == -1);
    }

    // generate_proc_trace: invalid pid yields no entries, own pid walks up the chain
    {
        PostData pc;

        json j1;
        unsigned int bad_pid = 1;
        pc.generate_proc_trace(bad_pid, j1);
        assert(!j1.contains("ptrace") || j1["ptrace"].empty());

        json j2;
        unsigned int my_pid = static_cast<unsigned int>(getpid());
        pc.generate_proc_trace(my_pid, j2);
        assert(j2.contains("ptrace"));
        assert(j2["ptrace"].size() >= 1);
        assert(j2["ptrace"][0]["pid"] == static_cast<int>(my_pid));
    }

    // filetrace.cpp handle_event() tests (see test_filetrace.cpp)
    run_filetrace_handle_event_tests();

    std::cout << "All PostData and filetrace handle_event unit tests passed." << std::endl;
    return 0;
}
