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

    // unlinkat is matched against the rebuilt path as well, so a relative
    // pathname must be reported as the full path too
    struct event unl{};
    unl.pid = 100;
    unl.flag = SYS_unlinkat;
    strncpy(unl.dir1, "etc", sizeof(unl.dir1) - 1);
    strncpy(unl.filename, "hosts", sizeof(unl.filename) - 1);
    assert(p.is_valid_event(unl) == true);
    json unl_reported = json::parse(p.convert_to_string(unl));
    assert(unl_reported["file"].get<std::string>() == "/etc/hosts");

    // the reported path must be the string that was matched
    json reported = json::parse(p.convert_to_string(cfr));
    assert(reported["file"].get<std::string>() == "/etc/hosts");

    // =========================================================================
    // SYS_rename, SYS_renameat, SYS_renameat2 tests:
    // 1. is_valid_event matches directly against e.filename (destination path),
    //    unlike SYS_write / SYS_copy_file_range / SYS_unlinkat which match
    //    against get_full_path(&e).
    // 2. Legal monitored path matching.
    // 3. Illegal event filtering:
    //    - unmonitored destination path rejected (even if oldfilename matches)
    //    - bare basename rejected when conf_list has absolute path (no get_full_path fallback)
    //    - invalid filename (empty or starting with '.') rejected
    //    - invalid pid (0) rejected
    //    - process in skip_processes rejected
    // 4. convert_to_string reporting: JSON field "file" must equal e.filename
    //    (destination), "flag" matches the syscall flag, and "syscall" matches nr_map.
    // =========================================================================
    {
        const int rename_flags[] = {SYS_rename, SYS_renameat, SYS_renameat2};
        p.conf_list = {"/etc/hosts", "/data/app.conf"};
        p.skip_processes.clear();

        for (int rf : rename_flags) {
            struct event ren{};
            ren.pid = 100;
            ren.uid = 0;
            ren.gid = 0;
            ren.i_ino = 1001;
            ren.flag = rf;
            strncpy(ren.cmd, "mv", sizeof(ren.cmd) - 1);
            strncpy(ren.filename, "/etc/hosts", sizeof(ren.filename) - 1);
            strncpy(ren.oldfilename, "/tmp/hosts.tmp", sizeof(ren.oldfilename) - 1);
            // Non-empty dir fields must not alter matching: rename* uses e.filename directly
            strncpy(ren.dir1, "var", sizeof(ren.dir1) - 1);
            strncpy(ren.dir2, "log", sizeof(ren.dir2) - 1);

            // 1. Legal monitored path matching
            assert(p.is_valid_event(ren) == true);

            // Another legal path in conf_list
            strncpy(ren.filename, "/data/app.conf", sizeof(ren.filename) - 1);
            assert(p.is_valid_event(ren) == true);

            // 2. Illegal filtering: unmonitored destination path
            strncpy(ren.filename, "/etc/shadow", sizeof(ren.filename) - 1);
            assert(p.is_valid_event(ren) == false);

            // Illegal filtering: oldfilename is monitored, but destination is unmonitored -> rejected
            strncpy(ren.oldfilename, "/etc/hosts", sizeof(ren.oldfilename) - 1);
            strncpy(ren.filename, "/tmp/hosts.bak", sizeof(ren.filename) - 1);
            assert(p.is_valid_event(ren) == false);

            // Illegal filtering: bare basename "hosts" with dir1="etc" must NOT match "/etc/hosts"
            // (rename does not invoke get_full_path in is_valid_event)
            strncpy(ren.filename, "hosts", sizeof(ren.filename) - 1);
            strncpy(ren.dir1, "etc", sizeof(ren.dir1) - 1);
            assert(p.is_valid_event(ren) == false);

            // Illegal filtering: empty filename
            memset(ren.filename, 0, sizeof(ren.filename));
            assert(p.is_valid_event(ren) == false);

            // Illegal filtering: starts with '.'
            strncpy(ren.filename, ".hosts", sizeof(ren.filename) - 1);
            assert(p.is_valid_event(ren) == false);
            strncpy(ren.filename, "./etc/hosts", sizeof(ren.filename) - 1);
            assert(p.is_valid_event(ren) == false);

            // Illegal filtering: invalid PID
            strncpy(ren.filename, "/etc/hosts", sizeof(ren.filename) - 1);
            ren.pid = 0;
            assert(p.is_valid_event(ren) == false);
            ren.pid = 100;

            // Illegal filtering: process in skip_processes
            p.skip_processes = {"mv"};
            assert(p.is_valid_event(ren) == false);
            p.skip_processes.clear();
            assert(p.is_valid_event(ren) == true);

            // 3. Reporting JSON fields correctness via convert_to_string
            // Reset fields for JSON serialization test
            strncpy(ren.filename, "/etc/hosts", sizeof(ren.filename) - 1);
            strncpy(ren.oldfilename, "/tmp/hosts.tmp", sizeof(ren.oldfilename) - 1);
            strncpy(ren.dir1, "dir_a", sizeof(ren.dir1) - 1);
            strncpy(ren.dir2, "dir_b", sizeof(ren.dir2) - 1);

            json ren_json = json::parse(p.convert_to_string(ren));
            // "file" must be the target filename e.filename, NOT get_full_path(&e)
            assert(ren_json["file"].get<std::string>() == "/etc/hosts");
            assert(ren_json["file"].get<std::string>() == ren.filename);
            assert(ren_json["flag"].get<int>() == rf);
            assert(ren_json["syscall"].get<std::string>() == nr_map[rf]);
            assert(ren_json["cmd"].get<std::string>() == "mv");
            assert(ren_json["pid"].get<int>() == 100);
            assert(ren_json["inode"].get<unsigned long>() == 1001);

            // Contrast with SYS_write: write reports get_full_path(&e)
            struct event wr = ren;
            wr.flag = SYS_write;
            json wr_json = json::parse(p.convert_to_string(wr));
            assert(wr_json["file"].get<std::string>() == "/dir_b/dir_a//etc/hosts");
            assert(wr_json["file"].get<std::string>() != ren_json["file"].get<std::string>());
        }
    }

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

            // SYS_rename* targeting an unmonitored path must also be rejected
            for (int rf : {SYS_rename, SYS_renameat, SYS_renameat2}) {
                struct event ren_unrelated{};
                ren_unrelated.pid = 1;
                ren_unrelated.flag = rf;
                strncpy(ren_unrelated.cmd, "renamer", sizeof(ren_unrelated.cmd) - 1);
                strncpy(ren_unrelated.filename, "/etc/shadow", sizeof(ren_unrelated.filename) - 1);
                assert(dispatch.process_event(ren_unrelated) == 0);
            }

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

        // Normal mode also caches accepted SYS_rename* events
        for (int rf : {SYS_rename, SYS_renameat, SYS_renameat2}) {
            struct event ren_accepted{};
            ren_accepted.pid = 2;
            ren_accepted.flag = rf;
            strncpy(ren_accepted.cmd, "renamer", sizeof(ren_accepted.cmd) - 1);
            strncpy(ren_accepted.filename, "/etc/hosts", sizeof(ren_accepted.filename) - 1);
            assert(dispatch.process_event(ren_accepted) == 0);
            auto cached_ren = dispatch.get_events_from_queue(10);
            assert(cached_ren.size() == 1);
            assert(cached_ren[0]["filename"] == "/etc/hosts");
            assert(cached_ren[0]["pid"] == 2);
        }

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

        // missing 'conf' key must be rejected without touching the file
        json req4;
        req4["action"] = "add";
        assert(p2.update_config(req4) == -1);
        {
            std::ifstream in(cfg_path);
            json saved;
            in >> saved;
            assert(saved["config_list"].size() == 1);
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

    // sanitize_utf8 comprehensive unit tests
    {
        const std::string REPL = "\xEF\xBF\xBD"; // U+FFFD Unicode replacement character

        // 1. Empty string
        assert(PostData::sanitize_utf8("") == "");

        // 2. Pure ASCII strings
        assert(PostData::sanitize_utf8("hello world") == "hello world");
        assert(PostData::sanitize_utf8("/proc/12345/cmdline: python3 test.py --arg=val") ==
               "/proc/12345/cmdline: python3 test.py --arg=val");
        assert(PostData::sanitize_utf8("line1\nline2\tline3\r\n") == "line1\nline2\tline3\r\n");
        // ASCII boundary values (\x00 to \x7F)
        std::string ascii_boundary;
        ascii_boundary.push_back('\x00');
        ascii_boundary.push_back('\x01');
        ascii_boundary.push_back('\x20');
        ascii_boundary.push_back('\x7E');
        ascii_boundary.push_back('\x7F');
        assert(PostData::sanitize_utf8(ascii_boundary) == ascii_boundary);

        // 3. Valid multi-byte UTF-8 sequences (2, 3, and 4 bytes)
        // 2-byte UTF-8: Latin characters, Greek alphabet, etc.
        assert(PostData::sanitize_utf8("Café") == "Café");
        assert(PostData::sanitize_utf8("αβγδ") == "αβγδ");
        assert(PostData::sanitize_utf8("\xC2\x80\xDF\xBF") == "\xC2\x80\xDF\xBF");

        // 3-byte UTF-8: Chinese characters (汉字), Japanese, symbols
        assert(PostData::sanitize_utf8("中文字符测试") == "中文字符测试");
        assert(PostData::sanitize_utf8("こんにちは") == "こんにちは");
        assert(PostData::sanitize_utf8("★☆♠♣") == "★☆♠♣");
        assert(PostData::sanitize_utf8("\xE0\xA0\x80\xEF\xBF\xBF") == "\xE0\xA0\x80\xEF\xBF\xBF");

        // 4-byte UTF-8: Emoji and supplementary plane characters
        assert(PostData::sanitize_utf8("😀🚀🎉💡") == "😀🚀🎉💡");
        assert(PostData::sanitize_utf8("Hello 🌍! Status: ✔️") == "Hello 🌍! Status: ✔️");

        // 4. Invalid leading bytes
        // Single 0xFF
        assert(PostData::sanitize_utf8("\xFF") == REPL);
        // Single 0xFE
        assert(PostData::sanitize_utf8("\xFE") == REPL);
        // Disallowed prefix 0xF8..0xFD
        assert(PostData::sanitize_utf8("\xF8") == REPL);
        assert(PostData::sanitize_utf8("\xFC") == REPL);
        // Lone continuation bytes (0x80..0xBF)
        assert(PostData::sanitize_utf8("\x80") == REPL);
        assert(PostData::sanitize_utf8("\xBF") == REPL);
        assert(PostData::sanitize_utf8("\x9A") == REPL);
        // Invalid leading byte embedded in ASCII
        assert(PostData::sanitize_utf8("abc\xFF" "def") == "abc" + REPL + "def");
        assert(PostData::sanitize_utf8("stat:\xFE" "cmd") == "stat:" + REPL + "cmd");

        // 5. Truncated incomplete sequences
        // 2-byte sequence truncated (only leading byte 0xC2..0xDF at end of string)
        assert(PostData::sanitize_utf8("\xC3") == REPL);
        assert(PostData::sanitize_utf8("cmd_\xC3") == "cmd_" + REPL);
        // 2-byte sequence followed by non-continuation ASCII
        assert(PostData::sanitize_utf8("\xC3" "a") == REPL + "a");

        // 3-byte sequence truncated:
        // Leading byte only at end of string
        assert(PostData::sanitize_utf8("\xE4") == REPL);
        assert(PostData::sanitize_utf8("prefix_\xE4") == "prefix_" + REPL);
        assert(PostData::sanitize_utf8("\xE4" "a") == REPL + "a");
        // 3-byte sequence with only 2 bytes at end of string (missing 3rd byte)
        // E.g., '中' is \xE4\xB8\xAD, truncated to \xE4\xB8
        assert(PostData::sanitize_utf8("\xE4\xB8") == REPL + REPL);
        assert(PostData::sanitize_utf8("cmd_\xE4\xB8") == "cmd_" + REPL + REPL);
        assert(PostData::sanitize_utf8("\xE4\xB8" "x") == REPL + REPL + "x");
        // 3-byte sequence followed by invalid byte
        assert(PostData::sanitize_utf8("\xE4\xB8\xFF") == REPL + REPL + REPL);

        // 4-byte sequence truncated (e.g. emoji truncated at 1, 2, or 3 bytes):
        // E.g., 😀 is \xF0\x9F\x98\x80
        assert(PostData::sanitize_utf8("\xF0") == REPL);
        assert(PostData::sanitize_utf8("\xF0\x9F") == REPL + REPL);
        assert(PostData::sanitize_utf8("\xF0\x9F\x98") == REPL + REPL + REPL);
        assert(PostData::sanitize_utf8("emoji_\xF0\x9F\x98") == "emoji_" + REPL + REPL + REPL);
        assert(PostData::sanitize_utf8("\xF0\x9F\x98" "Z") == REPL + REPL + REPL + "Z");

        // 6. Consecutive invalid bytes replaced with \xEF\xBF\xBD
        assert(PostData::sanitize_utf8("\xFF\xFF") == REPL + REPL);
        assert(PostData::sanitize_utf8("\xFF\xFF\xFF") == REPL + REPL + REPL);
        assert(PostData::sanitize_utf8("\x80\x81\x82") == REPL + REPL + REPL);
        assert(PostData::sanitize_utf8("\xFF\xFE\x80\xBF") == REPL + REPL + REPL + REPL);
        assert(PostData::sanitize_utf8("start\xFF\xFF" "middle\x80\x81" "end") ==
               "start" + REPL + REPL + "middle" + REPL + REPL + "end");

        // 7. Simulated /proc/<pid>/stat and cmdline reading scenarios
        // Scenario A: cmdline with null-separated arguments, truncated UTF-8, and invalid bytes
        std::string mock_cmdline;
        mock_cmdline.append("python3\0", 8);
        mock_cmdline.append("/opt/app/运行.py\0", strlen("/opt/app/运行.py") + 1);
        mock_cmdline.append("--data=\xFF\xFE\0", 10);
        mock_cmdline.append("arg2", 4);

        std::string expected_cmdline;
        expected_cmdline.append("python3\0", 8);
        expected_cmdline.append("/opt/app/运行.py\0", strlen("/opt/app/运行.py") + 1);
        expected_cmdline.append("--data=");
        expected_cmdline.append(REPL);
        expected_cmdline.append(REPL);
        expected_cmdline.append("\0arg2", 5);

        assert(PostData::sanitize_utf8(mock_cmdline) == expected_cmdline);

        // Scenario B: buffer truncation on reading /proc/<pid>/cmdline or path
        // Buffer cut off in the middle of a 3-byte Chinese character (e.g. "服务\xE6\x9C")
        std::string truncated_cmd = "/usr/bin/服务\xE6\x9C";
        assert(PostData::sanitize_utf8(truncated_cmd) == "/usr/bin/服务" + REPL + REPL);

        // Scenario C: /proc/<pid>/stat line with corrupted process comm name
        std::string stat_line = "1234 (proc_\xFF\xFE_test) S 1 1234 0 0";
        assert(PostData::sanitize_utf8(stat_line) == "1234 (proc_" + REPL + REPL + "_test) S 1 1234 0 0");

        std::cout << "  PASS: sanitize_utf8 comprehensive tests" << std::endl;
    }

    // filetrace.cpp handle_event() tests (see test_filetrace.cpp)
    run_filetrace_handle_event_tests();

    std::cout << "All PostData and filetrace handle_event unit tests passed." << std::endl;
    return 0;
}
