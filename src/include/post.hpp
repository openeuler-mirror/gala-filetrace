#ifndef POST_HPP
#define POST_HPP

#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <curl/curl.h>
#include <pwd.h>
#include <grp.h>
#include <utmp.h>
#include <utmpx.h> 
#include <nlohmann/json.hpp>
#include <httplib.h>
#include <linux/version.h>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <chrono>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}
#include "filetrace.skel.h" 
#include "filetrace.h"
#include "exporter.hpp"

using namespace std;
using json = nlohmann::json;

static constexpr unsigned int PID_MAX_LIMIT = 4194304;
class PostData {
    public:
        PostData();
        PostData(filetrace_bpf *skel, const std::string& configFile, bool verbose = false, const std::string& monitorFilePath = "");
        ~PostData();
        static std::string sanitize_utf8(const std::string &s);
        //config items
        std::string ragdoll_api;
        std::string config_json;
        std::vector<std::string> conf_list;
        std::vector<std::string> skip_processes;
        std::string host_id;
        std::string domain_name;
        std::string cluster_id;
        std::string server; //provide set and config methods for ragdoll service
        std::string exporter_address;
        int cache_timeout_seconds;
        std::string log_level;
        std::string log_file;
        bool verbose;
        bool cache_data;
        std::string monitor_file_path;
        int max_event_queue_size;
        int max_dir_level;
        PrometheusExporter *exporter_ptr;
        int port;
        bool publish; // default is false
        json config_json_obj;
        int http_connect_init();
        // Single entry point: validate once before dispatching any event effects.
        int process_event(struct event e);
        int exec_map_fd;
        static int WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
        int load_config(const std::string& configFile);
        std::string convert_to_string(struct event &e);
        bool is_valid_event(struct event &e);
        std::string get_username_by_uid(unsigned int &uid);
        std::string get_groupname_by_gid(unsigned int &gid);
        int get_procinfo_by_pid_from_map(struct pinfo_t *pinfo, unsigned int &pid);
        int get_procinfo_by_pid_from_system(struct pinfo_t *pinfo, unsigned int &pid,
                                            unsigned long long expected_start_time = 0);
        void generate_proc_trace(unsigned int &pid, json &json_data,
                                 unsigned long long start_time = 0);
        void add_ptrace(json& j, const std::string cmd, int pid);
        std::string get_full_path(const struct event *event);
        std::string get_old_full_path(const struct event *event);
        std::string get_reported_path(const struct event *event,
                                      std::string *old_full_path = nullptr);
        std::string get_loginip_by_username(const std::string &username);
        // Queue for storing events (FIFO) - protected by mutex
        std::queue<json> event_queue;
        std::mutex event_queue_mutex;
        std::mutex config_mutex;
        // Publishing is decoupled from the ring buffer consumer through a bounded
        // FIFO: a slow or unreachable ragdoll endpoint must not stall event
        // consumption (the ring buffer would overflow and drop events silently).
        size_t max_publish_queue_size;
        std::queue<std::string> publish_queue;
        std::mutex publish_queue_mutex;
        std::condition_variable publish_cv;
        std::thread publish_thread;
        std::atomic<bool> stop_publish_thread{false};
        // Cleared when the publisher thread cannot create its curl handle, so
        // send() stops enqueueing instead of filling the queue and spamming
        // drop warnings for events that can never be delivered.
        std::atomic<bool> publish_worker_ok{true};
        // curl_global_init() succeeded; cleanup is paired in the destructor.
        bool curl_global_inited = false;
        // Drop bookkeeping: send() runs on the single ring buffer consumer
        // thread, so these do not need a lock. The log is rate limited so a
        // sustained overflow cannot flood the log (and the write happens
        // outside publish_queue_mutex).
        size_t publish_dropped_count = 0;
        std::chrono::steady_clock::time_point last_publish_drop_log{};
        void publish_worker_loop();
        std::vector<std::string> split_stat_line(const std::string &line);
        void start_http_server();
        void handle_update_config_request(const std::string &body, httplib::Response &res);
        int update_config(const json &j);
        bool is_valid_ip(const std::string& ip);
        bool compare_config_file(const vector<string> &v, const std::string &config);
        bool match_process_name(const std::vector<std::string> &skip_processes, const std::string &cmd);
        int get_dir_level(const std::string &path);
        // Single source of truth for monitor-path validation, shared by
        // load_config, update_config and handle_update_config_request so the
        // rules cannot drift apart.
        bool is_valid_monitor_path(const std::string &path);
        bool exporter_start();
        json get_events_from_queue(int count = 10);
        bool is_valid_filename(const std::string &filename);
        // Exposed for unit tests: the test-only constructor has no exporter or
        // eBPF state, so tests cannot reach this through process_event().
        void cache_event(const struct event *event);
    private:
        int send(struct event e);
        void print_event(const struct event *event);
        filetrace_bpf *skel;
        size_t log_size; 
};
#endif
