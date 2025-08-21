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

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}
#include "filetrace.skel.h" 
#include "filetrace.h"

using namespace std;
using json = nlohmann::json;

class PostData {
    public:
        PostData(filetrace_bpf *skel);
        ~PostData();

        std::string ragdoll_api;
        std::string config_json;
        std::vector<std::string> conf_list;
        std::vector<std::string> skip_processes;
        std::string host_id;
        std::string domain_name;
        std::string server; //provide set and config methods for ragdoll service
        int port;
        bool publish = false; // default is false
        json config_json_obj;
        int http_connect_init();
        int send(struct event e);
        int exec_map_fd;
        static int WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
        int load_config(const std::string& configFile);
        std::string convert_to_string(struct event &e);
        bool is_valid_event(struct event &e);
        std::string get_username_by_uid(unsigned int &uid);
        std::string get_groupname_by_gid(unsigned int &gid);
        int get_procinfo_by_pid_from_map(struct pinfo_t *pinfo, unsigned int &pid);
        int get_procinfo_by_pid_from_system(struct pinfo_t *pinfo, unsigned int &pid);
        void generate_proc_trace(unsigned int &pid, json &json_data);
        void add_ptrace(json& j, const std::string cmd, int pid);
        std::string get_full_path(const struct event *event);
        std::string get_loginip_by_username(const std::string &username);
        void print_event(const struct event *event);
        std::vector<std::string> split_stat_line(const std::string &line);
        void start_http_server();
        int update_config(const json &j);
        bool is_valid_ip(const std::string& ip);
    private:
        filetrace_bpf *skel;
};
#endif