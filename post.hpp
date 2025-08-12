#ifndef POST_HPP
#define POST_HPP
#endif

#include <iostream>
#include <string>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <pwd.h>
#include <grp.h>

#include "filetrace.h"

using namespace std;
using json = nlohmann::json;

class PostData {
    public:
        PostData();
        ~PostData();
        CURL *curl;
        CURLcode res;
        struct curl_slist *headers;
        std::string readBuffer; 
        std::string content_type; 
        std::string url;
        struct curl_slist *headers;
        std::string config_json;
        std::vector<std::string> conf_list;
        std::vector<std::string> skip_processes;
        json config_json_obj;

        size_t send(struct event &e);

        size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
        size_t load_config(const std::string& configFile);
        std::string convert_to_string(struct event &e);
        bool is_valid_event(struct event &e);
        std::string get_username_by_uid(unsigned int uid);
        std::string get_groupname_by_gid(unsigned int gid);
};