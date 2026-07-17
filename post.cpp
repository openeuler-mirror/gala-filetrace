#include  "post.hpp"
#include "logger.hpp"
#include <cstring>


// Replace invalid UTF-8 sequences with the Unicode replacement character (U+FFFD)
static std::string sanitize_utf8(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    const unsigned char *data = reinterpret_cast<const unsigned char*>(s.data());
    size_t i = 0, n = s.size();
    while (i < n) {
        unsigned char c = data[i];
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
            ++i;
        } else if ((c >> 5) == 0x6) {
            if (i + 1 < n && (data[i+1] & 0xC0) == 0x80) {
                out.append(reinterpret_cast<const char*>(&data[i]), 2);
                i += 2;
            } else {
                out.append("\xEF\xBF\xBD");
                ++i;
            }
        } else if ((c >> 4) == 0xE) {
            if (i + 2 < n && (data[i+1] & 0xC0) == 0x80 && (data[i+2] & 0xC0) == 0x80) {
                out.append(reinterpret_cast<const char*>(&data[i]), 3);
                i += 3;
            } else {
                out.append("\xEF\xBF\xBD");
                ++i;
            }
        } else if ((c >> 3) == 0x1E) {
            if (i + 3 < n && (data[i+1] & 0xC0) == 0x80 && (data[i+2] & 0xC0) == 0x80 && (data[i+3] & 0xC0) == 0x80) {
                out.append(reinterpret_cast<const char*>(&data[i]), 4);
                i += 4;
            } else {
                out.append("\xEF\xBF\xBD");
                ++i;
            }
        } else {
            out.append("\xEF\xBF\xBD");
            ++i;
        }
    }
    return out;
}

PostData::PostData(filetrace_bpf *skel, const std::string& configFile, bool verbose, const std::string& monitor_file_path)
    :  config_json(configFile),
        publish(false),
        verbose(verbose),
        monitor_file_path(monitor_file_path)
{
    std::cout << "Initializing PostData!" << std::endl;
    if(configFile.empty()) {
        throw std::runtime_error("Configuration file path is empty!");
    }
    int ret = load_config(config_json);
    if (ret != 0) {
        throw std::runtime_error("Configuration load failed");
    }
    // initialize logger from config (optional keys: log_level, log_file, log_size)
    try 
    {
        Logger::init(log_file, log_level, log_size);
        Logger::info("Logger initialized, level=" + log_level + ", file=" + log_file);
    } catch (const std::exception &e) {
        std::cerr << "Failed to initialize logger: " << e.what() << std::endl;
    }
    if(skel == nullptr) {
        throw std::runtime_error("eBPF skeleton is null!");
    }
    this->skel = skel;
    this->exec_map_fd = bpf_map__fd(skel->maps.exec_map);
    if (exec_map_fd < 0) {
        throw std::runtime_error("Failed to get exec_map fd!");
    }
    exporter_start();
    if(publish) {
        std::thread server_thread(&PostData::start_http_server, this);
        server_thread.detach(); // Detach the thread to run the HTTP server in the background
    }
    Logger::info("PostData initialized successfully!");
}

PostData::~PostData() 
{
    Logger::info("PostData destroyed");
    return;
}

int PostData::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb; 
}
bool PostData::is_valid_ip(const std::string& ip) {
    static const std::regex ip_regex(
        R"(^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)"
    );
    if (!std::regex_match(ip, ip_regex)) return false;
    std::istringstream iss(ip);
    std::string token;
    while (std::getline(iss, token, '.')) {
        int num = std::stoi(token);
        if (num < 0 || num > 255) return false;
    }
    return true;
}
int PostData::load_config(const std::string& configFile)
{
    Logger::info("Loading configuration from " + configFile);
    std::ifstream file(configFile);
    if (!file.is_open()) {
        Logger::error("Could not open config file: " + configFile);
        return -1;
    }
    try {
        file >> config_json_obj;
        file.close();
        conf_list = config_json_obj["config_list"].get<std::vector<std::string>>();
        if (conf_list.empty()) 
        {
            Logger::error("Configuration list is empty, please check your config file.");
            return -1; 
        }
        //log level
        log_level = config_json_obj.value("log_level", std::string("info"));
        log_file = config_json_obj.value("log_file", std::string("/var/log/filetrace.log"));
        
        // Parse log_size (in MB, default 100 MB)
        int log_size_mb = config_json_obj.value("log_size", 100);
        log_size = (size_t)log_size_mb * 1024 * 1024;  // Convert MB to bytes
        
        Logger::info("Log level set to: " + log_level + ", log file: " + log_file + 
                     ", log size limit: " + std::to_string(log_size_mb) + " MB");
        //check dir level
        for (const auto& conf : conf_list) {
            int level = get_dir_level(conf);
            if (level < 0) {
                Logger::error("Invalid path in config: " + conf);
                return -1; 
            }
            if (level > MAX_DIR_LEVEL) {
                Logger::error("Path exceeds maximum directory level (" + std::to_string(MAX_DIR_LEVEL) + "): " + conf);
                return -1; 
            }
        }
        host_id = config_json_obj["host_id"].get<std::string>();
        if (host_id.empty()) {
            Logger::error("Host ID is empty, please check your config file.");
            return -1; 
        }
        domain_name = config_json_obj["domain_name"].get<std::string>();
        if (domain_name.empty()) {
            Logger::error("Domain name is empty, please check your config file.");
            return -1; 
        }
        ragdoll_api = config_json_obj["ragdoll_api"].get<std::string>();
        skip_processes = config_json_obj["skip_processes_list"].get<std::vector<std::string>>();

        publish = config_json_obj.value("publish", false); 
        cache_data = config_json_obj.value("cache_data", false);
        server = config_json_obj.value("server", "0.0.0.0");
        if (!is_valid_ip(server)) {
            Logger::error("Invalid server IP address: " + server);
            return -1; 
        }
        port = config_json_obj.value("port", 8080);
        exporter_address = config_json_obj.value("exporter_address", "0.0.0.0:8080");
        Logger::info("Configuration loaded from " + configFile);
        Logger::info("ragdoll_api: " + ragdoll_api);
        Logger::info("skip_processes: ");
        for (const auto& process : skip_processes) {
            Logger::info(process);
        }
        Logger::info("conf_list: ");
        for (const auto& conf : conf_list) {
            Logger::info(conf);
        }
        Logger::info("host_id: " + host_id);
        Logger::info("domain_name: " + domain_name);
        Logger::info("publish: " + std::string(publish ? "true" : "false"));
        return 0;
    } catch (json::parse_error& e) {
        Logger::error("JSON parse error: " + std::string(e.what()));
    } catch (json::type_error& e) {
        Logger::error("JSON type error: " + std::string(e.what()));
    } catch (std::exception& e) {
        Logger::error("General error: " + std::string(e.what()));
    }
    return -1; 
}

int PostData::send(struct event e) 
{
    Logger::debug("Send event to Aops.");
    if(!is_valid_event(e)) {
        Logger::error("Skip event detected, skipping.");
        return 0; 
    }
    exporter_ptr->set_metrics(e);
    print_event(&e);
    std::string data = convert_to_string(e);
    if (data.empty()) {
        Logger::error("Failed to convert event to JSON string.");
        return 1; 
    }
    if(publish == false) {
        Logger::info("Publishing is disabled, skip it.");
        Logger::info("Data: " + data);
        return 0; 
    }
    Logger::info("Sending data to Aops: " + data);
    long http_code = 0;
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    std::string readBuffer; 
    std::string content_type = "Content-Type: application/json"; 
    curl = curl_easy_init(); 
    if (!curl) {
        Logger::error("Failed to initialize CURL.");
        return 1; 
    }
    headers = curl_slist_append(headers, content_type.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, ragdoll_api.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    //curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        Logger::error("curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        Logger::info("HTTP POST successful, HTTP Status Code: " + std::to_string(http_code));
        //Logger::info("Response: " + readBuffer);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return 0; 
}

void PostData::print_event(const struct event *event) 
{
    std::cout << "Event Details:" << std::endl;
    std::cout << "PID: " << event->pid << ", PPID: " << event->ppid << ", ";
    std::cout << "Command: " << event->cmd << ", ";
    std::cout << "Syscall: " << nr_map[event->flag] << ", ";
    std::cout << "Filename: " << event->filename << ", ";
    std::cout << "Old Filename: " << event->oldfilename << ", ";
    std::cout << "Directory1: " << event->dir1 
              << ", Directory2: " << event->dir2 
              << ", Directory3: " << event->dir3 
              << ", Directory4: " << event->dir4 
              << std::endl;
    Logger::info("Event Details: PID: " + std::to_string(event->pid) + 
                 ", PPID: " + std::to_string(event->ppid) + 
                 ", Command: " + std::string(event->cmd) + 
                 ", Syscall: " + std::string(nr_map[event->flag]) + 
                 ", Filename: " + std::string(event->filename) + 
                 ", Old Filename: " + std::string(event->oldfilename) + 
                 ", Directory1: " + std::string(event->dir1) + 
                 ", Directory2: " + std::string(event->dir2) + 
                 ", Directory3: " + std::string(event->dir3) + 
                 ", Directory4: " + std::string(event->dir4));
}
void PostData::cache_event(const struct event *event)
{
    Logger::debug("Caching event for API access.");
    if(!cache_data) {
        Logger::info("API server is disabled, not caching event.");
        return;
    }
    try {
        json j;
        j["pid"] = event->pid;
        j["ppid"] = event->ppid;
        j["cmd"] = std::string(event->cmd);
        j["flag"] = event->flag;
        j["syscall"] = std::string(nr_map[event->flag]);
        j["filename"] = std::string(event->filename);
        j["oldfilename"] = std::string(event->oldfilename);
        j["dir1"] = std::string(event->dir1);
        j["dir2"] = std::string(event->dir2);
        j["dir3"] = std::string(event->dir3);
        j["dir4"] = std::string(event->dir4);
        {
            std::lock_guard<std::mutex> lk(event_queue_mutex);
            if (event_queue.size() >= MAX_EVENT_QUEUE_SIZE) {
                event_queue.pop(); 
            }
            event_queue.push(std::move(j)); 
        }
    } catch (const std::exception &ex) {
        Logger::error(std::string("Failed to build event queue JSON: ") + ex.what());
    }
}
void PostData::add_ptrace(json& j, const std::string cmd, int pid) 
{
    j["ptrace"].push_back({{"cmd", cmd}, {"pid", pid}});
}

void PostData::generate_proc_trace(unsigned int &pid, json &json_data) 
{
    Logger::debug("Generating process trace for PID: " + std::to_string(pid));
    unsigned int proc_id = pid;
    if (proc_id  <= 1) {
        Logger::error("Invalid PID: " + std::to_string(pid));
        return; 
    }
    struct pinfo_t *pinfo = (struct pinfo_t *)malloc(sizeof(struct pinfo_t));
    if (!pinfo) {
        Logger::error("Failed to allocate memory for pinfo_t");
        return; 
    }
    // zero-init to avoid uninitialized garbage bytes (which can produce invalid UTF-8)
    memset(pinfo, 0, sizeof(struct pinfo_t));
    while (true)
    {
        if (proc_id == 0) {
            break; 
        }
        Logger::info("Generating proc trace for PID: " + std::to_string(proc_id));
        int ret = get_procinfo_by_pid_from_map(pinfo, proc_id);
        if (ret) {
            ret = get_procinfo_by_pid_from_system(pinfo, proc_id);
            if (ret) {
                break;
            }
        }
    std::string pinfo_cmd = std::string(pinfo->comm) + " " + 
                std::string(pinfo->arg1) + " " +
                std::string(pinfo->arg2) + " " +
                std::string(pinfo->arg3) + " " +
                std::string(pinfo->arg4);
    // sanitize invalid UTF-8 bytes 
    pinfo_cmd = sanitize_utf8(pinfo_cmd);
    add_ptrace(json_data, std::move(pinfo_cmd), proc_id);
        proc_id = pinfo->pid; 
    }
    free(pinfo);
    return;
}

std::string PostData::convert_to_string(struct event &e) 
{
    json json_data;
    std::string username = get_username_by_uid(e.uid);
    std::string groupname = get_groupname_by_gid(e.gid);
    int flag = e.flag;
    json_data["ptrace"] = json::array();
    generate_proc_trace(e.pid, json_data);

    json_data["host_id"] = host_id;
    json_data["domain_name"] = domain_name;  
    json_data["flag"] = e.flag;
    json_data["syscall"] = nr_map[e.flag];
    if(e.flag == SYS_write)
    {
        json_data["file"] = get_full_path(&e);
    } else {
        json_data["file"] = e.filename;
    }
    json_data["user"] = username;
    json_data["group"] = groupname;
    json_data["pid"] = e.pid;
    json_data["inode"] = e.i_ino;
    json_data["cmd"] = e.cmd;
    json_data["loginip"] = get_loginip_by_username(username);
    return json_data.dump(); 
}
bool PostData::compare_config_file(const vector<string> &v, const std::string &config) 
{
    if (verbose) {
        Logger::info("Comparing config file: " + config + " with " + monitor_file_path);
        if (monitor_file_path == config) {
            return true;
        } 
    }

    if (v.empty() || config.empty()) {
        return false; 
    }

    std::lock_guard<std::mutex> lk(config_mutex);
    for (const auto& item : v) {
        if (item == config) {
            return true;
        }
    }
    return false;
}

bool PostData::match_process_name(const std::vector<std::string> &skip_processes, const std::string &cmd)
{
    if (skip_processes.empty() || cmd.empty()) {
        return false;
    }
    size_t pos = cmd.find_last_of('/');
    std::string cmd_tmp = cmd.substr(pos + 1);
    
    for (const auto &skip_cmd : skip_processes) {
        //compre skip_cmd and cmd_tmp before 15 characters

        if (skip_cmd.size() > 15 || cmd_tmp.size() > 15) {
            if (skip_cmd.compare(0, 15, cmd_tmp, 0, 15) == 0) {
                return true;
            }
        } else {
            if (skip_cmd == cmd_tmp) {
                return true;
            }
        }
        
    }
    return false;
}

bool PostData::is_valid_filename(const std::string &filename) 
{
    if (filename.empty() || filename[0] == '.') {
        return false;
    }
    return true;
}
bool PostData::is_valid_event(struct event &e) 
{
   if (!is_valid_filename(e.filename)) {
        return false;
   }
   std::string fullpath = "";
    if (e.pid == 0) {
        return false; 
    }
    std::string cmd = e.cmd;
    if(match_process_name(skip_processes, cmd)) {
        return false; 
    }
    switch (e.flag) {
        case SYS_unlinkat:
            fullpath = get_full_path(&e);
            if(!compare_config_file(conf_list, fullpath)) {
                return false; 
            }
            break;
        case SYS_copy_file_range:
        case SYS_rename:
        case SYS_renameat:
        case SYS_renameat2:
            if(!compare_config_file(conf_list, e.filename)) {
                return false; 
            }
            break;       
        case SYS_write:
            fullpath = get_full_path(&e);
            if(!compare_config_file(conf_list, fullpath)) {
                return false; 
            }
            break;
        default:
            return false; 
    }
    return true; 
}

int  PostData::get_procinfo_by_pid_from_map(struct pinfo_t *pinfo , unsigned int &pid)
{
    int ret = bpf_map_lookup_elem(exec_map_fd, &pid, pinfo);
    if (ret != 0) {
        Logger::error("Failed to lookup pinfo for PID " + std::to_string(pid) + ", ret:" + std::to_string(ret));
        return -1; 
    }
    Logger::info("Found pinfo in map for PID " + std::to_string(pid) + ": " 
                 + std::string(pinfo->comm) + ", args: " 
                 + std::string(pinfo->arg1) + " " 
                 + std::string(pinfo->arg2) + " "
                 + std::string(pinfo->arg3) + " "
                 + std::string(pinfo->arg4));
    return 0;
}

std::vector<std::string> PostData::split_stat_line(const std::string &line) 
{
    std::vector<std::string> result;
    size_t start = 0, end = 0;

    // first item is pid
    end = line.find(' ');
    result.push_back(line.substr(start, end - start));
    start = end + 1;

    // second item is comm 
    end = line.find(' ', start);
    start = line.find('(');
    end = line.rfind(')');
    result.push_back(line.substr(start, end - start + 1));
    start = end + 2;

    // other
    std::istringstream iss(line.substr(start));
    std::string token;
    while (iss >> token) {
        result.push_back(token);
    }

    return result;
}

int PostData::get_procinfo_by_pid_from_system(struct pinfo_t *pinfo ,unsigned int &pid)
{
    char proc_path[1024];
    //get ppid and comm from /proc/<pid>/stat
    if(pid == 0 || pid > PID_MAX_LIMIT) {
        Logger::error("Invalid PID: " + std::to_string(pid));
        return -1; 
    }
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/stat", pid);
    std::ifstream stat_file(proc_path);
    if (!stat_file.is_open()) {
        Logger::error("Failed to open stat file: " + std::string(proc_path));
        return -1;
    }
    std::string line;
    std::getline(stat_file, line);
    stat_file.close();

    auto fields = split_stat_line(line);
    if (fields.size() < 5) {
        Logger::error(std::string(proc_path) + " content invalid.");
        return -1;
    }
    // pid, comm, ppid
    pinfo->pid = std::stoul(fields[3]);
    strncpy(pinfo->comm, fields[1].c_str(), sizeof(pinfo->comm) - 1);
    pinfo->comm[sizeof(pinfo->comm) - 1] = '\0';
    return 0;
}

std::string PostData::get_username_by_uid(unsigned int &uid)
{
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        return std::string(pw->pw_name);
    }
    return std::to_string(uid); 
}

std::string PostData::get_groupname_by_gid(unsigned int &gid)
{
    struct group *gr = getgrgid(gid);
    if (gr) {
        return std::string(gr->gr_name);
    }
    return std::to_string(gid);
}

// dir:/dir4/dir3/dir2/dir1/filename
std::string PostData::get_full_path(const struct event *event) 
{
    std::string fullpath;
    Logger::info("dir: dir1: " + std::string(event->dir1) + ", dir2: " + std::string(event->dir2)
              + ", dir3: " + std::string(event->dir3) + ", dir4: " + std::string(event->dir4)
              + ", filename: " + std::string(event->filename));
    if (event->dir4[0] == '/') {
        fullpath += std::string(event->dir4) + std::string(event->dir3) + "/" 
                    + std::string(event->dir2) + "/" + std::string(event->dir1) + "/" + std::string(event->filename);
        Logger::info("The 4 level fullpath: " + fullpath);
        return fullpath;
    }
    if (event->dir3[0] == '/') {
        fullpath += std::string(event->dir3) + std::string(event->dir2) + "/" + std::string(event->dir1)+ "/" + std::string(event->filename);
        Logger::info("The 3 level fullpath: " + fullpath);
        return fullpath;
    }
    if (event->dir2[0] == '/') {
        fullpath += std::string(event->dir2) + std::string(event->dir1)+ "/" + std::string(event->filename);
        Logger::info("The 2 level fullpath: " + fullpath);
        return fullpath;
    }
    if (event->dir1[0] == '/') {
        fullpath += std::string(event->dir1) + std::string(event->filename);
        Logger::info("The 1 level fullpath: " + fullpath);
        return fullpath;
    }
    return fullpath;
}

std::string PostData::get_loginip_by_username(const std::string& username) 
{
    struct utmpx *up;
    std::string clientip = "127.0.0.1";
    if (username.empty()) {
        return clientip; 
    }
    setutxent();
    while ((up = getutxent()) != NULL) {
        if (up->ut_type == USER_PROCESS &&
            std::string(up->ut_user) == username &&
            std::string(up->ut_host).find('.') != std::string::npos) { 
            clientip = up->ut_host;
            break; 
        }
    }
    endutxent();
    return clientip;
}
int PostData::update_config(const json &j) 
{
    Logger::info("Updating configuration with JSON: " + j.dump());
    std::lock_guard<std::mutex> lk(config_mutex);
    if (j.contains("conf")) {
        std::string conf = j["conf"];
        std::string action = j["action"];
        if (action == "add") {
            conf_list.push_back(conf);
        } else if (action == "remove") {
            conf_list.erase(std::remove(conf_list.begin(), conf_list.end(), conf), conf_list.end());
        } else {
            Logger::error("Unknown action: " + action);
            return -1; 
        }
    }else {
        Logger::error("JSON does not contain 'conf' key.");
        return -1; 
    }
    //write to file
    std::ofstream file(config_json);
    if (!file.is_open()) {
        Logger::error("Could not open config file for writing: " + config_json);
        return -1;
    }
    file << j.dump(4);
    file.close();
    Logger::info("Configuration updated successfully.");
    return 0; 
}
void PostData::start_http_server() 
{
    Logger::info("Starting HTTP Server.");
    httplib::Server svr;
    svr.Post("/filetrace", [this](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        //body {"conf": "value", "action": "add|remove"}
        std::string value = j["key"];
        std::string action = j["action"];
        int ret = update_config(j);
        if (ret != 0) {
            res.status = 500;
            res.set_content("Failed to update configuration", "text/plain");
            return;
        }
        res.status = 200;
        res.set_content("Configuration updated successfully", "text/plain");
    });
    svr.Get("/filetrace", [this](const httplib::Request& req, httplib::Response& res) {
        json j;
        j["status"] = "ok";
        std::lock_guard<std::mutex> lk(config_mutex);
        j["conf_list"] = conf_list;
        res.set_content(j.dump(2), "application/json");
    });
    // New endpoint: return one events from evnet queue 
    if(cache_data) {
        Logger::info("API monitor file status is enabled, caching events for API access.");
        svr.Get("/monitor_file_status", [this](const httplib::Request& req, httplib::Response& res) {
            int count = 10;
            auto it = req.params.find("count");
            if (it != req.params.end() && !it->second.empty()) {
                try {
                    count = std::stoi(it->second);
                } catch (const std::exception& e) {
                    Logger::error("Invalid count parameter for /monitor_file_status: " + it->second + ", error: " + e.what());
                    count = 10;
                }
                if (count <= 0 || count > MAX_EVENT_QUEUE_SIZE) {
                    count = 10;
                }
            }

            json event_j = get_events_from_queue(count);
            if (event_j.empty()) {
                json r;
                r["status"] = "no_event";
                res.status = 204;
                res.set_content(r.dump(2), "application/json");
                return;
            }

            json response;
            response["status"] = "ok";
            response["count"] = event_j.size();
            response["events"] = event_j;
            res.status = 200;
            res.set_content(response.dump(2), "application/json");
        });
    }
    Logger::info("Starting HTTP server at " + server + ":" + std::to_string(port));
    svr.listen(this->server.c_str(), this->port);
}
int PostData::get_dir_level(const std::string &path) 
{
    Logger::info("Getting dir level number for path: " + path);
    if (path.empty() || path[0] != '/') {
        return -1; 
    }
    std::string tmp_path = path;
    if(tmp_path.back() == '/'){
       tmp_path = tmp_path.substr(0, tmp_path.size() - 1);
    }
    return std::count(tmp_path.begin(), tmp_path.end(), '/'); 
}
json PostData::get_events_from_queue(int count)
{
    std::lock_guard<std::mutex> lk(event_queue_mutex);
    if (event_queue.empty()) {
        return json::array();
    }

    json events = json::array();
    int actual_count = std::min(count, static_cast<int>(event_queue.size()));
    for (int i = 0; i < actual_count; ++i) {
        events.push_back(event_queue.front());
        event_queue.pop();
    }
    return events;
}
bool PostData::exporter_start() 
{
    Logger::info("Starting Prometheus Exporter at " + exporter_address);
    if(exporter_address.empty()) {
        throw std::runtime_error("Exporter address is empty!");
    }
    try {
        exporter_ptr = new PrometheusExporter(exporter_address);
    } catch (const std::exception& e) {
        Logger::error("Failed to initialize Prometheus Exporter: " + std::string(e.what()));
        throw;
    }
    // store the counter returned by exporter for later use
    exporter_ptr->file_access_counter = &exporter_ptr->add_counter(
        "file_access_total",
        "File access events",
        {}
    );
    return true;
}
