#include  "post.hpp"

PostData::PostData(filetrace_bpf *skel)
    :  config_json("/etc/gala-filetrace/gala-filetrace.json"),
        publish(false)
{
    std::cout << "Initializing PostData!" << std::endl;
    int ret = load_config(config_json);
    if (ret != 0) {
        throw std::runtime_error("Configuration load failed");
    }
    this->skel = skel;
    this->exec_map_fd = bpf_map__fd(skel->maps.exec_map);
    if (exec_map_fd < 0) {
        throw std::runtime_error("Failed to get exec_map fd!");
    }
    if(publish) {
        std::thread server_thread(&PostData::start_http_server, this);
        server_thread.detach(); // Detach the thread to run the HTTP server in the background
    }
}

PostData::~PostData() 
{
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
    std::ifstream file(configFile);
    if (!file.is_open()) {
        std::cerr << "Could not open config file: " << configFile << std::endl;
        return -1; 
    }
    try {
        file >> config_json_obj;
        file.close();
        conf_list = config_json_obj["config_list"].get<std::vector<std::string>>();
        if (conf_list.empty()) 
        {
            std::cerr << "Configuration list is empty, please check your config file." << std::endl;
            return -1; 
        }
        //check dir level
        for (const auto& conf : conf_list) {
            int level = get_dir_level(conf);
            if (level < 0) {
                std::cerr << "Invalid path in config: " << conf << std::endl;
                return -1; 
            }
            if (level > MAX_DIR_LEVEL) {
                std::cerr << "Path exceeds maximum directory level (" << MAX_DIR_LEVEL << "): " << conf << std::endl;
                return -1; 
            }
        }
        host_id = config_json_obj["host_id"].get<std::string>();
        if (host_id.empty()) {
            std::cerr << "Host ID is empty, please check your config file." << std::endl;
            return -1; 
        }
        domain_name = config_json_obj["domain_name"].get<std::string>();
        if (domain_name.empty()) {
            std::cerr << "Domain name is empty, please check your config file." << std::endl;
            return -1; 
        }
        ragdoll_api = config_json_obj["ragdoll_api"].get<std::string>();
        skip_processes = config_json_obj["skip_processes_list"].get<std::vector<std::string>>();

        publish = config_json_obj.value("publish", false); 
        server = config_json_obj.value("server", "0.0.0.0");
        if (!is_valid_ip(server)) {
            std::cerr << "Invalid server IP address: " << server << std::endl;
            return -1; 
        }
        port = config_json_obj.value("port", 8080);
        std::cout << "Configuration loaded from " << configFile << std::endl;
        std::cout << "ragdoll_api: " << ragdoll_api <<  ";";
        std::cout << "skip_processes: ";
        for (const auto& process : skip_processes) {
            std::cout << process << " ";
        }
        std::cout <<  ";";
        std::cout << "conf_list: ";
        for (const auto& conf : conf_list) {
            std::cout << conf << " ";
        }
        std::cout <<  ";";
        std::cout << "host_id: " << host_id <<  ";";
        std::cout << "domain_name: " << domain_name <<  ";";
        std::cout << "publish: " << (publish ? "true" : "false") << std::endl;
        return 0;
    } catch (json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
    } catch (json::type_error& e) {
        std::cerr << "JSON type error: " << e.what() << std::endl;
    } catch (std::exception& e) {
        std::cerr << "General error: " << e.what() << std::endl;
    }
    return -1; 
}

int PostData::send(struct event e) 
{
    if(!is_valid_event(e)) {
        std::cerr << "Skip event detected, skipping." << std::endl;
        return 0; 
    }
    print_event(&e);

    std::string data = convert_to_string(e);
    if (data.empty()) {
        std::cerr << "Failed to convert event to JSON string." << std::endl;
        return 1; 
    }
    if(publish == false) {
        std::cout << "Publishing is disabled, not sending data." << std::endl;
        std::cout << "Data: " << data << std::endl;
        return 0; 
    }
    std::cout << "Sending data: " << data << std::endl;
    long http_code = 0;
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    std::string readBuffer; 
    std::string content_type = "Content-Type: application/json"; 
    curl = curl_easy_init(); 
    if (!curl) {
        std::cerr << "Failed to initialize CURL." << std::endl;
        return 1; 
    }
    headers = curl_slist_append(headers, content_type.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, ragdoll_api.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    //curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        std::cout << "HTTP POST successful, HTTP Status Code:" << http_code  << std::endl;
        //std::cout << "Response: " << readBuffer << std::endl;
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
}
void PostData::add_ptrace(json& j, const std::string cmd, int pid) 
{
    j["ptrace"].push_back({{"cmd", cmd}, {"pid", pid}});
}

void PostData::generate_proc_trace(unsigned int &pid, json &json_data) 
{
    unsigned int proc_id = pid;
    if (proc_id  <= 1) {
        return; 
    }
    struct pinfo_t *pinfo = (struct pinfo_t *)malloc(sizeof(struct pinfo_t));
    if (!pinfo) {
        std::cerr << "Failed to allocate memory for pinfo_t" << std::endl;
        return ; 
    }
    while (true)
    {
        if (proc_id == 0) {
            break; 
        }
        std::cout << "Generating proc trace for PID: " << proc_id << std::endl;
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
        add_ptrace(json_data, std::move(pinfo_cmd), proc_id);
        // get parent pid
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
    if (v.empty() || config.empty()) {
        return false; 
    }
    for (const auto& item : v) {
        if (item == config) {
            return true;
        }
    }
    return false;
}

bool PostData::is_valid_event(struct event &e) 
{
   std::string fullpath = "";
    if (e.pid == 0) {
        return false; 
    }
    if (std::find(skip_processes.begin(), skip_processes.end(), e.cmd) != skip_processes.end()) {
        return false; 
    }
    std::string cmd = e.cmd;
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
            if(!compare_config_file(conf_list, fullpath)) {
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
        std::cerr << "Failed to lookup pinfo for PID " << pid << ", ret:" << ret << std::endl;
        return -1; 
    }
    std::cout << "Found pinfo in map for PID " << pid << ": " 
              << pinfo->comm << ", args: " 
              << pinfo->arg1 << " " 
              << pinfo->arg2 << " "
              << pinfo->arg3 << " "
              << pinfo->arg4 << std::endl;
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

int  PostData::get_procinfo_by_pid_from_system(struct pinfo_t *pinfo ,unsigned int &pid)
{

    char proc_path[1024];
    //get ppid and comm from /proc/<pid>/stat

    snprintf(proc_path, sizeof(proc_path), "/proc/%u/stat", pid);
    std::ifstream stat_file(proc_path);
    if (!stat_file.is_open()) {
        std::cerr << "Failed to open stat file: " << proc_path << std::endl;
        return -1;
    }
    std::string line;
    std::getline(stat_file, line);
    stat_file.close();

    auto fields = split_stat_line(line);
    if (fields.size() < 5) {
        std::cerr << proc_path << "content invlad." << std::endl;
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
    //top level dir is /
    std::cout << "dir: dir1: " << event->dir1 << ", dir2: " << event->dir2
              << ", dir3: " << event->dir3 << ", dir4: " << event->dir4
              << ", filename: " << event->filename << std::endl;
    if (event->dir4[0]) {
        fullpath += std::string(event->dir4) + std::string(event->dir3) + "/" 
                    + std::string(event->dir2) + "/" + std::string(event->dir1) + "/" + std::string(event->filename);
        return fullpath;
    }
    if (event->dir3[0]) {
        fullpath += std::string(event->dir3) + std::string(event->dir2) + "/" + std::string(event->dir1)+ "/" + std::string(event->filename);
        return fullpath;
    }
    if (event->dir2[0]) {
        fullpath += std::string(event->dir2) + std::string(event->dir1)+ "/" + std::string(event->filename);
        return fullpath;
    }
    if (event->dir1[0]) {
        fullpath += std::string(event->dir1) + std::string(event->filename);
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
    if (j.contains("conf")) {
        std::string conf = j["conf"];
        std::string action = j["action"];
        if (action == "add") {
            conf_list.push_back(conf);
        } else if (action == "remove") {
            conf_list.erase(std::remove(conf_list.begin(), conf_list.end(), conf), conf_list.end());
        } else {
            std::cerr << "Unknown action: " << action << std::endl;
            return -1; 
        }
    }
    //write to file
    std::ofstream file(config_json);
    if (!file.is_open()) {
        std::cerr << "Could not open config file for writing: " << config_json << std::endl;
        return -1;
    }
    file << j.dump(4);
    file.close();
    std::cout << "Configuration updated successfully." << std::endl;
    return 0; 
}
void PostData::start_http_server() 
{
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
        j["conf_list"] = conf_list;
        res.set_content(j.dump(2), "application/json");
    });
    svr.listen(this->server.c_str(), this->port);
}
int PostData::get_dir_level(const std::string &path) 
{
    if (path.empty() || path[0] != '/') {
        return -1; 
    }
    std::string tmp_path = path;
    if(tmp_path.back() == '/'){
       tmp_path = tmp_path.substr(0, tmp_path.size() - 1);
    }
    return std::count(tmp_path.begin(), tmp_path.end(), '/'); 
}