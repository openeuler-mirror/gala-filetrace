#include  "post.hpp"
#include "logger.hpp"
#include <cstring>
#include <unistd.h>

namespace {

unsigned long long user_hz_value()
{
    static const unsigned long long hz = []() {
        long v = sysconf(_SC_CLK_TCK);
        return v > 0 ? static_cast<unsigned long long>(v) : 100ULL;
    }();
    return hz;
}

// task->start_boottime is in nanoseconds; /proc/<pid>/stat reports starttime
// in USER_HZ clock ticks. Convert without overflowing on long uptimes.
unsigned long long nsec_to_ticks(unsigned long long ns)
{
    const unsigned long long hz = user_hz_value();
    return (ns / 1000000000ULL) * hz +
           (ns % 1000000000ULL) * hz / 1000000000ULL;
}

unsigned long long ticks_to_nsec(unsigned long long ticks)
{
    const unsigned long long hz = user_hz_value();
    return (ticks / hz) * 1000000000ULL +
           (ticks % hz) * 1000000000ULL / hz;
}

} // namespace


// Replace invalid UTF-8 sequences with the Unicode replacement character (U+FFFD)
std::string PostData::sanitize_utf8(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    const unsigned char *data = reinterpret_cast<const unsigned char*>(s.data());
    size_t i = 0, n = s.size();
    while (i < n) {
        unsigned char c = data[i];
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
            ++i;
            continue;
        }
        // Derive the sequence length from the lead byte. This rejects the
        // reserved 5/6-byte leads (0xF8-0xFD), bare continuation bytes used
        // as leads (0x80-0xBF), and 0xFE/0xFF. 0xC0/0xC1 are excluded because
        // they can only start an overlong 2-byte encoding, and 0xF5-0xF7
        // because no Unicode scalar value needs four bytes beyond 0xF4.
        size_t len = 0;
        if (c >= 0xC2 && c <= 0xDF) {
            len = 2;
        } else if (c >= 0xE0 && c <= 0xEF) {
            len = 3;
        } else if (c >= 0xF0 && c <= 0xF4) {
            len = 4;
        }
        bool valid = len != 0 && i + len <= n;
        for (size_t k = 1; valid && k < len; ++k) {
            valid = (data[i + k] & 0xC0) == 0x80;
        }
        // Reject code points that are structurally well-formed but invalid
        // Unicode: overlong forms and UTF-16 surrogates. Without these
        // checks the result is still rejected by nlohmann::json::dump().
        if (valid && len == 3) {
            valid = !(c == 0xE0 && data[i + 1] < 0xA0) &&
                    !(c == 0xED && data[i + 1] >= 0xA0);
        } else if (valid && len == 4) {
            valid = !(c == 0xF0 && data[i + 1] < 0x90) &&
                    !(c == 0xF4 && data[i + 1] >= 0x90);
        }
        if (valid) {
            out.append(reinterpret_cast<const char*>(&data[i]), len);
            i += len;
        } else {
            // One invalid lead byte becomes one U+FFFD; any continuation
            // bytes after it are handled on the following iterations.
            out.append("\xEF\xBF\xBD");
            ++i;
        }
    }
    return out;
}

PostData::PostData(filetrace_bpf *skel, const std::string& configFile, bool verbose, const std::string& monitor_file_path)
    :  config_json(configFile),
        verbose(verbose),
        monitor_file_path(monitor_file_path),
        max_dir_level(4),
        publish(false),
        max_publish_queue_size(10000)
{
    std::cout << "Initializing PostData!" << std::endl;
    if(configFile.empty()) {
        throw std::runtime_error("Configuration file path is empty!");
    }
    if(std::ifstream(configFile).good() == false) {
        throw std::runtime_error("Configuration file does not exist or is not accessible: " + configFile);
    }
    int ret = load_config(config_json);
    if (ret != 0) {
        throw std::runtime_error("Configuration load failed");
    }
    // initialize logger from config (optional keys: log_level, log_file, log_size)
    try 
    {
        Logger::init(log_file, log_level, log_size);
        LOG_INFO("Logger initialized, level=" + log_level + ", file=" + log_file);
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
    // libcurl must be initialized before any thread is created, and
    // exporter_start() already spawns the gauge timeout thread.
    if (publish) {
        CURLcode init_res = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (init_res != CURLE_OK) {
            LOG_ERROR("curl_global_init() failed: " +
                      std::string(curl_easy_strerror(init_res)) +
                      ", event publishing is disabled");
            publish_worker_ok = false;
        } else {
            curl_global_inited = true;
        }
    }

    exporter_start();
    if(publish) {
        std::thread server_thread(&PostData::start_http_server, this);
        server_thread.detach(); // Detach the thread to run the HTTP server in the background

        if (publish_worker_ok.load()) {
            publish_thread = std::thread(&PostData::publish_worker_loop, this);
        }
    }
    LOG_INFO("PostData initialized successfully!");
}

// Default constructor for unit testing (does not touch eBPF or config files)
PostData::PostData()
    : config_json(std::string()),
      verbose(false),
      monitor_file_path(std::string()),
      max_dir_level(4),
      exporter_ptr(nullptr),
      publish(false),
      exec_map_fd(-1),
      max_publish_queue_size(10000),
      skel(nullptr),
      log_size(0)
{
    // Intentionally empty: test code can set fields directly.
}

PostData::~PostData()
{
    LOG_INFO("PostData destroyed");
    // Stop the publisher thread first so it cannot touch a half-destroyed
    // object; pending events are dropped on shutdown.
    if (publish_thread.joinable()) {
        // Change the state the worker waits on while holding the same mutex it
        // uses to evaluate the predicate: setting it outside the lock can lose
        // the wakeup (and then join() would block forever).
        {
            std::lock_guard<std::mutex> lk(publish_queue_mutex);
            stop_publish_thread = true;
        }
        publish_cv.notify_all();
        publish_thread.join();
        if (!publish_queue.empty()) {
            LOG_WARN("Dropping " + std::to_string(publish_queue.size()) +
                     " unpublished events on shutdown (" +
                     std::to_string(publish_dropped_count) +
                     " dropped while running)");
        }
    }
    if (curl_global_inited) {
        curl_global_cleanup();
        curl_global_inited = false;
    }
    this->skel = nullptr;
    this->exec_map_fd = -1;
    delete this->exporter_ptr;
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
    LOG_INFO("Loading configuration from " + configFile);
    std::ifstream file(configFile);
    if (!file.is_open()) {
        LOG_ERROR("Could not open config file: " + configFile);
        return -1;
    }
    try {
        file >> config_json_obj;
        file.close();
        conf_list = config_json_obj["config_list"].get<std::vector<std::string>>();
        if (conf_list.empty()) 
        {
            LOG_ERROR("Configuration list is empty, please check your config file.");
            return -1; 
        }
        //log level
        log_level = config_json_obj.value("log_level", std::string("info"));
        log_file = config_json_obj.value("log_file", std::string("/var/log/filetrace.log"));
        
        // Parse log_size (in MB, default 100 MB)
        int log_size_mb = config_json_obj.value("log_size", 100);
        log_size = (size_t)log_size_mb * 1024 * 1024;  // Convert MB to bytes
        
        LOG_INFO("Log level set to: " + log_level + ", log file: " + log_file + 
                 ", log size limit: " + std::to_string(log_size_mb) + " MB");
        max_dir_level = config_json_obj.value("max_dir_level", 4);
        if (max_dir_level <= 0) {
                LOG_WARN("max_dir_level must be positive, using default 4");
            max_dir_level = 4;
        }
        //check dir level
        for (const auto& conf : conf_list) {
            int level = get_dir_level(conf);
            if (level < 0) {
                LOG_ERROR("Invalid path in config: " + conf);
                return -1; 
            }
            if (level > max_dir_level) {
                LOG_ERROR("Path exceeds maximum directory level (" + std::to_string(max_dir_level) + "): " + conf);
                return -1; 
            }
        }
        host_id = config_json_obj["host_id"].get<std::string>();
        if (host_id.empty()) {
            LOG_ERROR("Host ID is empty, please check your config file.");
            return -1; 
        }
        domain_name = config_json_obj["domain_name"].get<std::string>();
        if (domain_name.empty()) {
            LOG_ERROR("Domain name is empty, please check your config file.");
            return -1; 
        }
        cluster_id = config_json_obj.value("cluster_id", std::string(""));
        ragdoll_api = config_json_obj["ragdoll_api"].get<std::string>();
        skip_processes = config_json_obj["skip_processes_list"].get<std::vector<std::string>>();

        publish = config_json_obj.value("publish", false); 
        cache_data = config_json_obj.value("cache_data", false);
        server = config_json_obj.value("server", "0.0.0.0");
        if (!is_valid_ip(server)) {
            LOG_ERROR("Invalid server IP address: " + server);
            return -1; 
        }
        port = config_json_obj.value("port", 8080);
        exporter_address = config_json_obj.value("exporter_address", "0.0.0.0:8080");
        cache_timeout_seconds = config_json_obj.value("cache_timeout_seconds", 30);
        if (cache_timeout_seconds <= 0) {
            LOG_WARN("cache_timeout_seconds must be positive, using default 30");
            cache_timeout_seconds = 30;
        }
        // max events to keep in memory for API access
        max_event_queue_size = config_json_obj.value("max_event_queue_size", 1000);
        if (max_event_queue_size <= 0) {
            LOG_WARN("max_event_queue_size must be positive, using default 1000");
            max_event_queue_size = 1000;
        }
        // bound for the publisher queue (oldest event is dropped on overflow).
        // Read it as a floating point value so a number above INT_MAX is
        // clamped instead of throwing json::out_of_range and failing startup.
        double publish_queue_limit = config_json_obj.value("max_publish_queue_size", 10000.0);
        if (!(publish_queue_limit >= 1.0)) {
            LOG_WARN("max_publish_queue_size must be positive, using default 10000");
            publish_queue_limit = 10000.0;
        }
        const double max_publish_queue_cap = 100000.0;
        if (publish_queue_limit > max_publish_queue_cap) {
            LOG_WARN("max_publish_queue_size exceeds the maximum, clamping to " +
                     std::to_string(static_cast<long long>(max_publish_queue_cap)));
            publish_queue_limit = max_publish_queue_cap;
        }
        max_publish_queue_size = static_cast<size_t>(publish_queue_limit);
        LOG_INFO("Configuration loaded from " + configFile);
        LOG_INFO("ragdoll_api: " + ragdoll_api);
        LOG_INFO("skip_processes: ");
        for (const auto& process : skip_processes) {
            LOG_INFO(process);
        }
        LOG_INFO("conf_list: ");
        for (const auto& conf : conf_list) {
            LOG_INFO(conf);
        }
        LOG_INFO("max_dir_level: " + std::to_string(max_dir_level));
        LOG_INFO("max_event_queue_size: " + std::to_string(max_event_queue_size));
        LOG_INFO("host_id: " + host_id);
        LOG_INFO("domain_name: " + domain_name);
        LOG_INFO("cluster_id: " + cluster_id);
        LOG_INFO("publish: " + std::string(publish ? "true" : "false"));
        return 0;
    } catch (json::parse_error& e) {
        LOG_ERROR("JSON parse error: " + std::string(e.what()));
    } catch (json::type_error& e) {
        LOG_ERROR("JSON type error: " + std::string(e.what()));
    } catch (std::exception& e) {
        LOG_ERROR("General error: " + std::string(e.what()));
    }
    return -1; 
}

int PostData::process_event(struct event e)
{
    if (!is_valid_event(e)) {
        return 0;
    }
    #ifdef GALA_DEBUG
    std::cout << "Command: " << e.cmd << ", PID: " << e.pid << ",filename: "
              << std::string(e.filename)
              << ", func: " << nr_map[e.flag] << std::endl;
    #endif
    if (verbose) {
        print_event(&e);
        return 0;
    }

    int result = send(e);
    // Cache accepted events even when publishing fails or is disabled.
    cache_event(&e);
    return result;
}

int PostData::send(struct event e)
{
    LOG_DEBUG("Send event to Aops.");
    // Renames report the monitored side in the JSON "file" field; pass the
    // same path to the exporter so the metric label does not diverge.
    std::string reported_file;
    if (e.flag == SYS_rename || e.flag == SYS_renameat || e.flag == SYS_renameat2) {
        reported_file = get_reported_path(&e);
    }
    exporter_ptr->set_metrics(e, reported_file);
    print_event(&e);
    std::string data = convert_to_string(e);
    if (data.empty()) {
        LOG_ERROR("Failed to convert event to JSON string.");
        return 1;
    }
    if(publish == false) {
        LOG_INFO("Publishing is disabled, skip it.");
        LOG_INFO("Data: " + data);
        return 0;
    }
    if (!publish_worker_ok.load()) {
        // The publisher could not start (curl init failed); enqueueing would
        // only fill the queue and log a drop warning for every event.
        LOG_DEBUG("Publisher is unavailable, skipping event.");
        return 0;
    }
    // Hand the payload to the publisher thread instead of POSTing here: this
    // function runs in the ring buffer callback, and a slow ragdoll endpoint
    // would stall event consumption until the ring buffer overflows.
    bool dropped = false;
    {
        std::lock_guard<std::mutex> lk(publish_queue_mutex);
        if (!publish_queue.empty() && publish_queue.size() >= max_publish_queue_size) {
            publish_queue.pop();
            dropped = true;
        }
        publish_queue.push(std::move(data));
    }
    if (dropped) {
        // Logging is done outside the queue lock and rate limited: this path
        // is reached once per event while the consumer is ahead of ragdoll.
        ++publish_dropped_count;
        auto now = std::chrono::steady_clock::now();
        if (now - last_publish_drop_log >= std::chrono::seconds(5)) {
            last_publish_drop_log = now;
            LOG_WARN("Publish queue full, dropped oldest event (total dropped: " +
                     std::to_string(publish_dropped_count) + ")");
        }
    }
    publish_cv.notify_one();
    return 0;
}

// Single dedicated curl connection so publishing does not pay the handle
// setup (and TLS handshake, once ragdoll moves to https) per event.
void PostData::publish_worker_loop()
{
    CURL *curl = curl_easy_init();
    if (!curl) {
        LOG_ERROR("Failed to initialize CURL, event publishing is disabled.");
        publish_worker_ok = false;
        return;
    }
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        LOG_ERROR("Failed to allocate curl headers, event publishing is disabled.");
        curl_easy_cleanup(curl);
        publish_worker_ok = false;
        return;
    }
    curl_easy_setopt(curl, CURLOPT_URL, ragdoll_api.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    // Never block the consumer indefinitely: bound both the connection and
    // the total transfer, and keep libcurl from using signals in a thread.
    // The total timeout is also the upper bound on how long shutdown can wait
    // for a request that was already in flight, so keep it short.
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    auto post = [&](const std::string &data) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(data.size()));
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            LOG_ERROR("curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
            return;
        }
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code < 200 || http_code >= 300) {
            LOG_ERROR("Publish rejected with HTTP status: " + std::to_string(http_code));
        } else {
            LOG_INFO("Published event, HTTP status: " + std::to_string(http_code));
        }
    };

    LOG_INFO("Publishing events to " + ragdoll_api);
    while (true) {
        std::string data;
        bool stopping = false;
        {
            std::unique_lock<std::mutex> lk(publish_queue_mutex);
            publish_cv.wait(lk, [this] {
                return stop_publish_thread.load() || !publish_queue.empty();
            });
            if (stop_publish_thread.load()) {
                stopping = true;
            } else {
                data = std::move(publish_queue.front());
                publish_queue.pop();
            }
        }

        if (stopping) {
            // Bounded flush: give a reachable endpoint a chance to receive
            // what is still queued, but do not let an unreachable one delay
            // shutdown indefinitely. The shorter timeout bounds each attempt
            // and the deadline bounds the whole drain.
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 500L);
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(2000);
            while (std::chrono::steady_clock::now() < deadline) {
                std::string pending;
                {
                    std::lock_guard<std::mutex> flush_lk(publish_queue_mutex);
                    if (publish_queue.empty()) {
                        break;
                    }
                    pending = std::move(publish_queue.front());
                    publish_queue.pop();
                }
                post(pending);
            }
            break;
        }

        post(data);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
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
    LOG_INFO("Event Details: PID: " + std::to_string(event->pid) + 
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
    LOG_DEBUG("Caching event for API access.");
    if(!cache_data) {
        LOG_INFO("API server is disabled, not caching event.");
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
            if (event_queue.size() >= static_cast<size_t>(max_event_queue_size)) {
                event_queue.pop(); 
            }
            event_queue.push(std::move(j)); 
        }
    } catch (const std::exception &ex) {
        LOG_ERROR(std::string("Failed to build event queue JSON: ") + ex.what());
    }
}
void PostData::add_ptrace(json& j, const std::string cmd, int pid) 
{
    j["ptrace"].push_back({{"cmd", cmd}, {"pid", pid}});
}

void PostData::generate_proc_trace(unsigned int &pid, json &json_data,
                                   unsigned long long start_time)
{
    LOG_DEBUG("Generating process trace for PID: " + std::to_string(pid));
    unsigned int proc_id = pid;
    // Generation expected for the next lookup. start_time == 0 means the
    // event did not carry one (older caller/test or a failed probe read), so
    // skip generation validation for the whole chain instead of risking a
    // half-validated tree.
    unsigned long long expected_start = start_time;
    bool check_generation = start_time != 0;
    if (proc_id  <= 1) {
        LOG_ERROR("Invalid PID: " + std::to_string(pid));
        return; 
    }
    struct pinfo_t *pinfo = (struct pinfo_t *)malloc(sizeof(struct pinfo_t));
    if (!pinfo) {
        LOG_ERROR("Failed to allocate memory for pinfo_t");
        return; 
    }
    // A recycled PID in exec_map can form a cycle (a -> b -> a); cap the walk
    // so a stale entry cannot loop forever or build an unbounded JSON array.
    const unsigned int max_trace_depth = 32;
    for (unsigned int depth = 0; depth < max_trace_depth; depth++)
    {
        if (proc_id == 0) {
            break;
        }
        LOG_INFO("Generating proc trace for PID: " + std::to_string(proc_id));
        // A map miss leaves the previous iteration's args in pinfo; clear it
        // so a /proc fallback never mixes two processes.
        memset(pinfo, 0, sizeof(struct pinfo_t));
        if (check_generation && expected_start == 0) {
            check_generation = false;
        }
        int ret = get_procinfo_by_pid_from_map(pinfo, proc_id);
        if (ret == 0 && check_generation) {
            if (pinfo->start_time == 0) {
                // 0 means the generation is unknown (entry written without
                // start_boottime). Accept it and stop validating the rest of
                // the chain instead of dropping the whole tree.
                check_generation = false;
            } else if (nsec_to_ticks(pinfo->start_time) !=
                       nsec_to_ticks(expected_start)) {
                LOG_DEBUG("exec_map entry for PID " + std::to_string(proc_id) +
                          " belongs to a different process (start_time mismatch)");
                ret = -1;
            }
        }
        if (ret) {
            ret = get_procinfo_by_pid_from_system(
                pinfo, proc_id, check_generation ? expected_start : 0);
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
        if (check_generation) {
            expected_start = pinfo->parent_start_time;
            if (expected_start == 0) {
                check_generation = false;
            }
        }
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
    generate_proc_trace(e.pid, json_data, e.start_time);

    json_data["host_id"] = host_id;
    json_data["domain_name"] = domain_name;
    json_data["cluster_id"] = cluster_id;
    json_data["flag"] = e.flag;
    json_data["syscall"] = nr_map[e.flag];
    // SYS_write, SYS_unlinkat, SYS_copy_file_range and the rename family are
    // matched against the rebuilt full path (see is_valid_event), so report
    // the same string that was matched - a relative unlinkat pathname would
    // otherwise be published as e.g. "hosts" while it was matched as
    // "/etc/hosts". For renames also expose the source path: a "mv away" event
    // reports the removed file under "file" while still recording where it
    // came from.
    // Field names below come from the kernel (BPF bpf_probe_read_str on dentry
    // names and task->comm). Linux filenames and commands may contain arbitrary
    // non-NUL bytes, so every such string must be sanitized before it reaches
    // json::dump() - otherwise a single invalid sequence throws type_error.316
    // out of the ring-buffer callback and terminates the daemon. sanitize_utf8()
    // is idempotent on already-valid text, so re-sanitizing is harmless.
    if (e.flag == SYS_write || e.flag == SYS_unlinkat ||
        e.flag == SYS_copy_file_range) {
        json_data["file"] = sanitize_utf8(get_full_path(&e));
    } else if (e.flag == SYS_rename || e.flag == SYS_renameat || e.flag == SYS_renameat2) {
        std::string oldpath;
        json_data["file"] = sanitize_utf8(get_reported_path(&e, &oldpath));
        json_data["old_file"] = sanitize_utf8(oldpath);
    } else {
        json_data["file"] = sanitize_utf8(std::string(e.filename));
    }
    json_data["user"] = sanitize_utf8(username);
    json_data["group"] = sanitize_utf8(groupname);
    json_data["pid"] = e.pid;
    json_data["inode"] = e.i_ino;
    json_data["cmd"] = sanitize_utf8(std::string(e.cmd));
    json_data["loginip"] = sanitize_utf8(get_loginip_by_username(username));
    // Final safety net: configuration-derived strings (host_id, domain_name,
    // cluster_id) are outside this function's control. Never let a serialization
    // exception escape into the ring-buffer callback.
    try {
        return json_data.dump();
    } catch (const json::exception &ex) {
        LOG_ERROR(std::string("Failed to serialize event to JSON: ") + ex.what());
        return std::string();
    }
}
bool PostData::compare_config_file(const vector<string> &v, const std::string &config) 
{
    // An empty path can never be a monitored file. Check this before the
    // verbose monitor_file_path shortcut below: with no -f target that
    // shortcut would otherwise match an empty path against the empty
    // monitor_file_path and report a rename with an empty source as valid.
    if (config.empty()) {
        return false;
    }

    if (verbose) {
        LOG_INFO("Comparing config file: " + config + " with " + monitor_file_path);
        if (monitor_file_path == config) {
            return true;
        } 
    }

    std::lock_guard<std::mutex> lk(config_mutex);
    if (v.empty()) {
        return false; 
    }

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
        // compare skip_cmd and cmd_tmp before 15 characters

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
            // Non-rename events carry the basename in filename; dotfiles and
            // empty names are still filtered here.
            if (!is_valid_filename(e.filename)) {
                return false;
            }
            fullpath = get_full_path(&e);
            if(!compare_config_file(conf_list, fullpath)) {
                return false; 
            }
            break;
        case SYS_rename:
        case SYS_renameat:
        case SYS_renameat2: {
            // Either side of the rename may be the monitored file: moving a
            // monitored file away must be reported too, not only overwrites.
            // Do NOT gate this on is_valid_filename(e.filename): a destina-
            // tion such as "." (``mv /etc/hosts .``) or a dotfile is a valid
            // rename target and the source may be the monitored path.
            std::string oldpath = get_old_full_path(&e);
            std::string newpath = get_full_path(&e);
            if (!compare_config_file(conf_list, newpath) &&
                !compare_config_file(conf_list, oldpath)) {
                return false;
            }
            break;
        }
        // copy_file_range and write only carry the basename in filename and
        // rebuild the path from dir1..dir4, so they must be matched against
        // the full path - a basename never equals an entry of conf_list, which
        // holds absolute paths.
        case SYS_copy_file_range:
        case SYS_write:
            if (!is_valid_filename(e.filename)) {
                return false;
            }
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
        // Not an error: any process that exec'd before filetrace started is
        // absent from the map; fall back to /proc below.
        LOG_DEBUG("No pinfo in map for PID " + std::to_string(pid) + ", ret:" + std::to_string(ret));
        return -1;
    }
    LOG_INFO("Found pinfo in map for PID " + std::to_string(pid) + ": " 
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
    // /proc/<pid>/stat is "pid (comm) state ppid ...". comm is wrapped in
    // parentheses and may itself contain spaces and parentheses, so locate the
    // last ')' of the line. An empty or malformed line must yield an empty
    // result: the process can exit between the open() and the read(), and an
    // exception here would escape the ring buffer callback.
    size_t comm_end = line.rfind(')');
    if (comm_end == std::string::npos) {
        return result;
    }
    size_t comm_start = line.find('(');
    if (comm_start == std::string::npos || comm_start > comm_end) {
        return result;
    }

    // first item is pid
    size_t end = line.find(' ');
    if (end == std::string::npos || end >= comm_start) {
        return result;
    }
    result.push_back(line.substr(0, end));

    // second item is comm, "(...)" inclusive
    result.push_back(line.substr(comm_start, comm_end - comm_start + 1));

    // other fields follow the closing parenthesis
    std::istringstream iss(line.substr(comm_end + 1));
    std::string token;
    while (iss >> token) {
        result.push_back(token);
    }

    return result;
}

int PostData::get_procinfo_by_pid_from_system(struct pinfo_t *pinfo ,unsigned int &pid,
                                               unsigned long long expected_start_time)
{
    char proc_path[1024];
    //get ppid and comm from /proc/<pid>/stat
    if(pid == 0 || pid > PID_MAX_LIMIT) {
        LOG_ERROR("Invalid PID: " + std::to_string(pid));
        return -1; 
    }
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/stat", pid);
    std::ifstream stat_file(proc_path);

    if (!stat_file.is_open()) {
        LOG_ERROR("Failed to open stat file: " + std::string(proc_path));
        return -1;
    }
    std::string line;
    // The process can exit between open() and read(): an empty or truncated
    // line must fail this lookup instead of throwing.
    if (!std::getline(stat_file, line)) {
        LOG_DEBUG("Failed to read stat file: " + std::string(proc_path));
        return -1;
    }
    stat_file.close();

    auto fields = split_stat_line(line);
    if (fields.size() < 5) {
        LOG_ERROR(std::string(proc_path) + " content invalid.");
        return -1;
    }
    // Field 22 (index 21, after pid/comm) is starttime in clock ticks since
    // boot. It identifies this process incarnation and must match the
    // generation carried by the event before we trust /proc.
    unsigned long long proc_start = 0;
    if (expected_start_time != 0) {
        if (fields.size() <= 21) {
            LOG_ERROR(std::string(proc_path) + " has no starttime field.");
            return -1;
        }
        try {
            proc_start = std::stoull(fields[21]);
        } catch (const std::exception &ex) {
            LOG_ERROR("Failed to parse starttime from " + std::string(proc_path) +
                      ": " + ex.what());
            return -1;
        }
        // Compare at USER_HZ resolution: the event carries nanoseconds
        // (start_boottime), /proc carries ticks, and the kernel truncates to
        // ticks as well. This also tolerates a /proc-derived parent value.
        if (proc_start != nsec_to_ticks(expected_start_time)) {
            LOG_DEBUG(std::string(proc_path) +
                      " belongs to a different process (starttime mismatch).");
            return -1;
        }
    }
    // pid, comm, ppid
    try {
        pinfo->pid = std::stoul(fields[3]);
    } catch (const std::exception &ex) {
        LOG_ERROR("Failed to parse ppid from " + std::string(proc_path) + ": " + ex.what());
        return -1;
    }
    // Fill the parent's generation as well, so the next level can still be
    // validated when the parent is absent from exec_map (e.g. it started
    // before the tracer). If /proc/<ppid> is already gone, leave 0 and the
    // next lookup will skip the check.
    pinfo->parent_start_time = 0;
    // Only needed to validate the next level; skip the extra /proc read when
    // generation checking is already disabled (expected_start_time == 0).
    if (expected_start_time != 0 && pinfo->pid > 1) {
        char parent_path[1024];
        snprintf(parent_path, sizeof(parent_path), "/proc/%u/stat", pinfo->pid);
        std::ifstream parent_file(parent_path);
        std::string parent_line;
        if (parent_file.is_open() && std::getline(parent_file, parent_line)) {
            auto parent_fields = split_stat_line(parent_line);
            if (parent_fields.size() > 21) {
                try {
                    pinfo->parent_start_time =
                        ticks_to_nsec(std::stoull(parent_fields[21]));
                } catch (const std::exception &) {
                    // keep 0: skip generation validation for this level
                }
            }
        }
    }
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
    const char *parts[] = {event->dir4, event->dir3, event->dir2, event->dir1, event->filename};
    for (const char *part : parts) {
        if (part[0] == '\0' || (part[0] == '/' && part[1] == '\0')) {
            continue;
        }
        if (!fullpath.empty()) {
            fullpath.push_back('/');
        }
        fullpath += part;
    }

    if (!fullpath.empty() && fullpath.front() != '/') {
        fullpath.insert(fullpath.begin(), '/');
    }

    LOG_INFO("Constructed full path: " + fullpath);
    return fullpath;
}

// dir:/odir4/odir3/odir2/odir1/oldfilename — the old-path counterpart of
// get_full_path(), used to match the source side of a rename.
std::string PostData::get_old_full_path(const struct event *event)
{
    std::string fullpath;
    const char *parts[] = {event->odir4, event->odir3, event->odir2, event->odir1, event->oldfilename};
    for (const char *part : parts) {
        if (part[0] == '\0' || (part[0] == '/' && part[1] == '\0')) {
            continue;
        }
        if (!fullpath.empty()) {
            fullpath.push_back('/');
        }
        fullpath += part;
    }

    if (!fullpath.empty() && fullpath.front() != '/') {
        fullpath.insert(fullpath.begin(), '/');
    }

    LOG_INFO("Constructed old full path: " + fullpath);
    return fullpath;
}

// Path reported for an event. For renames this is the monitored side (the
// destination when it is monitored, otherwise the source), matching the JSON
// "file" field; for basename-only events it is the rebuilt path.
std::string PostData::get_reported_path(const struct event *event,
                                        std::string *old_full_path)
{
    switch (event->flag) {
        case SYS_rename:
        case SYS_renameat:
        case SYS_renameat2: {
            std::string newpath = get_full_path(event);
            std::string oldpath = get_old_full_path(event);
            if (old_full_path != nullptr) {
                *old_full_path = oldpath;
            }
            return compare_config_file(conf_list, newpath) ? newpath : oldpath;
        }
        case SYS_write:
        case SYS_unlinkat:
        case SYS_copy_file_range:
            return get_full_path(event);
        default:
            return event->filename;
    }
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
    LOG_INFO("Updating configuration with JSON: " + j.dump());
    std::lock_guard<std::mutex> lk(config_mutex);
    if (!j.is_object() || !j.contains("conf") || !j["conf"].is_string() ||
        !j.contains("action") || !j["action"].is_string()) {
        LOG_ERROR("JSON must contain string fields 'conf' and 'action'.");
        return -1;
    }

    const std::string conf = j["conf"].get<std::string>();
    const std::string action = j["action"].get<std::string>();
    if (action == "add") {
        conf_list.push_back(conf);
    } else if (action == "remove") {
        conf_list.erase(std::remove(conf_list.begin(), conf_list.end(), conf), conf_list.end());
    } else {
        LOG_ERROR("Unknown action: " + action);
        return -1;
    }
    // Keep the parsed config object in sync and persist the WHOLE object.
    config_json_obj["config_list"] = conf_list;
    const std::string tmp_path = config_json + ".tmp";
    {
        std::ofstream file(tmp_path, std::ios::trunc);
        if (!file.is_open()) {
            LOG_ERROR("Could not open config file for writing: " + tmp_path);
            return -1;
        }
        file << config_json_obj.dump(4) << "\n";
        file.close();
    }
    if (std::rename(tmp_path.c_str(), config_json.c_str()) != 0) {
        LOG_ERROR("Failed to rename " + tmp_path + " to " + config_json);
        return -1;
    }
    LOG_INFO("Configuration updated successfully.");
    return 0;
}

void PostData::handle_update_config_request(const std::string &body, httplib::Response &res)
{
    try {
        const json j = json::parse(body);
        if (!j.is_object() || !j.contains("conf") || !j["conf"].is_string() ||
            !j.contains("action") || !j["action"].is_string()) {
            res.status = 400;
            res.set_content("JSON must contain string fields 'conf' and 'action'", "text/plain");
            return;
        }

        const std::string action = j["action"].get<std::string>();
        if (action != "add" && action != "remove") {
            res.status = 400;
            res.set_content("'action' must be 'add' or 'remove'", "text/plain");
            return;
        }

        if (update_config(j) != 0) {
            res.status = 500;
            res.set_content("Failed to update configuration", "text/plain");
            return;
        }
        res.status = 200;
        res.set_content("Configuration updated successfully", "text/plain");
    } catch (const json::exception &e) {
        LOG_ERROR("Invalid configuration update JSON: " + std::string(e.what()));
        res.status = 400;
        res.set_content("Invalid JSON request", "text/plain");
    }
}

void PostData::start_http_server()
{
    LOG_INFO("Starting HTTP Server.");
    httplib::Server svr;
    svr.Post("/filetrace", [this](const httplib::Request& req, httplib::Response& res) {
        //body {"conf": "value", "action": "add|remove"}
        handle_update_config_request(req.body, res);
    });
    svr.Get("/filetrace", [this](const httplib::Request& req, httplib::Response& res) {
        json j;
        j["status"] = "ok";
        std::lock_guard<std::mutex> lk(config_mutex);
        j["conf_list"] = conf_list;
        res.set_content(j.dump(2), "application/json");
    });
    // New endpoint: return one events from event queue
    if(cache_data) {
        LOG_INFO("API monitor file status is enabled, caching events for API access.");
        svr.Get("/monitor_file_status", [this](const httplib::Request& req, httplib::Response& res) {
            int count = 10;
            auto it = req.params.find("count");
            if (it != req.params.end() && !it->second.empty()) {
                try {
                    count = std::stoi(it->second);
                } catch (const std::exception& e) {
                    LOG_ERROR("Invalid count parameter for /monitor_file_status: " + it->second + ", error: " + e.what());
                    count = 10;
                }
                if (count <= 0 || count > this->max_event_queue_size) {
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
    LOG_INFO("Starting HTTP server at " + server + ":" + std::to_string(port));
    svr.listen(this->server.c_str(), this->port);
}
int PostData::get_dir_level(const std::string &path) 
{
    LOG_INFO("Getting dir level number for path: " + path);
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
    LOG_INFO("Starting Prometheus Exporter at " + exporter_address);
    if(exporter_address.empty()) {
        throw std::runtime_error("Exporter address is empty!");
    }
    try {
        exporter_ptr = new PrometheusExporter(exporter_address, cache_timeout_seconds);
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to initialize Prometheus Exporter: " + std::string(e.what()));
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
