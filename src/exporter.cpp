#include "exporter.hpp"


PrometheusExporter::PrometheusExporter(const std::string& address, int cache_timeout_seconds) 
    : cache_timeout_seconds(cache_timeout_seconds)
{
    LOG_INFO("Initializing PrometheusExporter with address: " + address);
    if(address.empty()) {
        throw std::runtime_error("Address for Prometheus Exporter cannot be empty.");
    }
    exposer = std::make_unique<prometheus::Exposer>(address);
    registry = std::make_shared<prometheus::Registry>();
    exposer->RegisterCollectable(registry);
    
    // start thread to check cache timeout
    LOG_INFO("PrometheusExporter initialized at: " + address);
    this->cache_timeout_thread_ = std::thread(&PrometheusExporter::task_gauge_cache_timeout, this);
}

PrometheusExporter::~PrometheusExporter() {
    LOG_INFO("Destroying PrometheusExporter.");
    stop_cache_timeout_thread();
    LOG_INFO("PrometheusExporter destroyed.");
}

void PrometheusExporter::stop_cache_timeout_thread() {
    LOG_INFO("Stopping cache timeout thread.");
    stop_thread_.store(true, std::memory_order_relaxed);
    if (cache_timeout_thread_.joinable()) {
        cache_timeout_thread_.join();
    }
    LOG_INFO("Cache timeout thread stopped.");
}

prometheus::Counter& PrometheusExporter::add_counter(
        const std::string& name,
        const std::string& help,
        const std::map<std::string, std::string>& labels)
{
    LOG_INFO("Adding counter: " + name + " with help: " + help);
    auto& family = prometheus::BuildCounter()
                       .Name(name)
                       .Help(help)
                       .Register(*registry);

    return family.Add(labels);
}

void PrometheusExporter::inc_counter(prometheus::Counter& counter, double v) {
    counter.Increment(v);
}

prometheus::Gauge& PrometheusExporter::add_gauge(
        const std::string& name,
        const std::string& help,
        const std::map<std::string, std::string>& labels)
{
    LOG_INFO("Adding gauge: " + name + " with help: " + help);
    auto& family = prometheus::BuildGauge()
                       .Name(name)
                       .Help(help)
                       .Register(*registry);
    return family.Add(labels);
}

prometheus::Histogram& PrometheusExporter::add_histogram(
        const std::string& name,
        const std::string& help,
        const prometheus::Histogram::BucketBoundaries& buckets,
        const std::map<std::string, std::string>& labels)
{
    LOG_INFO("Adding histogram: " + name + " with help: " + help);
    auto& family = prometheus::BuildHistogram()
                       .Name(name)
                       .Help(help)
                       //.Buckets(buckets)
                       .Register(*registry);
    //return family.Add(labels);
    return family.Add(labels, buckets);
}
// dir:/dir4/dir3/dir2/dir1/filename
std::string PrometheusExporter::get_full_path(const struct event *event) 
{
    LOG_INFO("Constructing full path for event with filename: " + std::string(event->filename));

    const char *parts[] = {event->dir4, event->dir3, event->dir2, event->dir1, event->filename};
    std::string fullpath;
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

void PrometheusExporter::set_metrics(struct event& e) 
{
    LOG_INFO("Setting metrics for event with filename: " + std::string(e.filename) + " and operation: " + std::string(nr_map[e.flag]));
    std::string filename = std::string(e.filename);
    if(e.flag == SYS_write)
    {
        filename = get_full_path(&e);
    } else {
        filename = e.filename;
    }
    std::string operation = std::string(nr_map[e.flag]);
    
    std::map<std::string, std::string> base_labels = {
        {"operation", operation},
        {"cmd", e.cmd},
    };
    
    if (file_access_counter != nullptr) {
        file_access_counter->Increment();
        LOG_INFO("Incremented file_access_counter");
    }
    
    std::map<std::string, std::string> detailed_labels = base_labels;
    detailed_labels.insert({"pid", std::to_string(e.pid)});
    detailed_labels.insert({"ppid", std::to_string(e.ppid)});
    detailed_labels.insert({"uid", std::to_string(e.uid)});
    detailed_labels.insert({"gid", std::to_string(e.gid)});
    detailed_labels.insert({"inode", std::to_string(e.i_ino)});
    detailed_labels.insert({"file", filename});
    detailed_labels.insert({"cmd", e.cmd});
    std::string time_now = std::to_string(std::time(nullptr));
    detailed_labels.insert({"ts", time_now});

    std::string pid_gauge_key = "filetrace_info_record_" + std::to_string(e.pid);
    prometheus::Gauge* pid_gauge = nullptr;
    // Protect cache access with mutex to avoid races with the cleanup thread
    {
        std::lock_guard<std::mutex> lock(gauge_cache_mutex);
        auto it = gauge_cache.find(pid_gauge_key);
        if (it != gauge_cache.end()) {
            LOG_INFO("Reusing existing gauge for PID: " + pid_gauge_key);
            pid_gauge = it->second;
        } else {
            pid_gauge = &add_gauge(
                "filetrace_info_record",
                "filetrace info",
                detailed_labels
            );
            gauge_cache[pid_gauge_key] = pid_gauge;
        }

        // Update the gauge and timestamp while holding the lock to ensure visibility
        if (pid_gauge) {
            pid_gauge->Set(static_cast<double>(e.pid));
        }
        gauge_cache_timestamps[pid_gauge_key] = time_now;
    }
    LOG_INFO("Updated PID gauge for PID " + std::to_string(e.pid));
}

void PrometheusExporter::task_gauge_cache_timeout() {
    LOG_INFO("Starting gauge cache timeout task.");
    while (!stop_thread_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::lock_guard<std::mutex> lock(gauge_cache_mutex);
        for (auto it = gauge_cache_timestamps.begin(); it != gauge_cache_timestamps.end(); ) {
            const std::string& key = it->first;
            std::cout << "Checking gauge cache key: " << key << std::endl;
            const std::string& timestamp_str = it->second;
            std::time_t timestamp = std::stol(timestamp_str);
            std::time_t now = std::time(nullptr);
            if (now - timestamp > cache_timeout_seconds) { 
                auto gauge_it = gauge_cache.find(key);
                if (gauge_it != gauge_cache.end()) {
                    try {
                        prometheus::Gauge* g = gauge_it->second;
                        if (g) {
                            g->Set(0.0);
                        }
                    } 
                    catch (...) 
                    {
                        LOG_ERROR("Error setting gauge to 0 for key: " + key);
                    }
                    gauge_cache.erase(key);
                    LOG_INFO("Removed stale gauge from cache: " + key);
                }
                it = gauge_cache_timestamps.erase(it);
            }
            else 
            {
                ++it;
            }
        }
    }
}
