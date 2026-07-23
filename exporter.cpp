#include "exporter.hpp"


PrometheusExporter::PrometheusExporter(const std::string& address, int cache_timeout_seconds) 
    : cache_timeout_seconds(cache_timeout_seconds)
{
    Logger::info("Initializing PrometheusExporter with address: " + address);
    if(address.empty()) {
        throw std::runtime_error("Address for Prometheus Exporter cannot be empty.");
    }
    exposer = std::make_unique<prometheus::Exposer>(address);
    registry = std::make_shared<prometheus::Registry>();
    exposer->RegisterCollectable(registry);
    
    // start thread to check cache timeout
    std::thread(&PrometheusExporter::task_gauge_cache_timeout, this).detach();
    Logger::info("PrometheusExporter initialized at: " + address);
}

prometheus::Counter& PrometheusExporter::add_counter(
        const std::string& name,
        const std::string& help,
        const std::map<std::string, std::string>& labels)
{
    Logger::info("Adding counter: " + name + " with help: " + help);
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
    Logger::info("Adding gauge: " + name + " with help: " + help);
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
    Logger::info("Adding histogram: " + name + " with help: " + help);
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
    Logger::info("Constructing full path for event with filename: " + std::string(event->filename));
    std::string fullpath;
    //top level dir is /
    Logger::info("dir: dir1: " + std::string(event->dir1) + ", dir2: " + std::string(event->dir2)
              + ", dir3: " + std::string(event->dir3) + ", dir4: " + std::string(event->dir4)
              + ", filename: " + std::string(event->filename));
    if (event->dir4[0] == '/') {
        fullpath += std::string(event->dir4) + std::string(event->dir3) + "/" 
                    + std::string(event->dir2) + "/" + std::string(event->dir1) + "/" + std::string(event->filename);
        Logger::info("The 4 level full path: " + fullpath);
        return fullpath;
    }
    if (event->dir3[0] == '/') {
        fullpath += std::string(event->dir3) + std::string(event->dir2) + "/" + std::string(event->dir1)+ "/" + std::string(event->filename);
        Logger::info("The 3 level full path: " + fullpath);
        return fullpath;
    }
    if (event->dir2[0] == '/') {
        fullpath += std::string(event->dir2) + std::string(event->dir1)+ "/" + std::string(event->filename);
        Logger::info("The 2 level full path: " + fullpath);
        return fullpath;
    }
    if (event->dir1[0] == '/') {
        fullpath += std::string(event->dir1) + std::string(event->filename);
        Logger::info("The 1 level full path: " + fullpath);
        return fullpath;
    }
    return fullpath;
}

void PrometheusExporter::set_metrics(struct event& e) 
{
    Logger::info("Setting metrics for event with filename: " + std::string(e.filename) + " and operation: " + std::string(nr_map[e.flag]));
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
        Logger::info("Incremented file_access_counter");
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
            Logger::info("Reusing existing gauge for PID: " + pid_gauge_key);
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
    Logger::info("Updated PID gauge for PID " + std::to_string(e.pid));
}

void PrometheusExporter::task_gauge_cache_timeout() {
    Logger::info("Starting gauge cache timeout task.");
    while (true) {
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
                        Logger::error("Error setting gauge to 0 for key: " + key);
                    }
                    gauge_cache.erase(key);
                    Logger::info("Removed stale gauge from cache: " + key);
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
