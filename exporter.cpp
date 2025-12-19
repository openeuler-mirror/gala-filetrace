#include "exporter.hpp"


PrometheusExporter::PrometheusExporter(const std::string& address) 
{
    if(address.empty()) {
        throw std::runtime_error("Address for Prometheus Exporter cannot be empty.");
    }
    exposer = std::make_unique<prometheus::Exposer>(address);
    registry = std::make_shared<prometheus::Registry>();
    exposer->RegisterCollectable(registry);
    
    // start thread to check cache timeout
    std::thread(&PrometheusExporter::task_gauge_cache_timeout, this).detach();
    std::cout << "PrometheusExporter initialized at: " << address << std::endl;
}

prometheus::Counter& PrometheusExporter::add_counter(
        const std::string& name,
        const std::string& help,
        const std::map<std::string, std::string>& labels)
{
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
    std::string fullpath;
    //top level dir is /
    std::cout << "dir: dir1: " << event->dir1 << ", dir2: " << event->dir2
              << ", dir3: " << event->dir3 << ", dir4: " << event->dir4
              << ", filename: " << event->filename << std::endl;
    if (event->dir4[0] == '/') {
        fullpath += std::string(event->dir4) + std::string(event->dir3) + "/" 
                    + std::string(event->dir2) + "/" + std::string(event->dir1) + "/" + std::string(event->filename);
        std::cout << "The 4 level fullpath: " << fullpath << std::endl;
        return fullpath;
    }
    if (event->dir3[0] == '/') {
        fullpath += std::string(event->dir3) + std::string(event->dir2) + "/" + std::string(event->dir1)+ "/" + std::string(event->filename);
        std::cout << "The 3 level fullpath: " << fullpath << std::endl;
        return fullpath;
    }
    if (event->dir2[0] == '/') {
        fullpath += std::string(event->dir2) + std::string(event->dir1)+ "/" + std::string(event->filename);
        std::cout << "The 2 level fullpath: " << fullpath << std::endl;
        return fullpath;
    }
    if (event->dir1[0] == '/') {
        fullpath += std::string(event->dir1) + std::string(event->filename);
        std::cout << "The 1 level fullpath: " << fullpath << std::endl;
        return fullpath;
    }
    return fullpath;
}

void PrometheusExporter::set_metrics(struct event& e) 
{
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
        std::cout << "Incremented file_access_counter" << std::endl;
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
            std::cout << "Reusing existing gauge for PID: " << pid_gauge_key << std::endl;
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
    std::cout << "Updated PID gauge for PID " << e.pid << std::endl;
}

void PrometheusExporter::task_gauge_cache_timeout() {
    while (true) {
        //loop every 10 seconds
        std::this_thread::sleep_for(std::chrono::seconds(10));
        std::lock_guard<std::mutex> lock(gauge_cache_mutex);
        for (auto it = gauge_cache_timestamps.begin(); it != gauge_cache_timestamps.end(); ) {
            const std::string& key = it->first;
            std::cout << "Checking gauge cache key: " << key << std::endl;
            const std::string& timestamp_str = it->second;
            std::time_t timestamp = std::stol(timestamp_str);
            std::time_t now = std::time(nullptr);
            if (now - timestamp > 30) { // 30 seconds timeout
                auto gauge_it = gauge_cache.find(key);
                if (gauge_it != gauge_cache.end()) {
                    // set metric to 0 before removing from cache so external scrapers
                    // see a cleared value (prometheus-cpp does not support unregistering
                    // individual metrics easily).
                    try {
                        prometheus::Gauge* g = gauge_it->second;
                        if (g) {
                            g->Set(0.0);
                        }
                    } 
                    catch (...) 
                    {
                        std::cerr << "Error setting gauge to 0 for key: " << key << std::endl;
                    }
                    gauge_cache.erase(key);
                    std::cout << "Removed stale gauge from cache: " << key << std::endl;
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