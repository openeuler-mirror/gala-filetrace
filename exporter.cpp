#include "exporter.hpp"

PrometheusExporter::PrometheusExporter(const std::string& address) 
{
    if(address.empty()) {
        throw std::runtime_error("Address for Prometheus Exporter cannot be empty.");
    }
    exposer_ = std::make_unique<prometheus::Exposer>(address);
    registry_ = std::make_shared<prometheus::Registry>();
    exposer_->RegisterCollectable(registry_);
}

prometheus::Counter& PrometheusExporter::add_counter(
        const std::string& name,
        const std::string& help,
        const std::map<std::string, std::string>& labels)
{
    auto& family = prometheus::BuildCounter()
                       .Name(name)
                       .Help(help)
                       .Register(*registry_);

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
                       .Register(*registry_);
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
                       .Register(*registry_);
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
    
    if (gauge_cache_.find(pid_gauge_key) != gauge_cache_.end()) {
        pid_gauge = gauge_cache_[pid_gauge_key];
    } else {
        pid_gauge = &add_gauge(
            "filetrace_info_record",
            "filetrace info",
            detailed_labels
        );
        gauge_cache_[pid_gauge_key] = pid_gauge;
    }
    
    pid_gauge->Set(static_cast<double>(e.pid));
    std::cout << "Updated PID gauge for PID " << e.pid << std::endl;

}