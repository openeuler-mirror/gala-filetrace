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


void PrometheusExporter::set_metrics(struct event& e) 
{
    std::string process_name = std::string(e.cmd);
    if (process_name.empty()) {
        process_name = "unknown";
    }
    
    std::string filename = std::string(e.filename);
    if (filename.empty()) {
        filename = "unknown";
    }
    
    std::cout << "Setting metrics for event: " << process_name << std::endl;
    
    std::string operation = std::string(nr_map[e.flag]);
    
    uint32_t safe_pid = e.pid;
    uint64_t safe_inode = e.i_ino;
    
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
    detailed_labels.insert({"inode", std::to_string(safe_inode)});
    detailed_labels.insert({"file", filename});
    detailed_labels.insert({"cmd", process_name});
    std::string time_now = std::to_string(std::time(nullptr));
    detailed_labels.insert({"ts", time_now});

    
    std::string pid_gauge_key = "file_access_process_pid_" + std::to_string(e.pid);
    prometheus::Gauge* pid_gauge = nullptr;
    
    if (gauge_cache_.find(pid_gauge_key) != gauge_cache_.end()) {
        pid_gauge = gauge_cache_[pid_gauge_key];
    } else {
        pid_gauge = &add_gauge(
            "file_access_process_pid",
            "Process ID accessing files",
            detailed_labels
        );
        gauge_cache_[pid_gauge_key] = pid_gauge;
    }
    
    pid_gauge->Set(static_cast<double>(e.pid));
    std::cout << "Updated PID gauge for PID " << e.pid << std::endl;

}