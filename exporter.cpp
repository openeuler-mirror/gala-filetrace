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
    std::cout << "Setting metrics for event: " << e.cmd << std::endl;
    
    // Get operation name as string
    std::string operation = std::string(nr_map[e.flag]);
    
    // Basic labels for all metrics
    std::map<std::string, std::string> base_labels = {
        {"operation", operation},
        {"process", e.cmd},
    };
    
    // 1. Increment file_access_counter if it exists (total count of file access events)
    if (file_access_counter != nullptr) {
        file_access_counter->Increment();
        std::cout << "Incremented file_access_counter" << std::endl;
    }
    
    // 2. Create detailed labels for gauges/histograms
    std::map<std::string, std::string> detailed_labels = base_labels;
    detailed_labels.insert({"pid", std::to_string(e.pid)});
    detailed_labels.insert({"uid", std::to_string(e.uid)});
    detailed_labels.insert({"gid", std::to_string(e.gid)});
    detailed_labels.insert({"inode", std::to_string(e.i_ino)});
    
    std::string file = "";
    if (e.flag != SYS_write) {
        file = e.filename;
    }
    detailed_labels.insert({"file", file});
    
    // 3. Increment operation-specific counter (with caching to avoid re-registration)
    std::string op_counter_name = "file_access_" + operation + "_total";
    prometheus::Counter* op_counter = nullptr;
    
    // Check cache first
    if (op_counter_cache_.find(op_counter_name) != op_counter_cache_.end()) {
        op_counter = op_counter_cache_[op_counter_name];
    } else {
        // Not in cache, create and cache it
        op_counter = &add_counter(
            op_counter_name,
            "Total " + operation + " operations",
            base_labels
        );
        op_counter_cache_[op_counter_name] = op_counter;
    }
    
    op_counter->Increment();
    std::cout << "Incremented " << op_counter_name << std::endl;
    
    // 4. Record the inode being accessed as a gauge (with caching)
    std::string inode_gauge_key = "file_access_inode_current_" + std::to_string(e.i_ino);
    prometheus::Gauge* inode_gauge = nullptr;
    
    if (gauge_cache_.find(inode_gauge_key) != gauge_cache_.end()) {
        inode_gauge = gauge_cache_[inode_gauge_key];
    } else {
        inode_gauge = &add_gauge(
            "file_access_inode_current",
            "Current inode being accessed",
            detailed_labels
        );
        gauge_cache_[inode_gauge_key] = inode_gauge;
    }
    
    inode_gauge->Set(static_cast<double>(e.i_ino));
    std::cout << "Updated inode gauge for inode " << e.i_ino << std::endl;
    
    // 5. Record process ID as a gauge (with caching)
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