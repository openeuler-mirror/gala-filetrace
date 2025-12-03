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

prometheus::Counter& PrometheusExporter::addCounter(
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

void PrometheusExporter::incCounter(prometheus::Counter& counter, double v) {
    counter.Increment(v);
}

prometheus::Gauge& PrometheusExporter::addGauge(
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

prometheus::Histogram& PrometheusExporter::addHistogram(
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
    std::map<std::string, std::string> labels = {
        {"process", e.cmd},
        {"pid", std::to_string(e.pid)},
        {"uid", std::to_string(e.uid)},
        {"gid", std::to_string(e.gid)},
    };
    std::string op = nr_map[e.flag];
    std::string file = "";
    if(e.flag != SYS_write)
    {
        file = e.filename;
    }
    labels.insert({"operation", op});
    labels.insert({"file", file});
    auto& file_access = addCounter(
        "file_access_total",
        "File access events",
        labels
    );
    file_access.Increment();
}