#include "exporter.hpp"

PrometheusExporter::PrometheusExporter(const std::string& address) 
{
    if(address.empty()) {
        throw std::runtime_error("Address for Prometheus Exposer cannot be empty.");
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