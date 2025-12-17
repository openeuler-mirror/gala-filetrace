#include <iostream>
#include <memory>
#include <string>
#include <map>

#include <prometheus/registry.h>
#include <prometheus/exposer.h>
#include <prometheus/counter.h>
#include <prometheus/gauge.h>
#include <prometheus/histogram.h>
#include <prometheus/summary.h>

#include "filetrace.h"

using namespace std;

class PrometheusExporter {
public:
    PrometheusExporter(const std::string& address);
    prometheus::Counter& add_counter(const std::string& name,
                                    const std::string& help,
                                    const std::map<std::string, std::string>& labels = {});

    prometheus::Gauge& add_gauge(const std::string& name,
                                const std::string& help,
                                const std::map<std::string, std::string>& labels = {});

    prometheus::Histogram& add_histogram(const std::string& name,
                                        const std::string& help,
                                        const prometheus::Histogram::BucketBoundaries& buckets,
                                        const std::map<std::string, std::string>& labels = {});

    void inc_counter(prometheus::Counter& counter, double v = 1.0);
    std::shared_ptr<prometheus::Registry> registry_;
    void set_metrics(struct event& e);
    prometheus::Counter* file_access_counter = nullptr;
    std::string get_full_path(const struct event *event);
private:
    std::unique_ptr<prometheus::Exposer> exposer_;
    std::map<std::string, prometheus::Counter*> op_counter_cache_;
    std::map<std::string, prometheus::Gauge*> gauge_cache_;
};
