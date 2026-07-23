#include <iostream>
#include <memory>
#include <string>
#include <map>
#include <thread>
#include <chrono>

#include <prometheus/registry.h>
#include <prometheus/exposer.h>
#include <prometheus/counter.h>
#include <prometheus/gauge.h>
#include <prometheus/histogram.h>
#include <prometheus/summary.h>
#include "logger.hpp"
#include "filetrace.h"

using namespace std;

class PrometheusExporter {
public:
    PrometheusExporter(const std::string& address, int cache_timeout_seconds);
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
    std::shared_ptr<prometheus::Registry> registry;
    void set_metrics(struct event& e);
    prometheus::Counter* file_access_counter = nullptr;
    std::string get_full_path(const struct event *event);
    //add a thread check cache gauge timeout and remove it after some time
    prometheus::Gauge* thread_check_cache_gauge = nullptr;
    //loop to check cache timeout every minute
    void task_gauge_cache_timeout();
    int cache_timeout_seconds;
private:
    std::unique_ptr<prometheus::Exposer> exposer;
    //std::map<std::string, prometheus::Counter*> op_counter_cache;
    std::map<std::string, prometheus::Gauge*> gauge_cache;
    std::map<std::string, std::string> gauge_cache_timestamps;
    std::mutex gauge_cache_mutex;
};
