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

using namespace std;

class PrometheusExporter {
public:
    PrometheusExporter(const std::string& address);
    prometheus::Counter& addCounter(
        const std::string& name,
        const std::string& help,
        const std::map<std::string, std::string>& labels = {}
    );
    void incCounter(prometheus::Counter& counter, double v = 1.0);
    std::shared_ptr<prometheus::Registry> registry_;
    void init();
private:
    std::unique_ptr<prometheus::Exposer> exposer_;
};
