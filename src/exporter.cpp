#include "exporter.hpp"


PrometheusExporter::PrometheusExporter(const std::string& address, int cache_timeout_seconds) 
    : cache_timeout_seconds(cache_timeout_seconds)
{
    LOG_INFO("Initializing PrometheusExporter with address: " + address);
    if(address.empty()) {
        throw std::runtime_error("Address for Prometheus Exporter cannot be empty.");
    }
    exposer = std::make_unique<prometheus::Exposer>(address);
    registry = std::make_shared<prometheus::Registry>();
    exposer->RegisterCollectable(registry);
    
    // start thread to check cache timeout
    LOG_INFO("PrometheusExporter initialized at: " + address);
    this->cache_timeout_thread_ = std::thread(&PrometheusExporter::task_gauge_cache_timeout, this);
}

PrometheusExporter::~PrometheusExporter() {
    LOG_INFO("Destroying PrometheusExporter.");
    stop_cache_timeout_thread();
    LOG_INFO("PrometheusExporter destroyed.");
}

void PrometheusExporter::stop_cache_timeout_thread() {
    LOG_INFO("Stopping cache timeout thread.");
    stop_thread_.store(true, std::memory_order_relaxed);
    if (cache_timeout_thread_.joinable()) {
        cache_timeout_thread_.join();
    }
    LOG_INFO("Cache timeout thread stopped.");
}

prometheus::Counter& PrometheusExporter::add_counter(
        const std::string& name,
        const std::string& help,
        const std::map<std::string, std::string>& labels)
{
    LOG_INFO("Adding counter: " + name + " with help: " + help);
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
    LOG_INFO("Adding gauge: " + name + " with help: " + help);
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
    LOG_INFO("Adding histogram: " + name + " with help: " + help);
    auto& family = prometheus::BuildHistogram()
                       .Name(name)
                       .Help(help)
                       //.Buckets(buckets)
                       .Register(*registry);
    //return family.Add(labels);
    return family.Add(labels, buckets);
}
std::string PrometheusExporter::make_series_key(
        const std::map<std::string, std::string>& labels)
{
    // std::map iterates in key order, so this encoding is canonical: identical
    // label sets always produce the same key. Length prefixes make it
    // injective even when a label value itself contains '=' or ';'.
    std::string key;
    for (const auto& kv : labels) {
        key += std::to_string(kv.first.size());
        key += ':';
        key += kv.first;
        key += std::to_string(kv.second.size());
        key += ':';
        key += kv.second;
        key += ';';
    }
    return key;
}

// dir:/dir4/dir3/dir2/dir1/filename
std::string PrometheusExporter::get_full_path(const struct event *event) 
{
    LOG_INFO("Constructing full path for event with filename: " + std::string(event->filename));

    const char *parts[] = {event->dir4, event->dir3, event->dir2, event->dir1, event->filename};
    std::string fullpath;
    for (const char *part : parts) {
        if (part[0] == '\0' || (part[0] == '/' && part[1] == '\0')) {
            continue;
        }
        if (!fullpath.empty()) {
            fullpath.push_back('/');
        }
        fullpath += part;
    }

    if (!fullpath.empty() && fullpath.front() != '/') {
        fullpath.insert(fullpath.begin(), '/');
    }

    LOG_INFO("Constructed full path: " + fullpath);
    return fullpath;
}

void PrometheusExporter::set_metrics(struct event& e, const std::string& reported_file)
{
    LOG_INFO("Setting metrics for event with filename: " + std::string(e.filename) + " and operation: " + std::string(nr_map[e.flag]));
    std::string filename = std::string(e.filename);
    // PostData passes the same path it publishes in the JSON "file" field
    // (the monitored side of a rename), so the metric label and the event
    // agree. Direct callers/tests may omit it and get the historical
    // rebuilt-path fallback.
    if (!reported_file.empty()) {
        filename = reported_file;
    } else if (e.flag == SYS_write || e.flag == SYS_unlinkat ||
               e.flag == SYS_copy_file_range || e.flag == SYS_rename ||
               e.flag == SYS_renameat || e.flag == SYS_renameat2)
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
        LOG_INFO("Incremented file_access_counter");
    }
    
    std::map<std::string, std::string> detailed_labels = base_labels;
    detailed_labels.insert({"pid", std::to_string(e.pid)});
    detailed_labels.insert({"ppid", std::to_string(e.ppid)});
    detailed_labels.insert({"uid", std::to_string(e.uid)});
    detailed_labels.insert({"gid", std::to_string(e.gid)});
    detailed_labels.insert({"inode", std::to_string(e.i_ino)});
    detailed_labels.insert({"file", filename});
    // "cmd" is already present via base_labels; inserting it again is a no-op.
    // No wall-clock "ts" label: Prometheus keys a series by its full label set,
    // so a per-event timestamp would register a brand-new series every time and
    // grow cardinality without bound. "When" is exported as the VALUE of a
    // separate filetrace_info_last_access_seconds gauge instead (see below).
    const std::string time_now = std::to_string(std::time(nullptr));
    const double access_time = static_cast<double>(std::time(nullptr));

    // The cache key is the full, ts-free label set. This is the series
    // identity: a key hit means the labels are already exactly what we want,
    // so the hot path is a plain Set() with no Remove+Add re-registration.
    // Series are bounded by distinct identities still alive in the cache and
    // are pruned by task_gauge_cache_timeout().
    const std::string series_key = make_series_key(detailed_labels);

    // Protect cache access with mutex to avoid races with the cleanup thread
    {
        std::lock_guard<std::mutex> lock(gauge_cache_mutex);
        auto it = gauge_cache.find(series_key);
        if (it == gauge_cache.end()) {
            if (!info_gauge_family) {
                info_gauge_family = &prometheus::BuildGauge()
                    .Name("filetrace_info_record")
                    .Help("filetrace info")
                    .Register(*registry);
            }
            prometheus::Gauge* gauge = &info_gauge_family->Add(detailed_labels);
            ++gauge_series_add_count;
            it = gauge_cache.emplace(series_key, gauge).first;
        }
        // Cache hit (or just created): labels are fixed by the key, so there is
        // never a stale-label case and never a need to Remove+Add.
        if (it->second) {
            it->second->Set(static_cast<double>(e.pid));
        }

        // Last-access time as a metric value under the same stable labels.
        auto ts_it = last_access_cache.find(series_key);
        if (ts_it == last_access_cache.end()) {
            if (!last_access_family) {
                last_access_family = &prometheus::BuildGauge()
                    .Name("filetrace_info_last_access_seconds")
                    .Help("unix timestamp of the most recent access for this filetrace identity")
                    .Register(*registry);
            }
            prometheus::Gauge* ts_gauge = &last_access_family->Add(detailed_labels);
            ++last_access_series_add_count;
            ts_it = last_access_cache.emplace(series_key, ts_gauge).first;
        }
        if (ts_it->second) {
            ts_it->second->Set(access_time);
        }

        gauge_cache_timestamps[series_key] = time_now;
    }
    LOG_INFO("Updated gauge for PID " + std::to_string(e.pid));
}

void PrometheusExporter::task_gauge_cache_timeout() {
    LOG_INFO("Starting gauge cache timeout task.");
    while (!stop_thread_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::lock_guard<std::mutex> lock(gauge_cache_mutex);
        for (auto it = gauge_cache_timestamps.begin(); it != gauge_cache_timestamps.end(); ) {
            const std::string& key = it->first;
            std::cout << "Checking gauge cache key: " << key << std::endl;
            const std::string& timestamp_str = it->second;
            std::time_t timestamp = std::stol(timestamp_str);
            std::time_t now = std::time(nullptr);
            if (now - timestamp > cache_timeout_seconds) {
                // The Family owns each gauge; erasing the cached pointer alone
                // leaves the labeled series registered and exported. Remove it
                // from the family first, for both the info and last-access
                // series that share this identity key.
                auto gauge_it = gauge_cache.find(key);
                if (gauge_it != gauge_cache.end()) {
                    if (info_gauge_family && gauge_it->second) {
                        info_gauge_family->Remove(gauge_it->second);
                    }
                    gauge_cache.erase(gauge_it);
                }
                auto ts_it = last_access_cache.find(key);
                if (ts_it != last_access_cache.end()) {
                    if (last_access_family && ts_it->second) {
                        last_access_family->Remove(ts_it->second);
                    }
                    last_access_cache.erase(ts_it);
                }
                LOG_INFO("Removed stale gauge from cache: " + key);
                it = gauge_cache_timestamps.erase(it);
            }
            else 
            {
                ++it;
            }
        }
    }
}
