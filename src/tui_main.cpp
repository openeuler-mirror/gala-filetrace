// filetrace-tui: standalone terminal UI entry point.
//
// This stage wires the TUI to a TraceStats instance fed by a demo
// generator so the rendering can be exercised without loading eBPF.
// The later stage replaces the demo feed with the real ring-buffer
// events inside the main filetrace binary (-t).

#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <thread>

#include "stats.hpp"
#include "tui.hpp"

using json = nlohmann::json;

static TuiApp *g_tui = nullptr;

static void tui_sig_handler(int)
{
    if (g_tui) {
        g_tui->request_stop();
    }
}

static std::vector<std::string> load_config_list(const std::string &path)
{
    std::vector<std::string> paths;
    std::ifstream f(path);
    if (!f.good()) {
        return paths;
    }
    try {
        json cfg = json::parse(f);
        if (cfg.contains("config_list") && cfg["config_list"].is_array()) {
            paths = cfg["config_list"].get<std::vector<std::string>>();
        }
    } catch (const std::exception &e) {
        std::cerr << "Warning: failed to parse config: " << e.what() << std::endl;
    }
    return paths;
}

// Demo event generator: fakes file operations on the configured paths so
// the UI shows data without kernel tracing. Only for standalone preview.
static void demo_feed(TraceStats &stats,
                      const std::vector<std::string> &paths,
                      std::atomic<bool> &running)
{
    const char *cmds[] = {"bash", "vim", "nginx", "python3", "rsync"};
    int kinds[] = {SYS_write, SYS_openat, SYS_unlinkat, SYS_renameat2};
    unsigned tick = 0;
    while (running) {
        for (size_t i = 0; i < paths.size(); i++) {
            for (int k = 0; k < 3; k++) {
                struct event e;
                memset(&e, 0, sizeof(e));
                e.pid = 1000 + (tick + k) % 7;
                e.ppid = 1;
                e.uid = 1000 + (int)i;
                snprintf(e.cmd, sizeof(e.cmd), "%s",
                         cmds[(tick + k) % 5]);
                e.flag = kinds[(tick + k + (int)i) % 4];
                stats.on_event(e, paths[i]);
            }
        }
        tick++;
        usleep(200 * 1000);
    }
}

int main(int argc, char **argv)
{
    std::string config_file = "/etc/gala-filetrace/gala-filetrace.json";
    int refresh_ms = 1000;
    bool demo = false;
    int opt;
    while ((opt = getopt(argc, argv, "c:r:d")) != -1) {
        switch (opt) {
            case 'c': config_file = optarg; break;
            case 'r': {
                // strict parse: the whole argument must be a decimal
                // integer, and errno catches values that do not fit in a
                // long. atoi() silently truncates on overflow, which lets a
                // huge -r value reach the multiply below and overflow.
                char *end = nullptr;
                errno = 0;
                long val = strtol(optarg, &end, 10);
                if (errno == ERANGE || end == optarg || *end != '\0' ||
                    val <= 0) {
                    std::cerr << "Warning: invalid refresh interval '"
                              << optarg << "', using 1000ms" << std::endl;
                    val = 1000;
                } else if (val < MIN_REFRESH_MS || val > MAX_REFRESH_MS) {
                    long clamped = val < MIN_REFRESH_MS ? MIN_REFRESH_MS
                                                        : MAX_REFRESH_MS;
                    std::cerr << "Warning: refresh interval " << val
                              << "ms out of range [" << MIN_REFRESH_MS << ", "
                              << MAX_REFRESH_MS << "], using " << clamped
                              << "ms" << std::endl;
                    val = clamped;
                }
                refresh_ms = (int)val;
                break;
            }
            case 'd': demo = true; break;
            default:
                std::cerr << "Usage: " << argv[0]
                          << " [-c config] [-r refresh_ms] [-d demo]" << std::endl;
                return 1;
        }
    }
    // clamp both ends: below MIN_REFRESH_MS the /proc sweep dominates the
    // refresh, above MAX_REFRESH_MS the UI looks frozen. The upper bound
    // is what keeps refresh_ms * 1000 (usec) inside useconds_t.
    if (refresh_ms < MIN_REFRESH_MS) {
        refresh_ms = MIN_REFRESH_MS;
    }
    if (refresh_ms > MAX_REFRESH_MS) {
        refresh_ms = MAX_REFRESH_MS;
    }

    auto paths = load_config_list(config_file);
    if (paths.empty()) {
        std::cerr << "No config_list entries in " << config_file
                  << "; nothing to monitor." << std::endl;
        return 1;
    }

    TraceStats stats(paths);
    if (stats.ignored_monitor_paths() > 0) {
        // the aggregate sizes its device table by MAX_DEVICE_ENTRIES, so a
        // config larger than that cannot be represented -- say so instead
        // of silently showing a truncated device list
        std::cerr << "Warning: config lists more than " << MAX_DEVICE_ENTRIES
                  << " distinct paths; " << stats.ignored_monitor_paths()
                  << " entries are ignored" << std::endl;
    }
    TuiOptions opts;
    opts.refresh_ms = refresh_ms;
    TuiApp tui(stats, opts);
    g_tui = &tui;
    signal(SIGINT, tui_sig_handler);
    signal(SIGTERM, tui_sig_handler);

    std::atomic<bool> running{true};
    std::thread feeder;
    if (demo) {
        feeder = std::thread(demo_feed, std::ref(stats), paths, std::ref(running));
    }

    tui.run();
    running = false;
    if (feeder.joinable()) {
        feeder.join();
    }
    return 0;
}
