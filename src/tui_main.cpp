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
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <thread>
#include <nlohmann/json.hpp>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include "stats.hpp"
#include "tui.hpp"

using json = nlohmann::json;

static std::atomic<TuiApp *> g_tui{nullptr}; // published while the TUI runs

static void tui_sig_handler(int)
{
    TuiApp *tui = g_tui.load(std::memory_order_acquire);
    if (tui) {
        tui->request_stop();
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
                // strict parse: whole-string decimal, errno checked for
                // overflow, junk or non-numeric input rejected
                char *end = nullptr;
                errno = 0;
                long val = strtol(optarg, &end, 10);
                if (errno == ERANGE || end == optarg || *end != '\0' ||
                    val <= 0) {
                    std::cerr << "Warning: invalid refresh interval '"
                              << optarg << "', using 1000ms" << std::endl;
                    val = 1000;
                } else if (val < MIN_REFRESH_MS || val > MAX_REFRESH_MS) {
                    // The TuiApp constructor clamps as well, but silently:
                    // say so here, otherwise a -r 3600000 the user asked for
                    // looks like a 60 s refresh that never happened.
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
    // below 100ms the /proc sampling cost dominates; above 60s the
    // usleep(refresh_ms * 1000) usec argument becomes needlessly large
    // and the UI would look frozen — clamp both ends
    if (refresh_ms < 100) {
        refresh_ms = 100;
    }
    if (refresh_ms > 60000) {
        refresh_ms = 60000;
    }

    // This standalone binary has no live event source (the real ring-buffer
    // feed lives in the main filetrace binary via -t); without the demo
    // generator the UI would render forever with no data at all.
    if (!demo) {
        std::cerr << "filetrace-tui has no live event source." << std::endl
                  << "Use -d for the demo feed, or run 'filetrace -t' for live tracing."
                  << std::endl;
        return 1;
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
    // publish before registering the handlers: a signal may arrive the
    // instant the handler is installed (release store pairs with the
    // acquire load in the handler)
    g_tui.store(&tui, std::memory_order_release);
    signal(SIGINT, tui_sig_handler);
    signal(SIGTERM, tui_sig_handler);

    std::atomic<bool> running{true};
    std::thread feeder;
    // Safe to share TraceStats across threads: on_event() and snapshot()
    // serialize on TraceStats' internal mutex, so the demo feeder writing
    // here and the UI thread taking snapshots cannot race.
    if (demo) {
        feeder = std::thread(demo_feed, std::ref(stats), paths, std::ref(running));
    }

    tui.run();
    running = false;
    if (feeder.joinable()) {
        feeder.join();
    }
    // Undo the handler and the published pointer BEFORE the locals unwind:
    // TuiApp is destroyed before TraceStats, so a SIGTERM/SIGINT delivered
    // between run() returning and process exit would otherwise call
    // request_stop() on an already-destructed object (UAF). Restoring
    // SIG_DFL also gives systemd/operator a second stop signal the usual
    // "force-kill on repeat signal" semantics.
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    g_tui.store(nullptr, std::memory_order_release);
    return 0;
}
