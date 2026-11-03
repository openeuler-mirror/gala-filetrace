#ifndef TUI_HPP
#define TUI_HPP

#include <atomic>
#include <map>
#include <string>
#include <vector>

#include "stats.hpp"

// Which panel the keyboard focus is on.
enum class Focus { Devices, Procs };

// Which full-screen page is displayed.
enum class Page { Main, Help, Detail };

// Sort key for the process table.
enum class SortColumn { Ops, Mem, Cpu, Pid, Cmd };

struct TuiOptions {
    int refresh_ms = 1000;          // sampling / redraw interval
    bool use_color = true;
};

// Percent samples read from /proc for one pid.
struct ProcUsage {
    double cpu = 0.0;   // percent, since previous sample
    double mem = 0.0;   // percent of total physical memory (RSS)
};

// top-style terminal UI over a TraceStats aggregator. The UI owns no
// data: each tick it takes a snapshot() and renders it. Run() blocks
// until the user quits.
class TuiApp {
public:
    TuiApp(TraceStats &stats, const TuiOptions &opts);

    // Initialize ncurses, loop refresh+input until quit. Returns when done.
    void run();

    // Request exit from another thread (e.g. signal handler).
    void request_stop() { running_ = false; }

private:
    // --- one sampling tick ---
    void sample_once();
    void sample_proc_usage();
    bool read_proc_usage(unsigned int pid, double total_mem_kb,
                                     unsigned long long *last_utime,
                                     unsigned long long *last_stime,
                                     double hz, bool have_prev);

    // --- rendering ---
    void render();
    void render_header();
    void render_devices();
    void render_procs();
    void render_footer();
    void render_help();
    void render_detail();

    // --- view helpers ---
    void sort_rows();
    void clamp_cursors();

    // --- input (wired up in later stages) ---
    void handle_key(int ch);

    TraceStats &stats_;
    TuiOptions opts_;
    std::atomic<bool> running_{true};

    // latest snapshot + derived view state
    StatsSnapshot snap_;
    std::vector<ProcStat> proc_rows_;      // sorted view of snap_.procs
    std::map<unsigned int, ProcUsage> usage_;

    // view state
    Page page_ = Page::Main;
    Focus focus_ = Focus::Procs;
    SortColumn sort_col_ = SortColumn::Ops;
    bool sort_desc_ = true;
    int proc_cursor_ = 0;                  // selected row (view index)
    int proc_scroll_ = 0;                  // first visible row
    int device_scroll_ = 0;
    int h_scroll_ = 0;                     // horizontal command-line scroll
    unsigned int detail_pid_ = 0;
    bool selection_active_ = false;

    // cached screen geometry
    int rows_ = 0, cols_ = 0;
    int dev_height_ = 0;                   // device panel height
    int proc_top_ = 0, proc_height_ = 0;   // process table body area
};

#endif // TUI_HPP
