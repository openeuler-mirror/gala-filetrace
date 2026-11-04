#ifndef TUI_HPP
#define TUI_HPP

#include <atomic>
#include <map>
#include <string>
#include <vector>

#include "stats.hpp"

#include <ncurses.h>   // MEVENT, KEY_MOUSE, key macros

// Which panel the keyboard focus is on.
enum class Focus { Devices, Procs };

// Which full-screen page is displayed.
enum class Page { Main, Help, Detail };

// Sort key for the process table.
enum class SortColumn { Ops, Mem, Cpu, Pid, Cmd };

// Sampling interval bounds, in milliseconds. Below the minimum the /proc
// sweep costs more than the redraw; above the maximum the UI looks frozen.
// Both the command-line parser and TuiApp's constructor clamp into this
// range, so the value is always safe to divide with (read_proc_usage does
// 1000.0 / refresh_ms) and to hand to ncurses timeout(), whose argument
// is the getch() wait in milliseconds.
static const int MIN_REFRESH_MS = 100;
static const int MAX_REFRESH_MS = 60000;

struct TuiOptions {
    int refresh_ms = 1000;          // sampling / redraw interval
    bool use_color = true;
};

// Percent samples read from /proc for one pid.
struct ProcUsage {
    double cpu = 0.0;   // percent, since previous sample
    double mem = 0.0;   // percent of total physical memory (RSS)
};

// Capacity contract for TuiApp::usage_: at most one sample per process
// the stats layer tracks. usage_ only ever mirrors the pids present in
// the current snapshot, and TraceStats already bounds its process table
// by MAX_PROC_ENTRIES, so this cap is inherited rather than chosen here.
static const size_t MAX_USAGE_ENTRIES = MAX_PROC_ENTRIES;

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

    // Sampling interval actually in use, i.e. after the constructor's
    // range clamp. Callers can log it; tests assert the clamp with it.
    int refresh_ms() const { return opts_.refresh_ms; }

private:
    // --- one sampling tick ---
    void sample_once();
    void sample_proc_usage();
    // Reads /proc/<pid>/stat and hands the computed usage back through
    // *out; *last_utime/*last_stime are updated on success only.
    bool read_proc_usage(unsigned int pid, double total_mem_kb,
                                     unsigned long long *last_utime,
                                     unsigned long long *last_stime,
                                     double hz, bool have_prev,
                                     ProcUsage *out);

    // --- rendering ---
    void render();
    void render_header();
    void render_devices();
    void render_procs();
    void render_footer();
    void render_help();
    void render_detail();

    // --- view helpers ---
    ProcUsage usage_of(unsigned int pid) const;   // no-insert usage_ lookup
    void sort_rows();
    void clamp_cursors();
    void move_proc_cursor(int delta);
    void scroll_list(int delta);
    void open_detail();
    void escape();
    void cycle_sort();
    void reverse_sort();
    void set_sort_column(SortColumn col);
    void handle_mouse(const MEVENT &ev);

    // x offset of each process-table column (recomputed each render)
    int col_x_[8] = {0};
    int col_w_[8] = {0};
    int proc_header_y_ = 0;

    // --- input (wired up in later stages) ---
    void handle_key(int ch);

    TraceStats &stats_;
    TuiOptions opts_;
    std::atomic<bool> running_{true};

    // latest snapshot + derived view state
    StatsSnapshot snap_;
    std::vector<ProcStat> proc_rows_;      // sorted view of snap_.procs
    // Latest /proc sample per pid. Lifecycle contract:
    //   * entries exist only for pids in the current proc_rows_ (i.e. in
    //     snap_.procs), never for processes that already left the table,
    //     so no state accumulates across exited pids;
    //   * sample_proc_usage() re-samples exactly the current rows and
    //     erases every other pid at the end of each tick;
    //   * size is therefore bounded by MAX_USAGE_ENTRIES
    //     (= MAX_PROC_ENTRIES), enforced by a defensive trim as well.
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
