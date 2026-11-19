#include "tui.hpp"

#include <dirent.h>
#include <unistd.h>

#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <map>

#include <ncurses.h>

// layout constants (lines)
static const int HEADER_LINES = 2;
static const int DEV_HEADER = 2;    // panel title + column header
static const int FOOTER_LINES = 2;
static const int PROC_HEADER = 1;

// process table column layout: name, width, header text
struct Column {
    const char *title;
    int width;
};

static const Column kColumns[] = {
    {"PID",     8},
    {"PPID",    8},
    {"USER",    10},
    {"%CPU",    7},
    {"%MEM",    7},
    {"OPS",     8},
    {"COMMAND", 0},   // 0 = fill remaining width
};
static const int kNumCols = (int)(sizeof(kColumns) / sizeof(kColumns[0]));

static const Column kDevColumns[] = {
    {"PATH",    0},
    {"OPS",     8},
    {"WRITE",   8},
    {"OPEN",    8},
    {"UNLINK",  8},
    {"RENAME",  8},
    {"OTHER",   8},
};
static const int kNumDevCols = (int)(sizeof(kDevColumns) / sizeof(kDevColumns[0]));

static std::string fmt_uint64(uint64_t v)
{
    char buf[24];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
    return buf;
}

static std::string trim_to_width(const std::string &s, int width)
{
    if (width <= 0) {
        return s;
    }
    if ((int)s.size() <= width) {
        return s;
    }
    if (width == 1) {
        return "~";
    }
    return s.substr(0, width - 1) + "~";
}

TuiApp::TuiApp(TraceStats &stats, const TuiOptions &opts)
    : stats_(stats), opts_(opts)
{
    // The interval is used as a divisor and converted to microseconds for
    // the tick sleep, so a caller-provided value outside the supported
    // range would either divide by zero or overflow the sleep argument.
    // Clamp once here instead of trusting every caller to do it.
    if (opts_.refresh_ms < MIN_REFRESH_MS) {
        opts_.refresh_ms = MIN_REFRESH_MS;
    } else if (opts_.refresh_ms > MAX_REFRESH_MS) {
        opts_.refresh_ms = MAX_REFRESH_MS;
    }
}

// ---------------------------------------------------------------------------
// sampling
// ---------------------------------------------------------------------------

static double read_total_mem_kb()
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) {
        return 0;
    }
    char line[256];
    double kb = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            sscanf(line + 9, "%lf", &kb);
            break;
        }
    }
    fclose(f);
    return kb;
}

static unsigned long long read_boot_ms_since()
{
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

bool TuiApp::read_proc_usage(unsigned int pid, double total_mem_kb,
                             unsigned long long *last_utime,
                             unsigned long long *last_stime,
                             double hz, bool have_prev, ProcUsage *out)
{
    ProcUsage u;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return false;
    }
    char line[512];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return false;
    }
    fclose(f);

    // fields after the comm in parentheses
    char *p = strrchr(line, ')');
    if (!p) {
        return false;
    }
    unsigned long long utime = 0, stime = 0;
    long rss_pages = 0;
    // fields: state(3) ppid(4) ... utime(14) stime(15) ...
    //         starttime(22) vsize(23) rss(24)
    if (sscanf(p + 2,
               "%*s %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu "
               "%*d %*d %*d %*d %*d %*d %*u %*u %lu",
               &utime, &stime, &rss_pages) < 3) {
        return false;
    }

    // rss is reported in pages; the page size is 4 KB on x86-64 but 16 or
    // 64 KB on other kernels, so query it once instead of assuming. Doing
    // it per process per tick would put a sysconf() call in the hot path
    // of a sweep that runs over every row.
    static const double page_kb = [] {
        long psz = sysconf(_SC_PAGESIZE);
        return psz > 0 ? (double)psz / 1024.0 : 4.0;
    }();

    if (total_mem_kb > 0) {
        u.mem = 100.0 * (double)rss_pages * page_kb / total_mem_kb;
        if (u.mem < 0) {
            u.mem = 0;
        }
        if (u.mem > 100) {
            u.mem = 100;
        }
    }
    if (have_prev && hz > 0) {
        // clamp each delta at zero before subtracting: utime/stime move
        // backwards when a pid is reused by a new process, and unsigned
        // wrap-around would otherwise inflate dt and pin %CPU at the
        // 999 ceiling
        unsigned long long dt =
            (utime >= *last_utime ? utime - *last_utime : 0) +
            (stime >= *last_stime ? stime - *last_stime : 0);
        u.cpu = 100.0 * (double)dt / hz *
                (1000.0 / (double)opts_.refresh_ms);
        if (u.cpu < 0) {
            u.cpu = 0;
        }
        if (u.cpu > 999) {
            u.cpu = 999;
        }
    }

    *out = u;
    *last_utime = utime;
    *last_stime = stime;
    return true;
}

struct UsageSample {
    unsigned long long utime = 0, stime = 0;
    bool have = false;
};

void TuiApp::sample_proc_usage()
{
    static double total_mem_kb = 0, hz = 0;
    if (hz == 0) {
        long v = sysconf(_SC_CLK_TCK);
        hz = v > 0 ? (double)v : 100.0;
    }
    if (total_mem_kb == 0) {
        total_mem_kb = read_total_mem_kb();
    }

    static std::map<unsigned int, UsageSample> prev;
    static std::map<unsigned int, UsageSample> cur;
    std::swap(prev, cur);
    cur.clear();

    for (auto &row : proc_rows_) {
        UsageSample s;
        bool have_prev = prev.count(row.pid) && prev[row.pid].have;
        unsigned long long utime = have_prev ? prev[row.pid].utime : 0;
        unsigned long long stime = have_prev ? prev[row.pid].stime : 0;
        ProcUsage u;
        bool ok = read_proc_usage(row.pid, total_mem_kb,
                                  &utime, &stime, hz, have_prev, &u);
        if (ok) {
            s.utime = utime;
            s.stime = stime;
            s.have = true;
            usage_[row.pid] = u;
        } else if (have_prev) {
            // carry the last good sample forward so the delta baseline
            // survives transient read failures (e.g. pid vanished mid-tick)
            s.utime = prev[row.pid].utime;
            s.stime = prev[row.pid].stime;
            s.have = true;
        }
        cur[row.pid] = s;
    }

    // drop usage for pids that left the table so the map cannot grow
    // without bound across long sessions
    for (auto it = usage_.begin(); it != usage_.end();) {
        if (cur.count(it->first) == 0) {
            it = usage_.erase(it);
        } else {
            ++it;
        }
    }
    // defense in depth: the loop above already leaves only current pids,
    // but never let a future change to the snapshot let this map outgrow
    // its documented cap
    while (usage_.size() > MAX_USAGE_ENTRIES) {
        usage_.erase(usage_.begin());
    }
}

void TuiApp::sample_once()
{
    snap_ = stats_.snapshot();
    proc_rows_ = snap_.procs;
    // refresh %CPU/%MEM BEFORE sorting: sort_rows() orders by the usage
    // values that are rendered, so sampling after the sort would order
    // the rows by the previous sample's numbers
    sample_proc_usage();
    sort_rows();
    // the selection tracks a pid, but the cursor is an index into
    // proc_rows_: re-sorting (new events, changed order) moves rows, so
    // re-locate the selected process after every refresh; if it exited,
    // clear the selection instead of pointing at an unrelated row
    if (selection_active_ && selected_pid_ != 0) {
        bool found = false;
        for (int idx = 0; idx < (int)proc_rows_.size(); idx++) {
            if (proc_rows_[idx].pid == selected_pid_) {
                proc_cursor_ = idx;
                found = true;
                break;
            }
        }
        if (!found) {
            selection_active_ = false;
            selected_pid_ = 0;
        }
    }
    clamp_cursors();

    // The device table can shrink between ticks (LRU eviction) or the
    // terminal can be resized. device_scroll_ is only adjusted on an explicit
    // scroll, so without re-clamping here it can point far past the end and
    // render_devices() then draws an entirely blank panel.
    int dev_visible = dev_height_ - DEV_HEADER - 1;
    if (dev_visible < 1) {
        dev_visible = 1;
    }
    int dev_max_scroll = (int)snap_.devices.size() - dev_visible;
    if (dev_max_scroll < 0) {
        dev_max_scroll = 0;
    }
    if (device_scroll_ > dev_max_scroll) {
        device_scroll_ = dev_max_scroll;
    }
    if (device_scroll_ < 0) {
        device_scroll_ = 0;
    }
}

// ---------------------------------------------------------------------------
// sorting / view helpers
// ---------------------------------------------------------------------------

// Non-inserting usage_ lookup: reads during sort/render must not add
// zero entries back into the map the sampler rebuilds every tick.
ProcUsage TuiApp::usage_of(unsigned int pid) const
{
    auto it = usage_.find(pid);
    return it != usage_.end() ? it->second : ProcUsage{};
}

// Sort the process rows by the current sort column/direction.
// (Column cycling and direction toggling are wired up in a later stage;
// this keeps the default view: OPS descending.)
void TuiApp::sort_rows()
{
    std::sort(proc_rows_.begin(), proc_rows_.end(),
              [this](const ProcStat &a, const ProcStat &b) {
                  uint64_t ka = 0, kb = 0;
                  switch (sort_col_) {
                      case SortColumn::Pid:
                          return sort_desc_ ? a.pid > b.pid : a.pid < b.pid;
                      case SortColumn::Cmd:
                          return sort_desc_ ? a.cmd > b.cmd : a.cmd < b.cmd;
                      case SortColumn::Mem:
                          ka = (uint64_t)(usage_of(a.pid).mem * 100);
                          kb = (uint64_t)(usage_of(b.pid).mem * 100);
                          break;
                      case SortColumn::Cpu:
                          ka = (uint64_t)(usage_of(a.pid).cpu * 100);
                          kb = (uint64_t)(usage_of(b.pid).cpu * 100);
                          break;
                      case SortColumn::Ops:
                      default:
                          ka = a.ops;
                          kb = b.ops;
                          break;
                  }
                  if (ka != kb) {
                      return sort_desc_ ? ka > kb : ka < kb;
                  }
                  return a.pid < b.pid;   // stable tie-break
              });
}

void TuiApp::clamp_cursors()
{
    int n = (int)proc_rows_.size();
    int visible = proc_height_ > 1 ? proc_height_ - 1 : 1;
    if (proc_cursor_ >= n) {
        proc_cursor_ = n - 1;
    }
    if (proc_cursor_ < 0) {
        proc_cursor_ = 0;
    }
    if (visible > 0) {
        if (proc_cursor_ < proc_scroll_) {
            proc_scroll_ = proc_cursor_;
        }
        if (proc_cursor_ >= proc_scroll_ + visible) {
            proc_scroll_ = proc_cursor_ - visible + 1;
        }
        if (proc_scroll_ > n - visible) {
            proc_scroll_ = n - visible;
        }
    }
    if (proc_scroll_ < 0) {
        proc_scroll_ = 0;
    }
}

// ---------------------------------------------------------------------------
// ncurses lifecycle + main loop
// ---------------------------------------------------------------------------

void TuiApp::run()
{
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    set_escdelay(50);
    timeout(opts_.refresh_ms);       // blocking getch() ticks the interval
    mousemask(BUTTON1_CLICKED | BUTTON1_DOUBLE_CLICKED, nullptr);

    if (opts_.use_color && has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_BLACK, COLOR_CYAN);    // column header
        init_pair(2, COLOR_BLACK, COLOR_WHITE);   // selected row
        init_pair(3, COLOR_GREEN, -1);            // highlight values
        init_pair(4, COLOR_YELLOW, -1);           // titles / hints
    }

    // paint once before the first blocking wait, so the screen is not
    // blank for up to a whole refresh interval at startup
    sample_once();
    render();
    auto last_sample = std::chrono::steady_clock::now();

    while (running_) {
        // getch() blocks up to one refresh interval, so a key press or a
        // click is handled the moment it arrives instead of waiting out a
        // full sleep'ed tick first.
        int ch = getch();
        if (ch != ERR) {
            // Drain the whole typeahead buffer before drawing: a burst of
            // keys must be handled immediately, but one full-screen render
            // per event is wasted work. The drain itself uses a zero
            // timeout so the batch ends as soon as the buffer is empty.
            timeout(0);
            do {
                if (ch == KEY_MOUSE) {
                    MEVENT ev;
                    if (getmouse(&ev) == OK) {
                        handle_mouse(MouseEvent{ev.id, ev.x, ev.y, ev.z,
                                                (unsigned long)ev.bstate});
                    }
                } else {
                    handle_key(ch);
                }
                if (!running_) {
                    break;
                }
            } while ((ch = getch()) != ERR);
            timeout(opts_.refresh_ms);
            if (!running_) {
                break;
            }
        }
        // ERR is not a reliable sampling tick: while events keep arriving
        // faster than refresh_ms, getch() keeps returning early, ERR never
        // fires and sampling would starve (the data freezes while the UI
        // keeps redrawing). Track the interval on the wall clock instead,
        // so a sample runs at least every refresh_ms no matter how busy
        // the input is. Background pages sample the same way.
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_sample)
                .count() >= opts_.refresh_ms) {
            sample_once();
            last_sample = now;
        }
        render();
    }

    endwin();
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

void TuiApp::render()
{
    erase();
    getmaxyx(stdscr, rows_, cols_);

    if (page_ == Page::Help) {
        render_help();
        return;
    }
    if (page_ == Page::Detail) {
        render_detail();
        return;
    }

    // layout: header | devices panel | process panel | footer
    dev_height_ = std::min(rows_ / 3, 3 + (int)snap_.devices.size());
    if (dev_height_ < DEV_HEADER + 2) {
        // title + column header + at least one data row + separator
        dev_height_ = DEV_HEADER + 2;
    }
    if (dev_height_ > rows_ - HEADER_LINES - FOOTER_LINES - PROC_HEADER - 1) {
        dev_height_ = rows_ - HEADER_LINES - FOOTER_LINES - PROC_HEADER - 1;
    }
    if (dev_height_ < DEV_HEADER + 2) {
        // title + column header + at least one data row + separator
        dev_height_ = DEV_HEADER + 2;
    }
    proc_top_ = HEADER_LINES + dev_height_;
    proc_height_ = rows_ - proc_top_ - FOOTER_LINES;
    if (proc_height_ < 1) {
        proc_height_ = 1;
    }

    render_header();
    render_devices();
    render_procs();
    render_footer();
    refresh();
}

void TuiApp::render_header()
{
    time_t now = time(nullptr);
    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", localtime(&now));

    attron(A_BOLD);
    mvprintw(0, 0, "filetrace-tui");
    attroff(A_BOLD);
    mvprintw(0, 16, "load: sample every %dms   events: %llu   procs: %d   files: %d   %s",
             opts_.refresh_ms,
             (unsigned long long)snap_.total_events,
             (int)snap_.procs.size(),
             (int)snap_.devices.size(),
             tbuf);
    mvhline(1, 0, ACS_HLINE, cols_);
}

void TuiApp::render_devices()
{
    int y = HEADER_LINES;
    attron(A_BOLD | COLOR_PAIR(opts_.use_color ? 4 : 0));
    mvprintw(y, 0, "Monitored Files (config_list)");
    attroff(A_BOLD | COLOR_PAIR(opts_.use_color ? 4 : 0));

    // column header row
    int x = 0;
    y++;
    for (int i = 0; i < kNumDevCols; i++) {
        int w = kDevColumns[i].width;
        if (w == 0) {
            w = cols_ - x;
            for (int j = 0; j < kNumDevCols; j++) {
                if (kDevColumns[j].width != 0) {
                    w -= kDevColumns[j].width;
                }
            }
            if (w < 4) {
                w = 4;
            }
        }
        attron(A_BOLD | COLOR_PAIR(1));
        mvprintw(y, x, "%-*s", w, kDevColumns[i].title);
        attroff(A_BOLD | COLOR_PAIR(1));
        x += w;
    }

    // rows, honoring device_scroll_
    int visible = dev_height_ - DEV_HEADER - 1;
    for (int row = 0; row < visible; row++) {
        int idx = device_scroll_ + row;
        y++;
        if (y >= HEADER_LINES + dev_height_) {
            break;
        }
        mvhline(y, 0, ' ', cols_);
        if (idx >= (int)snap_.devices.size()) {
            continue;
        }
        const DeviceStat &d = snap_.devices[idx];
        x = 0;
        // PATH column gets remaining width
        int path_w = cols_ - (kNumDevCols - 1) * 8;
        if (path_w < 4) {
            path_w = 4;
        }
        mvprintw(y, x, "%-*s", path_w, trim_to_width(d.path, path_w).c_str());
        x += path_w;
        std::string vals[5] = {
            fmt_uint64(d.ops), fmt_uint64(d.writes),
            fmt_uint64(d.opens), fmt_uint64(d.unlinks),
            fmt_uint64(d.renames),
        };
        for (int i = 0; i < 5; i++) {
            mvprintw(y, x, "%8s", vals[i].c_str());
            x += 8;
        }
        mvprintw(y, x, "%8s", fmt_uint64(d.others).c_str());
    }

    // panel separator
    int sep = HEADER_LINES + dev_height_ - 1;
    if (sep < rows_) {
        mvhline(sep, 0, ACS_HLINE, cols_);
    }
}

void TuiApp::render_procs()
{
    int y = proc_top_;
    int x = 0;
    int cmd_w = cols_ - x;
    for (int i = 0; i < kNumCols; i++) {
        if (kColumns[i].width != 0) {
            cmd_w -= kColumns[i].width;
        }
    }
    if (cmd_w < 8) {
        cmd_w = 8;
    }

    // column header; sortable columns get the sort marker
    proc_header_y_ = y;
    for (int i = 0; i < kNumCols; i++) {
        int w = kColumns[i].width != 0 ? kColumns[i].width : cmd_w;
        col_x_[i] = x;
        col_w_[i] = w;
        std::string title = kColumns[i].title;
        bool sortable = title == "OPS" || title == "%MEM" ||
                        title == "%CPU" || title == "PID" || title == "COMMAND";
        if (sortable) {
            bool active = (title == "OPS" && sort_col_ == SortColumn::Ops) ||
                          (title == "%MEM" && sort_col_ == SortColumn::Mem) ||
                          (title == "%CPU" && sort_col_ == SortColumn::Cpu) ||
                          (title == "PID" && sort_col_ == SortColumn::Pid) ||
                          (title == "COMMAND" && sort_col_ == SortColumn::Cmd);
            if (active) {
                title += sort_desc_ ? " v" : " ^";
            }
        }
        attron(A_BOLD | COLOR_PAIR(1));
        mvprintw(y, x, "%-*s", w, title.c_str());
        attroff(A_BOLD | COLOR_PAIR(1));
        x += w;
    }

    // rows: the column header occupies one line, matching clamp_cursors
    int visible = proc_height_ - 1;
    for (int row = 0; row < visible; row++) {
        int idx = proc_scroll_ + row;
        y++;
        if (y >= proc_top_ + proc_height_) {
            break;
        }
        mvhline(y, 0, ' ', cols_);
        if (idx >= (int)proc_rows_.size()) {
            continue;
        }
        const ProcStat &p = proc_rows_[idx];
        bool selected = selection_active_ && idx == proc_cursor_;
        if (selected || (focus_ == Focus::Procs && idx == proc_cursor_)) {
            attron(selected ? COLOR_PAIR(2) | A_BOLD : A_REVERSE);
        }
        x = 0;
        char num[16];
        snprintf(num, sizeof(num), "%u", p.pid);
        mvprintw(y, x, "%-8s", num);
        x += 8;
        snprintf(num, sizeof(num), "%u", p.ppid);
        mvprintw(y, x, "%-8s", num);
        x += 8;
        mvprintw(y, x, "%-10s", fmt_uint64(p.uid).c_str());
        x += 10;
        snprintf(num, sizeof(num), "%.1f", usage_of(p.pid).cpu);
        mvprintw(y, x, "%7s", num);
        x += 7;
        snprintf(num, sizeof(num), "%.1f", usage_of(p.pid).mem);
        mvprintw(y, x, "%7s", num);
        x += 7;
        mvprintw(y, x, "%8s", fmt_uint64(p.ops).c_str());
        x += 8;
        // command line: h-scroll window for long lines
        std::string cmd = p.cmd;
        std::string view = cmd;
        if (h_scroll_ < 0 && (int)cmd.size() > cmd_w) {
            int start = -h_scroll_;
            int max_start = (int)cmd.size() - cmd_w;
            if (start > max_start) {
                start = max_start;   // never scroll past the line tail
            }
            if (start < 0) {
                start = 0;
            }
            view = cmd.substr(start);
        }
        mvprintw(y, x, "%-*s", cmd_w, trim_to_width(view, cmd_w).c_str());
        if (selected || (focus_ == Focus::Procs && idx == proc_cursor_)) {
            attroff(selected ? COLOR_PAIR(2) | A_BOLD : A_REVERSE);
        }
    }
}

void TuiApp::render_footer()
{
    int y = rows_ - FOOTER_LINES;
    mvhline(y, 0, ACS_HLINE, cols_);
    const char *focus_name = focus_ == Focus::Procs ? "Procs" : "Devices";
    mvprintw(y + 1, 0, "focus:%s  sort:%s%s  [h]help [q]quit [Tab]focus [s]sort [/]reverse  @%d/%d",
             focus_name,
             sort_col_ == SortColumn::Ops ? "OPS" :
             sort_col_ == SortColumn::Mem ? "%MEM" :
             sort_col_ == SortColumn::Cpu ? "%CPU" :
             sort_col_ == SortColumn::Pid ? "PID" : "COMMAND",
             sort_desc_ ? " desc" : " asc",
             proc_scroll_ + 1,
             std::max((int)proc_rows_.size(), 1));
}

void TuiApp::render_help()
{
    static const char *lines[] = {
        "filetrace-tui help                                        ",
        "                                                          ",
        "  h / ?            toggle this help (sampling continues)  ",
        "  q                quit from main view                    ",
        "  Tab              switch focus: devices <-> processes    ",
        "  Up / Down, j / k move cursor / scroll list (focused)    ",
        "  PageUp/PageDown  page up / page down (focused)          ",
        "  Home / End       jump to first / last row (focused)     ",
        "  Left / Right     scroll command lines (process focus)   ",
        "  mouse click on   OPS / %MEM / %CPU header: sort by that ",
        "    %MEM %CPU OPS  column (desc first, click again flips) ",
        "  s / S            cycle sort: OPS -> %MEM -> %CPU (desc) ",
        "  /                reverse current sort direction         ",
        "  Enter            open detail page of selected process   ",
        "  Esc              back / clear selection / quit          ",
        "                                                          ",
        "  press h / ? or Esc to close this help                   ",
    };
    int n = (int)(sizeof(lines) / sizeof(lines[0]));
    int top = std::max(0, (rows_ - n) / 2);
    for (int i = 0; i < n; i++) {
        attron(COLOR_PAIR(1));
        mvprintw(top + i, 2, "%s", lines[i]);
        attroff(COLOR_PAIR(1));
    }
    refresh();
}

void TuiApp::render_detail()
{
    const ProcStat *p = nullptr;
    for (auto &row : proc_rows_) {
        if (row.pid == detail_pid_) {
            p = &row;
            break;
        }
    }
    attron(A_BOLD);
    mvprintw(0, 0, "Process Detail");
    attroff(A_BOLD);
    if (!p) {
        mvprintw(2, 2, "process %u has exited; press Esc to go back", detail_pid_);
        refresh();
        return;
    }
    char num[16];
    int y = 2;
    mvprintw(y++, 2, "PID      : %u", p->pid);
    mvprintw(y++, 2, "PPID     : %u", p->ppid);
    snprintf(num, sizeof(num), "%llu", (unsigned long long)p->uid);
    mvprintw(y++, 2, "UID      : %s", num);
    mvprintw(y++, 2, "COMMAND  : %s", p->cmd.c_str());
    snprintf(num, sizeof(num), "%.1f / %.1f",
             usage_of(p->pid).cpu, usage_of(p->pid).mem);
    mvprintw(y++, 2, "CPU/MEM%% : %s", num);
    y++;
    attron(A_BOLD | COLOR_PAIR(1));
    mvprintw(y++, 2, "per monitored file ops:");
    attroff(A_BOLD | COLOR_PAIR(1));
    if (p->per_file) {
        for (const auto &kv : *p->per_file) {
            mvprintw(y++, 4, "%-40s %8s", trim_to_width(kv.first, 40).c_str(),
                     fmt_uint64(kv.second).c_str());
        }
    }
    y++;
    mvprintw(y, 2, "press Esc or Enter to go back");
    refresh();
}

// ---------------------------------------------------------------------------
// sorting controls
// ---------------------------------------------------------------------------

// s / S: cycle OPS -> %MEM -> %CPU (spec order), resetting to descending.
void TuiApp::cycle_sort()
{
    switch (sort_col_) {
        case SortColumn::Ops:
            sort_col_ = SortColumn::Mem;
            break;
        case SortColumn::Mem:
            sort_col_ = SortColumn::Cpu;
            break;
        case SortColumn::Cpu:
        default:
            sort_col_ = SortColumn::Ops;
            break;
    }
    sort_desc_ = true;
    sort_rows();
    clamp_cursors();
}

// '/': reverse the current sort direction.
void TuiApp::reverse_sort()
{
    sort_desc_ = !sort_desc_;
    sort_rows();
    clamp_cursors();
}

// Header click: switch to that column descending by default; clicking
// the active column again flips the direction.
void TuiApp::set_sort_column(SortColumn col)
{
    if (sort_col_ == col) {
        sort_desc_ = !sort_desc_;
    } else {
        sort_col_ = col;
        sort_desc_ = true;
    }
    sort_rows();
    clamp_cursors();
}

static SortColumn column_to_sort(const char *title)
{
    if (strcmp(title, "OPS") == 0) return SortColumn::Ops;
    if (strcmp(title, "%MEM") == 0) return SortColumn::Mem;
    if (strcmp(title, "%CPU") == 0) return SortColumn::Cpu;
    return SortColumn::Ops;
}

// ---------------------------------------------------------------------------
// mouse
// ---------------------------------------------------------------------------

void TuiApp::handle_mouse(const MouseEvent &ev)
{
    int mx = ev.x, my = ev.y;

    // header row: sortable column click sorts
    if (page_ == Page::Main && my == proc_header_y_) {
        for (int i = 0; i < kNumCols; i++) {
            if (mx >= col_x_[i] && mx < col_x_[i] + col_w_[i]) {
                const char *title = kColumns[i].title;
                if (strcmp(title, "OPS") == 0 || strcmp(title, "%MEM") == 0 ||
                    strcmp(title, "%CPU") == 0) {
                    set_sort_column(column_to_sort(title));
                }
                return;
            }
        }
        return;
    }

    if (page_ != Page::Main) {
        return;
    }

    // process row click selects; click below the table (footer/blank)
    // clears the selection
    int row = my - proc_top_ - 1;    // -1 for column header
    // only proc_height_ - 1 rows are drawn (last panel line is the
    // separator), matching render_procs and clamp_cursors
    if (row >= 0 && row < proc_height_ - 1) {
        int idx = proc_scroll_ + row;
        if (idx < (int)proc_rows_.size()) {
            proc_cursor_ = idx;
            selected_pid_ = proc_rows_[idx].pid;
            selection_active_ = true;
        } else {
            // Clicking an empty row inside the panel (e.g. the table has
            // fewer rows than fit on screen) must clear the selection just
            // like a click below the table. Returning here without clearing
            // left a stale selection pointing at a process the user did not
            // click.
            selection_active_ = false;
            selected_pid_ = 0;
        }
        return;
    }
    selection_active_ = false;
    selected_pid_ = 0;
}


void TuiApp::move_proc_cursor(int delta)
{
    if (proc_rows_.empty()) {
        return;
    }
    selection_active_ = true;
    proc_cursor_ += delta;
    if (proc_cursor_ < 0) {
        proc_cursor_ = 0;
    }
    if (proc_cursor_ >= (int)proc_rows_.size()) {
        proc_cursor_ = (int)proc_rows_.size() - 1;
    }
    // record the pid of the NEW row: recording it before the move would
    // anchor the selection on the previous row and every refresh would
    // relocate the cursor back there, cancelling the key press
    selected_pid_ = proc_rows_[proc_cursor_].pid;
    clamp_cursors();
}

// One-line move of the FOCUSED list. Devices have no selection cursor, so
// moving there means scrolling the list, exactly like PageUp/PageDown do
// through scroll_list(); the process panel moves its cursor. Keeping both
// paths on the same focus dispatch is what stops the arrow keys from
// silently moving the unfocused list.
void TuiApp::move_cursor(int delta)
{
    if (focus_ == Focus::Devices) {
        scroll_list(delta);
    } else {
        move_proc_cursor(delta);
    }
}

// Scroll the focused list by delta lines (devices when device-focused,
// processes otherwise).
void TuiApp::scroll_list(int delta)
{
    if (focus_ == Focus::Devices) {
        int n = (int)snap_.devices.size();
        int visible = dev_height_ - DEV_HEADER - 1;
        if (visible <= 0) {
            return;
        }
        device_scroll_ += delta;
        if (device_scroll_ > n - visible) {
            device_scroll_ = n - visible;
        }
        if (device_scroll_ < 0) {
            device_scroll_ = 0;
        }
    } else {
        move_proc_cursor(delta);
    }
}

void TuiApp::open_detail()
{
    if (focus_ != Focus::Procs || proc_rows_.empty() ||
        proc_cursor_ >= (int)proc_rows_.size()) {
        return;
    }
    detail_pid_ = proc_rows_[proc_cursor_].pid;
    page_ = Page::Detail;
}

// Esc semantics: help/detail go back; in the main view first clear the
// selection, and quit only when nothing is selected.
void TuiApp::escape()
{
    switch (page_) {
        case Page::Help:
        case Page::Detail:
            page_ = Page::Main;
            break;
        case Page::Main:
        default:
            if (selection_active_) {
                selection_active_ = false;
                selected_pid_ = 0;
            } else {
                running_ = false;
            }
            break;
    }
}

void TuiApp::handle_key(int ch)
{
    // Help / detail pages: limited keys, sampling keeps running.
    if (page_ == Page::Help) {
        switch (ch) {
            case 'h':
            case '?':
            case 27:            // Esc
            case 'q':
                page_ = Page::Main;
                break;
            default:
                break;
        }
        return;
    }
    if (page_ == Page::Detail) {
        switch (ch) {
            case 27:            // Esc
            case '\n':
            case '\r':
            case KEY_ENTER:
                page_ = Page::Main;
                break;
            default:
                break;
        }
        return;
    }

    switch (ch) {
        case 'q':
        case 'Q':
            running_ = false;
            break;
        case 'h':
        case '?':
            page_ = Page::Help;
            break;
        case '\t':
            focus_ = focus_ == Focus::Procs ? Focus::Devices : Focus::Procs;
            break;
        case KEY_UP:
        case 'k':
            move_cursor(-1);
            break;
        case KEY_DOWN:
        case 'j':
            move_cursor(1);
            break;
        case KEY_PPAGE:
            if (focus_ == Focus::Devices) {
                scroll_list(-std::max(dev_height_ - DEV_HEADER - 1, 1));
            } else {
                scroll_list(-std::max(proc_height_ - 1, 1));
            }
            break;
        case KEY_NPAGE:
            if (focus_ == Focus::Devices) {
                scroll_list(std::max(dev_height_ - DEV_HEADER - 1, 1));
            } else {
                scroll_list(std::max(proc_height_ - 1, 1));
            }
            break;
        case KEY_HOME:
            if (focus_ == Focus::Devices) {
                device_scroll_ = 0;
            } else if (!proc_rows_.empty()) {
                proc_cursor_ = 0;
                // keep the pid anchor in sync, or the next refresh would
                // relocate the cursor back to the previously selected row
                selection_active_ = true;
                selected_pid_ = proc_rows_[proc_cursor_].pid;
                clamp_cursors();
            }
            break;
        case KEY_END:
            if (focus_ == Focus::Devices) {
                int n = (int)snap_.devices.size();
                int visible = dev_height_ - DEV_HEADER - 1;
                device_scroll_ = visible > 0 ? std::max(n - visible, 0) : 0;
            } else if (!proc_rows_.empty()) {
                proc_cursor_ = (int)proc_rows_.size() - 1;
                // keep the pid anchor in sync (see KEY_HOME)
                selection_active_ = true;
                selected_pid_ = proc_rows_[proc_cursor_].pid;
                clamp_cursors();
            }
            break;
        case KEY_LEFT:
            // the device panel has nothing to scroll horizontally: acting on
            // the process table while it is not focused would shift the
            // command column behind the user's back
            if (focus_ == Focus::Procs) {
                h_scroll_ -= 8;      // reveal later part of long command lines
                if (h_scroll_ < -(1 << 16)) {
                    h_scroll_ = -(1 << 16);
                }
            }
            break;
        case KEY_RIGHT:
            if (focus_ == Focus::Procs) {
                h_scroll_ += 8;
                if (h_scroll_ > 0) {
                    h_scroll_ = 0;
                }
            }
            break;
        case 's':
        case 'S':
            cycle_sort();
            break;
        case '/':
            reverse_sort();
            break;
        case '\n':
        case '\r':
        case KEY_ENTER:
            open_detail();
            break;
        case 27:                 // Esc
            escape();
            break;
        default:
            break;
    }
}
