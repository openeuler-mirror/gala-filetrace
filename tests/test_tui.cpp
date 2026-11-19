// ******************************************************************************
// Copyright (c) Huawei Technologies Co., Ltd. 2021-2023. All rights reserved.
// licensed under the Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//     http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
// PURPOSE.
// See the Mulan PSL v2 for more details.
// ******************************************************************************/
// Unit tests for the TuiApp logic that is independent of ncurses rendering:
// the constructor's interval clamp, the sampling tick, cursor/selection
// bookkeeping, sorting and the /proc usage reader. Private members are
// opened up at include time (access specifiers do not change the layout
// here: all data members live in one contiguous private block) so the
// helpers can be driven directly; tui.o itself is compiled unmodified.

#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <unistd.h>

#define private public
#include "tui.hpp"
#undef private

static const double TEST_TOTAL_MEM_KB = 1024.0 * 1024.0;  // 1 GiB

static void test_constructor_should_clamp_refresh_ms()
{
    TraceStats stats({"/etc/hosts"});

    TuiOptions low;
    low.refresh_ms = MIN_REFRESH_MS - 1;
    TuiApp low_app(stats, low);
    assert(low_app.refresh_ms() == MIN_REFRESH_MS);

    TuiOptions high;
    high.refresh_ms = MAX_REFRESH_MS + 1;
    TuiApp high_app(stats, high);
    assert(high_app.refresh_ms() == MAX_REFRESH_MS);

    TuiOptions ok;
    ok.refresh_ms = 1500;
    TuiApp ok_app(stats, ok);
    assert(ok_app.refresh_ms() == 1500);
    std::cout << "test_constructor_should_clamp_refresh_ms passed" << std::endl;
}

static void test_request_stop_should_clear_running()
{
    TraceStats stats({"/etc/hosts"});
    TuiOptions opts;
    TuiApp app(stats, opts);

    assert(app.running_.load());
    app.request_stop();
    assert(!app.running_.load());
    std::cout << "test_request_stop_should_clear_running passed" << std::endl;
}

static void test_sample_once_should_populate_rows_and_usage()
{
    unsigned int self_pid = getpid();
    TraceStats stats({"/etc/hosts"});

    event ev;
    memset(&ev, 0, sizeof(ev));
    ev.pid = self_pid;
    ev.ppid = 1;
    ev.uid = 0;
    snprintf(ev.cmd, sizeof(ev.cmd), "test_tui");
    strncpy(ev.filename, "/etc/hosts", sizeof(ev.filename) - 1);
    ev.flag = SYS_openat;
    stats.on_event(ev, "/etc/hosts");

    TuiOptions opts;
    TuiApp app(stats, opts);
    app.sample_once();

    assert(app.proc_rows_.size() == 1);
    assert(app.proc_rows_[0].pid == self_pid);
    assert(app.usage_.find(self_pid) != app.usage_.end());

    ProcUsage u = app.usage_of(self_pid);
    assert(std::isfinite(u.cpu) && u.cpu >= 0.0);
    assert(std::isfinite(u.mem) && u.mem >= 0.0 && u.mem <= 100.0);
    std::cout << "test_sample_once_should_populate_rows_and_usage passed" << std::endl;
}

static void test_sample_once_should_clamp_device_scroll()
{
    // A single configured path: the device panel has one row. Simulate a
    // scroll offset left over from a previously larger table/window.
    TraceStats stats({"/dev0"});
    event ev;
    memset(&ev, 0, sizeof(ev));
    ev.pid = 12345;
    ev.flag = SYS_write;
    strncpy(ev.filename, "f", sizeof(ev.filename) - 1);
    stats.on_event(ev, "/dev0");

    TuiOptions opts;
    TuiApp app(stats, opts);
    app.dev_height_ = 12;               // tall panel, few device rows
    app.device_scroll_ = 50;            // stale offset past the end
    app.sample_once();

    int visible = app.dev_height_ - 2 - 1;  // DEV_HEADER=2
    int max_scroll = (int)app.snap_.devices.size() - visible;
    if (max_scroll < 0) {
        max_scroll = 0;
    }
    assert(app.device_scroll_ <= max_scroll);
    assert(app.device_scroll_ >= 0);
    std::cout << "test_sample_once_should_clamp_device_scroll passed" << std::endl;
}

static void test_usage_of_should_not_insert_missing_pid()
{
    TraceStats stats({"/etc/hosts"});
    TuiOptions opts;
    TuiApp app(stats, opts);

    ProcUsage u = app.usage_of(424242);
    assert(u.cpu == 0.0 && u.mem == 0.0);
    assert(app.usage_.find(424242) == app.usage_.end());
    std::cout << "test_usage_of_should_not_insert_missing_pid passed" << std::endl;
}

static TraceStats *make_stats_with_procs()
{
    // fresh heap instance so each test owns its event history
    static TraceStats *stats = nullptr;
    delete stats;
    stats = new TraceStats({"/etc/hosts"});
    struct {
        unsigned int pid;
        uint64_t ops;
    } procs[] = {
        {100, 1},
        {200, 3},
        {300, 2},
    };
    for (const auto &p : procs) {
        event ev;
        memset(&ev, 0, sizeof(ev));
        ev.pid = p.pid;
        ev.ppid = 1;
        ev.uid = 0;
        snprintf(ev.cmd, sizeof(ev.cmd), "proc%u", p.pid);
        strncpy(ev.filename, "/etc/hosts", sizeof(ev.filename) - 1);
        ev.flag = SYS_openat;
        for (uint64_t i = 0; i < p.ops; i++) {
            stats->on_event(ev, "/etc/hosts");
        }
    }
    return stats;
}

static void test_sample_once_should_sort_rows_by_ops_desc()
{
    TraceStats &stats = *make_stats_with_procs();
    TuiOptions opts;
    TuiApp app(stats, opts);

    app.sample_once();

    assert(app.proc_rows_.size() == 3);
    assert(app.proc_rows_[0].pid == 200);
    assert(app.proc_rows_[1].pid == 300);
    assert(app.proc_rows_[2].pid == 100);
    std::cout << "test_sample_once_should_sort_rows_by_ops_desc passed" << std::endl;
}

static void test_move_proc_cursor_should_track_row_pid_and_clamp()
{
    TraceStats &stats = *make_stats_with_procs();
    TuiOptions opts;
    TuiApp app(stats, opts);
    app.sample_once();

    // rows are ordered 200, 300, 100 by ops desc
    app.move_proc_cursor(1);
    assert(app.proc_cursor_ == 1);
    assert(app.selection_active_);
    assert(app.selected_pid_ == app.proc_rows_[1].pid);

    app.move_proc_cursor(100);
    assert(app.proc_cursor_ == 2);
    assert(app.selected_pid_ == app.proc_rows_[2].pid);

    app.move_proc_cursor(-100);
    assert(app.proc_cursor_ == 0);
    assert(app.selected_pid_ == app.proc_rows_[0].pid);

    // moving on an empty table must not enable the selection
    TuiApp empty_app(stats, opts);
    empty_app.sample_once();
    empty_app.proc_rows_.clear();
    empty_app.move_proc_cursor(1);
    assert(!empty_app.selection_active_);
    assert(empty_app.proc_cursor_ == 0);
    std::cout << "test_move_proc_cursor_should_track_row_pid_and_clamp passed" << std::endl;
}

static void test_sample_once_should_relocate_selection_after_resort()
{
    TraceStats &stats = *make_stats_with_procs();
    TuiOptions opts;
    TuiApp app(stats, opts);
    app.sample_once();

    // select the top row (pid 200), then make pid 100 the heaviest one
    app.move_proc_cursor(0);
    assert(app.selected_pid_ == 200);

    event ev;
    memset(&ev, 0, sizeof(ev));
    ev.pid = 100;
    ev.ppid = 1;
    ev.uid = 0;
    snprintf(ev.cmd, sizeof(ev.cmd), "proc%u", 100u);
    strncpy(ev.filename, "/etc/hosts", sizeof(ev.filename) - 1);
    ev.flag = SYS_openat;
    for (int i = 0; i < 10; i++) {
        stats.on_event(ev, "/etc/hosts");
    }

    app.sample_once();
    assert(app.selection_active_);
    assert(app.selected_pid_ == 200);
    assert(app.proc_rows_[app.proc_cursor_].pid == 200);
    std::cout << "test_sample_once_should_relocate_selection_after_resort passed" << std::endl;
}

static void test_set_sort_column_and_reverse_should_reorder_rows()
{
    TraceStats &stats = *make_stats_with_procs();
    TuiOptions opts;
    TuiApp app(stats, opts);
    app.sample_once();

    app.set_sort_column(SortColumn::Pid);
    assert(app.sort_col_ == SortColumn::Pid);
    assert(app.sort_desc_);
    assert(app.proc_rows_[0].pid == 300);

    app.reverse_sort();
    assert(!app.sort_desc_);
    assert(app.proc_rows_[0].pid == 100);

    // clicking the active column again flips the direction
    app.set_sort_column(SortColumn::Pid);
    assert(app.sort_desc_);
    assert(app.proc_rows_[0].pid == 300);
    std::cout << "test_set_sort_column_and_reverse_should_reorder_rows passed" << std::endl;
}

static void test_cycle_sort_should_walk_columns()
{
    TraceStats &stats = *make_stats_with_procs();
    TuiOptions opts;
    TuiApp app(stats, opts);

    assert(app.sort_col_ == SortColumn::Ops);
    app.cycle_sort();
    assert(app.sort_col_ == SortColumn::Mem);
    app.cycle_sort();
    assert(app.sort_col_ == SortColumn::Cpu);
    app.cycle_sort();
    assert(app.sort_col_ == SortColumn::Ops);
    assert(app.sort_desc_);
    std::cout << "test_cycle_sort_should_walk_columns passed" << std::endl;
}

static void test_read_proc_usage_should_sample_self()
{
    TraceStats stats({"/etc/hosts"});
    TuiOptions opts;
    TuiApp app(stats, opts);

    unsigned long long last_utime = 0, last_stime = 0;
    ProcUsage out;
    bool got = app.read_proc_usage(getpid(), TEST_TOTAL_MEM_KB,
                                   &last_utime, &last_stime, 100.0, false, &out);
    assert(got);
    assert(out.cpu == 0.0);  // no previous sample: %CPU is not computed yet
    assert(out.mem >= 0.0 && out.mem <= 100.0);

    unsigned long long prev_utime = last_utime, prev_stime = last_stime;
    got = app.read_proc_usage(getpid(), TEST_TOTAL_MEM_KB,
                              &last_utime, &last_stime, 100.0, true, &out);
    assert(got);
    assert(std::isfinite(out.cpu) && out.cpu >= 0.0);
    assert(last_utime >= prev_utime && last_stime >= prev_stime);
    std::cout << "test_read_proc_usage_should_sample_self passed" << std::endl;
}

static void test_read_proc_usage_should_fail_for_missing_pid()
{
    TraceStats stats({"/etc/hosts"});
    TuiOptions opts;
    TuiApp app(stats, opts);

    unsigned long long last_utime = 0, last_stime = 0;
    ProcUsage out;
    bool got = app.read_proc_usage(999999, TEST_TOTAL_MEM_KB,
                                   &last_utime, &last_stime, 100.0, false, &out);
    assert(!got);
    std::cout << "test_read_proc_usage_should_fail_for_missing_pid passed" << std::endl;
}

static void test_clamp_cursors_should_bound_cursor_and_scroll()
{
    TraceStats &stats = *make_stats_with_procs();
    TuiOptions opts;
    TuiApp app(stats, opts);
    app.sample_once();

    app.proc_cursor_ = 100;
    app.clamp_cursors();
    assert(app.proc_cursor_ == (int)app.proc_rows_.size() - 1);

    app.proc_cursor_ = -5;
    app.clamp_cursors();
    assert(app.proc_cursor_ == 0);
    std::cout << "test_clamp_cursors_should_bound_cursor_and_scroll passed" << std::endl;
}

int main()
{
    test_constructor_should_clamp_refresh_ms();
    test_request_stop_should_clear_running();
    test_sample_once_should_populate_rows_and_usage();
    test_sample_once_should_clamp_device_scroll();
    test_usage_of_should_not_insert_missing_pid();
    test_sample_once_should_sort_rows_by_ops_desc();
    test_move_proc_cursor_should_track_row_pid_and_clamp();
    test_sample_once_should_relocate_selection_after_resort();
    test_set_sort_column_and_reverse_should_reorder_rows();
    test_cycle_sort_should_walk_columns();
    test_read_proc_usage_should_sample_self();
    test_read_proc_usage_should_fail_for_missing_pid();
    test_clamp_cursors_should_bound_cursor_and_scroll();
    std::cout << "All TuiApp unit tests passed" << std::endl;
    return 0;
}
