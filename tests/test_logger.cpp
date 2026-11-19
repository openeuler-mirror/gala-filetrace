#include <cassert>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include "logger.hpp"

static std::string read_file(const std::string &path)
{
    std::ifstream ifs(path);
    return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

static std::vector<std::string> split_lines(const std::string &content)
{
    std::vector<std::string> lines;
    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

static size_t count_files_with_prefix(const std::string &dir, const std::string &prefix)
{
    size_t count = 0;
    for (const auto &entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().filename().string().rfind(prefix, 0) == 0) {
            ++count;
        }
    }
    return count;
}

static void remove_files_with_prefix(const std::string &dir, const std::string &prefix)
{
    for (const auto &entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().filename().string().rfind(prefix, 0) == 0) {
            std::filesystem::remove(entry.path());
        }
    }
}

static bool is_digits(const std::string &s, size_t pos, size_t len)
{
    if (pos + len > s.size()) return false;
    for (size_t i = 0; i < len; ++i) {
        if (!std::isdigit(static_cast<unsigned char>(s[pos + i]))) return false;
    }
    return true;
}

// Validate "YYYY-MM-DDTHH:MM:SS" prefix produced by now_iso8601()
static bool has_valid_iso8601_prefix(const std::string &line)
{
    if (line.size() < 19) return false;
    if (!is_digits(line, 0, 4) || line[4] != '-' ||
        !is_digits(line, 5, 2) || line[7] != '-' ||
        !is_digits(line, 8, 2) || line[10] != 'T' ||
        !is_digits(line, 11, 2) || line[13] != ':' ||
        !is_digits(line, 14, 2) || line[16] != ':' ||
        !is_digits(line, 17, 2)) {
        return false;
    }
    int month = std::stoi(line.substr(5, 2));
    int day   = std::stoi(line.substr(8, 2));
    int hour  = std::stoi(line.substr(11, 2));
    int min   = std::stoi(line.substr(14, 2));
    int sec   = std::stoi(line.substr(17, 2));
    return month >= 1 && month <= 12 &&
           day >= 1 && day <= 31 &&
           hour >= 0 && hour <= 23 &&
           min >= 0 && min <= 59 &&
           sec >= 0 && sec <= 60;
}

static void verify_log_line(const std::string &line,
                            const std::string &expected_level,
                            const std::string &expected_file,
                            int expected_line,
                            const std::string &expected_msg)
{
    assert(has_valid_iso8601_prefix(line));
    const std::string expected_suffix =
        " [" + expected_level + "] " + expected_file + ":" + std::to_string(expected_line) + " " + expected_msg;
    assert(line.substr(19) == expected_suffix);
}

static void verify_log_line_structure(const std::string &line,
                                      const std::string &expected_level,
                                      const std::string &expected_file,
                                      const std::string &msg_prefix)
{
    assert(has_valid_iso8601_prefix(line));
    const std::string tag_prefix = " [" + expected_level + "] " + expected_file + ":";
    assert(line.compare(19, tag_prefix.size(), tag_prefix) == 0);
    size_t pos = 19 + tag_prefix.size();
    size_t digit_start = pos;
    while (pos < line.size() && std::isdigit(static_cast<unsigned char>(line[pos]))) {
        ++pos;
    }
    assert(pos > digit_start);
    assert(pos < line.size() && line[pos] == ' ');
    assert(line.compare(pos + 1, msg_prefix.size(), msg_prefix) == 0);
}

struct CerrCapture {
    std::ostringstream oss;
    std::streambuf *old_buf;

    CerrCapture() : old_buf(std::cerr.rdbuf(oss.rdbuf())) {}
    ~CerrCapture() { std::cerr.rdbuf(old_buf); }

    std::string str() const { return oss.str(); }
};

// Must run before any Logger::init call so g_log_ofs is still closed.
static void test_uninitialized_fallback_to_cerr()
{
    std::string captured;
    int info_line = 0, warn_line = 0, error_line = 0;
    {
        CerrCapture cap;
        LOG_INFO("uninit info");   info_line  = __LINE__;
        LOG_WARN("uninit warn");   warn_line  = __LINE__;
        LOG_ERROR("uninit error"); error_line = __LINE__;
        LOG_DEBUG("uninit debug"); // default threshold is INFO, must be filtered
        captured = cap.str();
    }

    auto lines = split_lines(captured);
    assert(lines.size() == 3);
    verify_log_line(lines[0], "INFO",  "test_logger.cpp", info_line,  "uninit info");
    verify_log_line(lines[1], "WARN",  "test_logger.cpp", warn_line,  "uninit warn");
    verify_log_line(lines[2], "ERROR", "test_logger.cpp", error_line, "uninit error");
    assert(captured.find("uninit debug") == std::string::npos);

    std::cout << "  PASS: uninitialized logger falls back to std::cerr" << std::endl;
}

static void test_basic_init_and_reinit()
{
    const std::string path = "/tmp/gala_test_logger.log";
    unlink(path.c_str());

    // init with info level
    Logger::init(path, "info", 1024);
    LOG_INFO("unit test info1");
    LOG_DEBUG("unit test debug1");

    {
        std::string content = read_file(path);
        assert(content.find("INFO") != std::string::npos);
        // debug should be filtered at info level
        assert(content.find("DEBUG") == std::string::npos);
    }

    // re-init with debug level and ensure DEBUG appears
    Logger::init(path, "debug", 1024);
    LOG_DEBUG("unit test debug2");
    {
        std::string content = read_file(path);
        assert(content.find("DEBUG") != std::string::npos);
    }

    unlink(path.c_str());
    std::cout << "  PASS: basic init and re-init level change" << std::endl;
}

static void test_level_parsing_matrix()
{
    const std::string path = "/tmp/gala_test_logger.log";

    // Level filtering matrix: a message is written only when its severity
    // rank meets or exceeds the configured threshold. Empty or invalid level
    // names fall back to info.
    struct LevelCase {
        const char *cfg;
        const char *tag;
        bool exp_info, exp_warn, exp_error, exp_debug;
    };
    const LevelCase cases[] = {
        {"info",  "info_lower",  true,  true,  true,  false},
        {"INFO",  "info_upper",  true,  true,  true,  false},
        {"Info",  "info_title",  true,  true,  true,  false},
        {"warn",  "warn_lower",  false, true,  true,  false},
        {"WARN",  "warn_upper",  false, true,  true,  false},
        {"Warn",  "warn_title",  false, true,  true,  false},
        {"error", "error_lower", false, false, true,  false},
        {"ERROR", "error_upper", false, false, true,  false},
        {"Error", "error_title", false, false, true,  false},
        {"debug", "debug_lower", true,  true,  true,  true},
        {"DEBUG", "debug_upper", true,  true,  true,  true},
        {"Debug", "debug_title", true,  true,  true,  true},
        {"",      "empty",       true,  true,  true,  false},
        {"bogus", "bogus",       true,  true,  true,  false},
    };
    for (const auto &c : cases) {
        unlink(path.c_str());
        Logger::init(path, c.cfg, 0);
        LOG_INFO("m_info_" + std::string(c.tag));
        LOG_WARN("m_warn_" + std::string(c.tag));
        LOG_ERROR("m_error_" + std::string(c.tag));
        LOG_DEBUG("m_debug_" + std::string(c.tag));
        std::string content = read_file(path);
        assert((content.find(std::string("m_info_")  + c.tag) != std::string::npos) == c.exp_info);
        assert((content.find(std::string("m_warn_")  + c.tag) != std::string::npos) == c.exp_warn);
        assert((content.find(std::string("m_error_") + c.tag) != std::string::npos) == c.exp_error);
        assert((content.find(std::string("m_debug_") + c.tag) != std::string::npos) == c.exp_debug);
    }

    unlink(path.c_str());
    std::cout << "  PASS: case-variant and fallback level parsing matrix" << std::endl;
}

static void test_direct_methods_basename_and_format()
{
    const std::string path = "/tmp/gala_test_logger_direct.log";
    unlink(path.c_str());

    Logger::init(path, "debug", 0);
    int l_info  = __LINE__; Logger::info("direct info msg", __FILE__, __LINE__);
    int l_warn  = __LINE__; Logger::warn("direct warn msg", __FILE__, __LINE__);
    int l_error = __LINE__; Logger::error("direct error msg", __FILE__, __LINE__);
    int l_debug = __LINE__; Logger::debug("direct debug msg", __FILE__, __LINE__);

    // basename_of_path branches: nullptr -> "unknown", no '/', and nested '/'
    Logger::info("null path msg", nullptr, 42);
    Logger::warn("plain path msg", "standalone.cpp", 77);
    Logger::error("nested path msg", "/a/b/c/deep_caller.cpp", 99);

    auto lines = split_lines(read_file(path));
    assert(lines.size() == 7);
    verify_log_line(lines[0], "INFO",  "test_logger.cpp",  l_info,  "direct info msg");
    verify_log_line(lines[1], "WARN",  "test_logger.cpp",  l_warn,  "direct warn msg");
    verify_log_line(lines[2], "ERROR", "test_logger.cpp",  l_error, "direct error msg");
    verify_log_line(lines[3], "DEBUG", "test_logger.cpp",  l_debug, "direct debug msg");
    verify_log_line(lines[4], "INFO",  "unknown",          42,      "null path msg");
    verify_log_line(lines[5], "WARN",  "standalone.cpp",   77,      "plain path msg");
    verify_log_line(lines[6], "ERROR", "deep_caller.cpp",  99,      "nested path msg");

    // Verify severity filtering also applies to direct helper methods
    unlink(path.c_str());
    Logger::init(path, "warn", 0);
    Logger::debug("filtered debug", __FILE__, __LINE__);
    Logger::info("filtered info", __FILE__, __LINE__);
    int l_kept_warn  = __LINE__; Logger::warn("kept warn", __FILE__, __LINE__);
    int l_kept_error = __LINE__; Logger::error("kept error", __FILE__, __LINE__);

    lines = split_lines(read_file(path));
    assert(lines.size() == 2);
    verify_log_line(lines[0], "WARN",  "test_logger.cpp", l_kept_warn,  "kept warn");
    verify_log_line(lines[1], "ERROR", "test_logger.cpp", l_kept_error, "kept error");

    unlink(path.c_str());
    std::cout << "  PASS: direct Logger methods, basename_of_path, and line format" << std::endl;
}

static void test_init_creates_single_level_dir()
{
    const std::string dir = "/tmp/gala_test_logger_dir_" + std::to_string(getpid());
    const std::string path = dir + "/sub.log";
    std::filesystem::remove_all(dir);
    assert(!std::filesystem::exists(dir));

    Logger::init(path, "info", 0);
    assert(std::filesystem::is_directory(dir));

    LOG_INFO("created dir msg"); int line_no = __LINE__;
    auto lines = split_lines(read_file(path));
    assert(lines.size() == 1);
    verify_log_line(lines[0], "INFO", "test_logger.cpp", line_no, "created dir msg");

    std::filesystem::remove_all(dir);
    std::cout << "  PASS: init creates missing single-level parent directory" << std::endl;
}

static void test_init_no_slash_path()
{
    const std::string rel_path = "gala_test_noslash_" + std::to_string(getpid()) + ".log";
    unlink(rel_path.c_str());

    Logger::init(rel_path, "info", 0);
    LOG_INFO("no slash path msg"); int line_no = __LINE__;

    auto lines = split_lines(read_file(rel_path));
    assert(lines.size() == 1);
    verify_log_line(lines[0], "INFO", "test_logger.cpp", line_no, "no slash path msg");

    unlink(rel_path.c_str());
    std::cout << "  PASS: init handles filepath without '/'" << std::endl;
}

static void test_open_failure_fallback_to_cerr()
{
    const std::string prev_path = "/tmp/gala_test_logger.log";
    unlink(prev_path.c_str());

    Logger::init(prev_path, "info", 0);
    LOG_INFO("before open failure");
    const std::string before_content = read_file(prev_path);

    // Multi-level missing parent guarantees mkdir and open() fail even as root.
    const std::string bad_path = "/tmp/gala_missing_parent_" + std::to_string(getpid()) + "/nested/fail.log";
    std::string init_err;
    {
        CerrCapture cap;
        Logger::init(bad_path, "info", 0);
        init_err = cap.str();
    }
    assert(init_err.find("failed to open log file") != std::string::npos);

    // Previous log file must be closed and untouched; logs fall back to std::cerr.
    std::string log_err;
    int fallback_line = 0;
    {
        CerrCapture cap;
        LOG_INFO("open fail fallback info"); fallback_line = __LINE__;
        LOG_DEBUG("open fail fallback debug"); // filtered by info level
        log_err = cap.str();
    }
    auto lines = split_lines(log_err);
    assert(lines.size() == 1);
    verify_log_line(lines[0], "INFO", "test_logger.cpp", fallback_line, "open fail fallback info");
    assert(read_file(prev_path) == before_content);

    // Opening an existing directory as filepath also fails open() even as root.
    {
        CerrCapture cap;
        Logger::init("/tmp", "warn", 0);
        assert(cap.str().find("failed to open log file") != std::string::npos);
    }
    {
        CerrCapture cap;
        LOG_WARN("dir open fail warn"); int warn_line = __LINE__;
        LOG_INFO("dir open fail info"); // filtered by warn level
        auto dir_lines = split_lines(cap.str());
        assert(dir_lines.size() == 1);
        verify_log_line(dir_lines[0], "WARN", "test_logger.cpp", warn_line, "dir open fail warn");
    }

    unlink(prev_path.c_str());
    std::cout << "  PASS: file open failure falls back to std::cerr" << std::endl;
}

static void test_rotation_and_cleanup()
{
    // Rotation: once the file reaches max_size it is renamed to a
    // timestamped backup and a fresh file is created.
    const std::string rpath = "/tmp/gala_test_rotate.log";
    unlink(rpath.c_str());
    remove_files_with_prefix("/tmp", "gala_test_rotate.log.");

    Logger::init(rpath, "debug", 100);
    for (int i = 0; i < 12; ++i) {
        LOG_INFO("rotation test line " + std::to_string(i) + " padding padding");
    }
    size_t backups = count_files_with_prefix("/tmp", "gala_test_rotate.log.");
    // Each rotation must produce its own backup. With many small writes
    // several rotations land in the same second; a second-only timestamp
    // would overwrite earlier backups and lose log history.
    assert(backups >= 2);
    // a fresh file must have been created and hold the most recent line
    std::string content = read_file(rpath);
    assert(content.find("rotation test line 11") != std::string::npos);

    unlink(rpath.c_str());
    remove_files_with_prefix("/tmp", "gala_test_rotate.log.");
    std::cout << "  PASS: log rotation and cleanup" << std::endl;
}

static void test_max_size_zero_disables_rotation()
{
    const std::string nrpath = "/tmp/gala_test_norotate.log";
    unlink(nrpath.c_str());
    remove_files_with_prefix("/tmp", "gala_test_norotate.log.");

    Logger::init(nrpath, "debug", 0);
    const std::string padding(80, 'x');
    for (int i = 0; i < 60; ++i) {
        LOG_INFO("no rotate line " + std::to_string(i) + " " + padding);
    }

    assert(count_files_with_prefix("/tmp", "gala_test_norotate.log.") == 0);
    auto lines = split_lines(read_file(nrpath));
    assert(lines.size() == 60);
    assert(lines.front().find("no rotate line 0 ") != std::string::npos);
    assert(lines.back().find("no rotate line 59 ") != std::string::npos);

    unlink(nrpath.c_str());
    std::cout << "  PASS: max_size == 0 disables log rotation" << std::endl;
}

static void test_multithreaded_concurrent_writes_and_rotation()
{
    // Part A: concurrent writes with rotation disabled -> zero lost or torn lines
    const std::string mt_path = "/tmp/gala_test_mt_write.log";
    unlink(mt_path.c_str());
    remove_files_with_prefix("/tmp", "gala_test_mt_write.log.");

    const int num_threads = 8;
    const int msgs_per_thread = 50;
    Logger::init(mt_path, "debug", 0);

    std::vector<std::thread> writers;
    for (int t = 0; t < num_threads; ++t) {
        writers.emplace_back([t]() {
            for (int i = 0; i < msgs_per_thread; ++i) {
                LOG_INFO("mt_write_t" + std::to_string(t) + "_i" + std::to_string(i));
            }
        });
    }
    for (auto &w : writers) {
        w.join();
    }

    std::string all_content = read_file(mt_path);
    auto lines = split_lines(all_content);
    assert(lines.size() == static_cast<size_t>(num_threads * msgs_per_thread));
    for (const auto &line : lines) {
        verify_log_line_structure(line, "INFO", "test_logger.cpp", "mt_write_t");
    }
    for (int t = 0; t < num_threads; ++t) {
        for (int i = 0; i < msgs_per_thread; ++i) {
            const std::string marker = "mt_write_t" + std::to_string(t) + "_i" + std::to_string(i) + "\n";
            assert(all_content.find(marker) != std::string::npos);
        }
    }
    unlink(mt_path.c_str());

    // Part B: concurrent writes with aggressive rotation -> no deadlock, crash, or torn lines
    const std::string mt_rot_path = "/tmp/gala_test_mt_rotate.log";
    unlink(mt_rot_path.c_str());
    remove_files_with_prefix("/tmp", "gala_test_mt_rotate.log.");

    const int rot_threads = 6;
    const int rot_msgs = 50;
    Logger::init(mt_rot_path, "debug", 256);

    std::vector<std::thread> rot_writers;
    for (int t = 0; t < rot_threads; ++t) {
        rot_writers.emplace_back([t]() {
            for (int i = 0; i < rot_msgs; ++i) {
                LOG_DEBUG("mt_rot_t" + std::to_string(t) + "_i" + std::to_string(i) + " padding_padding_padding");
            }
        });
    }
    for (auto &w : rot_writers) {
        w.join();
    }

    assert(count_files_with_prefix("/tmp", "gala_test_mt_rotate.log.") >= 1);
    auto check_file_lines = [](const std::string &fpath) {
        auto flines = split_lines(read_file(fpath));
        assert(!flines.empty());
        for (const auto &line : flines) {
            verify_log_line_structure(line, "DEBUG", "test_logger.cpp", "mt_rot_t");
        }
    };
    check_file_lines(mt_rot_path);
    for (const auto &entry : std::filesystem::directory_iterator("/tmp")) {
        if (entry.path().filename().string().rfind("gala_test_mt_rotate.log.", 0) == 0) {
            check_file_lines(entry.path().string());
        }
    }

    unlink(mt_rot_path.c_str());
    remove_files_with_prefix("/tmp", "gala_test_mt_rotate.log.");
    std::cout << "  PASS: multi-threaded concurrent writes and rotation safety" << std::endl;
}

int main()
{
    std::cout << "Running Logger unit tests..." << std::endl;

    test_uninitialized_fallback_to_cerr();
    test_basic_init_and_reinit();
    test_level_parsing_matrix();
    test_direct_methods_basename_and_format();
    test_init_creates_single_level_dir();
    test_init_no_slash_path();
    test_open_failure_fallback_to_cerr();
    test_rotation_and_cleanup();
    test_max_size_zero_disables_rotation();
    test_multithreaded_concurrent_writes_and_rotation();

    std::cout << "Logger unit tests passed." << std::endl;
    return 0;
}
