#include "logger.hpp"
#include <fstream>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <sys/stat.h>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

static std::ofstream g_log_ofs;
static std::mutex g_log_mutex;
static Logger::Level g_log_level = Logger::INFO;
static std::string g_log_filepath;
static size_t g_max_log_size = 100 * 1024 * 1024; // default 100MB

static Logger::Level parse_level(const std::string &s) {
    if (s == "warn" || s == "WARN" || s == "Warn") return Logger::WARN;
    if (s == "error" || s == "ERROR" || s == "Error") return Logger::ERROR;
    if (s == "debug" || s == "DEBUG" || s == "Debug") return Logger::DEBUG;
    return Logger::INFO;
}

// Level enum values are not ordered by severity (DEBUG has the largest value),
// so compare explicit severity ranks when applying the configured threshold.
static int severity_rank(Logger::Level level) {
    switch (level) {
        case Logger::DEBUG: return 0;
        case Logger::INFO:  return 1;
        case Logger::WARN:  return 2;
        case Logger::ERROR: return 3;
    }
    return 1;
}

// Create (or fix up) the log file with deterministic, safe permissions.
// std::ofstream::open() creates a missing file as 0666 & ~umask, which is
// world-writable when a daemon runs with umask 0; it also follows symlinks, so
// a planted run.log symlink can redirect a root daemon's writes. Pre-creating
// with O_NOFOLLOW and an explicit 0644 mode, then fchmod()-ing the descriptor,
// closes both holes. Returning false keeps ofstream from ever opening the path.
static bool ensure_log_file(const std::string &filepath) {
    struct stat st{};
    if (lstat(filepath.c_str(), &st) == 0 && S_ISLNK(st.st_mode)) {
        return false;  // refuse to follow a symlink planted at the log path
    }
    int fd = ::open(filepath.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0644);
    if (fd < 0) {
        return false;
    }
    // Tighten the mode even when the file already existed with a loose one.
    fchmod(fd, 0644);
    close(fd);
    return true;
}

// Rotate the log file: rename current log to backup and create new one
static void rotate_log_file() {
    if (g_log_ofs.is_open()) {
        g_log_ofs.close();
    }
    
    // Create backup filename with timestamp
    time_t now = std::time(nullptr);
    struct tm tm_info{};
    localtime_r(&now, &tm_info);
    
    std::ostringstream backup_name;
    backup_name << g_log_filepath << ".";
    backup_name << std::put_time(&tm_info, "%Y%m%d_%H%M%S");
    
    // Rename current log file to backup
    if (std::rename(g_log_filepath.c_str(), backup_name.str().c_str()) != 0) {
        std::cerr << "Logger: failed to rotate log file from '" << g_log_filepath 
                  << "' to '" << backup_name.str() << "'" << std::endl;
    }
    
    // Open new log file with the same safe, deterministic permissions.
    if (ensure_log_file(g_log_filepath)) {
        g_log_ofs.open(g_log_filepath, std::ios::app);
    }
    if (!g_log_ofs.is_open()) {
        std::cerr << "Logger: failed to create new log file '" << g_log_filepath << "'" << std::endl;
    }
}

// Check if log file needs rotation
static bool should_rotate_log() {
    if (g_max_log_size == 0) {
        return false; 
    }
    
    struct stat st;
    if (stat(g_log_filepath.c_str(), &st) == 0) {
        return (size_t)st.st_size >= g_max_log_size;
    }
    return false;
}

// Create every missing component of dir, each with an explicit 0755 mode.
// mkdir(..., 0755) is used instead of std::filesystem::create_directories(),
// which applies 0777 & ~umask: with a permissive umask (0/002) the log dir
// would become world-writable, and a local user could plant a run.log symlink
// for a root daemon to follow. Keep the original 0755 boundary explicitly.
static void create_log_directories(const std::string &dir) {
    std::string current;
    size_t start = 0;
    if (!dir.empty() && dir[0] == '/') {
        current = "/";
        start = 1;
    }
    while (start <= dir.size()) {
        size_t slash = dir.find('/', start);
        std::string part = (slash == std::string::npos)
            ? dir.substr(start) : dir.substr(start, slash - start);
        if (!part.empty()) {
            if (!current.empty() && current.back() != '/') {
                current += '/';
            }
            current += part;
            if (mkdir(current.c_str(), 0755) != 0) {
                if (errno != EEXIST) {
                    return;  // open() below reports the failure
                }
                // EEXIST is not necessarily a real directory: it can be a
                // symlink. lstat() deliberately does not follow symlinks, so a
                // planted symlink component is rejected instead of granting a
                // path through the 0755 boundary. Do not chmod() an existing
                // component: it may be a system dir (e.g. /var/log) whose mode
                // is intentionally managed elsewhere.
                struct stat comp_st{};
                if (lstat(current.c_str(), &comp_st) != 0 || !S_ISDIR(comp_st.st_mode)) {
                    return;
                }
            }
        }
        if (slash == std::string::npos) {
            break;
        }
        start = slash + 1;
    }
}

void Logger::init(const std::string &filepath, const std::string &level, size_t max_size) {
    std::lock_guard<std::mutex> lk(g_log_mutex);
    g_log_level = parse_level(level);
    g_log_filepath = filepath;
    g_max_log_size = max_size;
    
    size_t pos = filepath.rfind('/');
    if (pos != std::string::npos && pos > 0) {
        std::string dir = filepath.substr(0, pos);
        struct stat st;
        if (stat(dir.c_str(), &st) != 0) {
            // A single mkdir() fails when any parent component is missing
            // (e.g. /var/log/filetrace/run.log), leaving the log file
            // unopenable and all output redirected to stderr. Create the
            // whole chain with explicit 0755 permissions instead.
            create_log_directories(dir);
        }
    }
    // Close before reopening: on libstdc++ calling open() on an already-open
    // stream leaves failbit set, and every later write is silently dropped.
    if (g_log_ofs.is_open()) {
        g_log_ofs.close();
    }
    // ofstream::open(app) creates a missing file as 0666 & ~umask and follows
    // symlinks: umask 0 yields a world-writable file and a planted symlink can
    // redirect writes. ensure_log_file() pre-creates with O_NOFOLLOW + 0644 and
    // fchmod()s it; the open below then sees an existing file and keeps its mode.
    if (ensure_log_file(filepath)) {
        g_log_ofs.open(filepath, std::ios::app);
    }
    if (!g_log_ofs.is_open()) {
        std::cerr << "Logger: failed to open log file '" << filepath << "', logging to stderr" << std::endl;
    }
}

static std::string now_iso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    return ss.str();
}

static const char *basename_of_path(const char *path) {
    if (path == nullptr) return "unknown";
    const char *base = std::strrchr(path, '/');
    return base ? base + 1 : path;
}

void Logger::log(Logger::Level lvl, const std::string &msg, const char *file, int line) {
    if (severity_rank(lvl) < severity_rank(g_log_level)) return;
    const char *lvl_s = (lvl == Logger::INFO) ? "INFO" :
                        (lvl == Logger::WARN) ? "WARN" :
                        (lvl == Logger::ERROR) ? "ERROR" :
                        (lvl == Logger::DEBUG) ? "DEBUG" : "UNKNOWN";
    std::ostringstream ss;
    ss << now_iso8601() << " [" << lvl_s << "] "
       << basename_of_path(file) << ":" << line << " " << msg << "\n";
    std::string out = ss.str();
    std::lock_guard<std::mutex> lk(g_log_mutex);
    
    // Check if rotation is needed before writing
    if (should_rotate_log()) {
        rotate_log_file();
    }
    
    if (g_log_ofs.is_open()) {
        g_log_ofs << out;
        g_log_ofs.flush();
    } else {
        std::cerr << out;
    }
}
void Logger::debug(const std::string &msg, const char *file, int line) { log(DEBUG, msg, file, line); }
void Logger::info(const std::string &msg, const char *file, int line) { log(INFO, msg, file, line); }
void Logger::warn(const std::string &msg, const char *file, int line) { log(WARN, msg, file, line); }
void Logger::error(const std::string &msg, const char *file, int line) { log(ERROR, msg, file, line); }
