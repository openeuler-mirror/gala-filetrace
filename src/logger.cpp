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

// Create (or fix up) the log file with safe permissions and no symlink
// indirection. std::ofstream::open() alone creates a missing file as 0666 &
// ~umask (world-writable when umask is 0) and follows symlinks, so a planted
// run.log symlink can redirect a root daemon's writes to an arbitrary file.
// Pre-create with O_NOFOLLOW, then strip only the group/other WRITE bits from
// the resulting mode. Crucially we do NOT force 0644: a file created under a
// strict umask (077) is 0600 and must stay 0600, not be widened to readable by
// everyone. Permission tightening is best-effort: a failure only warns, it
// never costs us the log file itself (see below).
static bool ensure_log_file(const std::string &filepath) {
    struct stat st{};
    // Reject symlinks and already-existing non-regular files BEFORE open(): a
    // blocking O_WRONLY open() on a FIFO with no reader would hang the daemon
    // forever, and the later S_ISREG check would never be reached.
    if (lstat(filepath.c_str(), &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            std::cerr << "Logger: refusing symlink log file '" << filepath << "'" << std::endl;
            return false;
        }
        if (!S_ISREG(st.st_mode)) {
            std::cerr << "Logger: refusing non-regular log file '" << filepath << "'" << std::endl;
            return false;
        }
    }
    // O_NONBLOCK is a belt-and-braces guard: even if the path is swapped for a
    // FIFO between lstat() and open(), open() returns ENXIO instead of hanging.
    // It has no effect on regular files and is dropped when we close this fd;
    // ofstream re-opens the path with normal blocking semantics afterwards.
    int fd = ::open(filepath.c_str(),
                    O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0644);
    if (fd < 0) {
        std::cerr << "Logger: cannot open log file '" << filepath << "': "
                  << std::strerror(errno) << std::endl;
        return false;
    }
    // fstat is best-effort: lstat already vetted the type, and a failure here
    // must not make us abandon a file we can write to.
    if (fstat(fd, &st) != 0) {
        std::cerr << "Logger: cannot stat log file '" << filepath
                  << "'; continuing with current mode" << std::endl;
        close(fd);
        return true;
    }
    if (!S_ISREG(st.st_mode)) {
        std::cerr << "Logger: refusing non-regular log file '" << filepath << "'" << std::endl;
        close(fd);
        return false;
    }
    // Pure permission bits only: st_mode carries the S_IFREG type bit, so
    // compare and fchmod on the same 07777 mask (otherwise the check is always
    // true and type bits leak to the kernel).
    const mode_t cur_mode = static_cast<mode_t>(st.st_mode & 07777);
    const mode_t safe_mode = cur_mode & ~static_cast<mode_t>(S_IWGRP | S_IWOTH);
    if (cur_mode != safe_mode && fchmod(fd, safe_mode) != 0) {
        // Hardening is an enhancement, not a precondition for logging. If the
        // file is not ours (EPERM) or lives on a FS without chmod (EOPNOTSUPP),
        // failing here sends ALL logs to stderr - the very loss this PR fixes.
        // Warn and keep using the already-opened (non-symlink) file instead.
        std::cerr << "Logger: cannot tighten mode of log file '" << filepath
                  << "': " << std::strerror(errno) << "; continuing" << std::endl;
    }
    if (close(fd) != 0) {
        std::cerr << "Logger: close failed for log file '" << filepath << "'" << std::endl;
    }
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
//
// Symlinks in the path are resolved with stat() (not lstat()): common system
// links such as /var/run -> /run or /var/lock -> /run/lock are legitimate and
// must keep working, otherwise logging silently degrades to stderr. A symlink
// is accepted only when it resolves to a real directory; a dangling link or a
// link to a regular file is rejected. The end-to-end safety boundary is that
// the log FILE itself is never opened through a symlink (see ensure_log_file).
static bool create_log_directories(const std::string &dir) {
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
            struct stat comp_st{};
            if (stat(current.c_str(), &comp_st) == 0) {
                // Exists (possibly via a symlink): accept only real directories.
                // Never chmod an existing component -- it may be a system dir
                // whose mode is intentionally managed elsewhere.
                if (!S_ISDIR(comp_st.st_mode)) {
                    std::cerr << "Logger: log dir component is not a directory: '"
                              << current << "'" << std::endl;
                    return false;
                }
            } else if (mkdir(current.c_str(), 0755) != 0) {
                // EEXIST is a race (another instance created it between our
                // stat() and mkdir()) or a dangling symlink. Re-check: only a
                // real directory may be accepted, otherwise keep refusing.
                if (errno == EEXIST) {
                    if (stat(current.c_str(), &comp_st) != 0 ||
                        !S_ISDIR(comp_st.st_mode)) {
                        std::cerr << "Logger: log dir component is not a directory: '"
                                  << current << "'" << std::endl;
                        return false;
                    }
                } else {
                    std::cerr << "Logger: cannot create log dir '" << current << "': "
                              << std::strerror(errno) << std::endl;
                    return false;
                }
            }
        }
        if (slash == std::string::npos) {
            break;
        }
        start = slash + 1;
    }
    return true;
}

void Logger::init(const std::string &filepath, const std::string &level, size_t max_size) {
    std::lock_guard<std::mutex> lk(g_log_mutex);
    g_log_level = parse_level(level);
    g_log_filepath = filepath;
    g_max_log_size = max_size;
    
    size_t pos = filepath.rfind('/');
    if (pos != std::string::npos && pos > 0) {
        // Always walk the chain: a bare stat(dir) short-circuits when an
        // intermediate component is a symlink or a non-directory, hiding the
        // validation and leaving the log file unopenable. create_log_directories
        // is idempotent for components that already exist.
        std::string dir = filepath.substr(0, pos);
        if (!create_log_directories(dir)) {
            std::cerr << "Logger: failed to prepare log directory '" << dir
                      << "', logging to stderr" << std::endl;
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
