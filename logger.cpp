#include "logger.hpp"
#include <fstream>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <sys/stat.h>

static std::ofstream g_log_ofs;
static std::mutex g_log_mutex;
static Logger::Level g_log_level = Logger::INFO;

static Logger::Level parse_level(const std::string &s) {
    if (s == "warn" || s == "WARN" || s == "Warn") return Logger::WARN;
    if (s == "error" || s == "ERROR" || s == "Error") return Logger::ERROR;
    if (s == "debug" || s == "DEBUG" || s == "Debug") return Logger::DEBUG;
    return Logger::INFO;
}

void Logger::init(const std::string &filepath, const std::string &level) {
    std::lock_guard<std::mutex> lk(g_log_mutex);
    g_log_level = parse_level(level);
    size_t pos = filepath.rfind('/');
    if (pos != std::string::npos && pos > 0) {
        std::string dir = filepath.substr(0, pos);
        struct stat st;
        if (stat(dir.c_str(), &st) != 0) {
            mkdir(dir.c_str(), 0755);
        }
    }
    g_log_ofs.open(filepath, std::ios::app);
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

void Logger::log(Logger::Level lvl, const std::string &msg) {
    if (lvl < g_log_level) return;
    const char *lvl_s = (lvl == Logger::INFO) ? "INFO" :
                        (lvl == Logger::WARN) ? "WARN" :
                        (lvl == Logger::ERROR) ? "ERROR" :
                        (lvl == Logger::DEBUG) ? "DEBUG" : "UNKNOWN";
    std::ostringstream ss;
    ss << now_iso8601() << " [" << lvl_s << "] " << msg << "\n";
    std::string out = ss.str();
    std::lock_guard<std::mutex> lk(g_log_mutex);
    if (g_log_ofs.is_open()) {
        g_log_ofs << out;
        g_log_ofs.flush();
    } else {
        std::cerr << out;
    }
}
void Logger::debug(const std::string &msg) { log(DEBUG, msg); }
void Logger::info(const std::string &msg) { log(INFO, msg); }
void Logger::warn(const std::string &msg) { log(WARN, msg); }
void Logger::error(const std::string &msg) { log(ERROR, msg); }
