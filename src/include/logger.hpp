#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>

class Logger {
public:
    enum Level { INFO = 0, WARN = 1, ERROR = 2, DEBUG = 3 };

    // Initialize logger: filepath (default /var/log/filetrace.log), level string (info,warn,error)
    // max_size: maximum log file size in bytes (default 100MB), 0 means unlimited
    static void init(const std::string &filepath = "/var/log/filetrace.log", 
                     const std::string &level = "info", 
                     size_t max_size = 100 * 1024 * 1024);

    // These functions expect the caller to provide source file and line.
    // Do not use __FILE__/__LINE__ as default parameter values here —
    // they would expand to this header instead of the call site.
    static void info(const std::string &msg, const char *file, int line);
    static void warn(const std::string &msg, const char *file, int line);
    static void error(const std::string &msg, const char *file, int line);
    static void debug(const std::string &msg, const char *file, int line);

    static void log(Level lvl, const std::string &msg, const char *file, int line);

private:
    Logger() = delete;
};

#endif // LOGGER_HPP

// Convenience macros that expand `__FILE__`/`__LINE__` at the call site.
// Prefer using these to ensure logged file/line reflect the caller.
#define LOG_INFO(msg) Logger::log(Logger::INFO, (msg), __FILE__, __LINE__)
#define LOG_WARN(msg) Logger::log(Logger::WARN, (msg), __FILE__, __LINE__)
#define LOG_ERROR(msg) Logger::log(Logger::ERROR, (msg), __FILE__, __LINE__)
#define LOG_DEBUG(msg) Logger::log(Logger::DEBUG, (msg), __FILE__, __LINE__)
