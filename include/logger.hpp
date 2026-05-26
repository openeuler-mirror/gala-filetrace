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

    static void info(const std::string &msg);
    static void warn(const std::string &msg);
    static void error(const std::string &msg);
    static void debug(const std::string &msg);

    static void log(Level lvl, const std::string &msg);

private:
    Logger() = delete;
};

#endif // LOGGER_HPP
