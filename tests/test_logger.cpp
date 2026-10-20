#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include "logger.hpp"

static std::string read_file(const std::string &path)
{
    std::ifstream ifs(path);
    return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

int main()
{
    const std::string path = "/tmp/gala_test_logger.log";
    // remove existing log file if any
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

    // Level filtering matrix: a message is written only when its severity
    // rank meets or exceeds the configured threshold. An invalid level name
    // falls back to info.
    struct LevelCase {
        const char *cfg;
        bool exp_info, exp_warn, exp_error, exp_debug;
    };
    const LevelCase cases[] = {
        {"info",  true,  true,  true,  false},
        {"warn",  false, true,  true,  false},
        {"error", false, false, true,  false},
        {"debug", true,  true,  true,  true},
        {"bogus", true,  true,  true,  false},
    };
    for (const auto &c : cases) {
        unlink(path.c_str());
        Logger::init(path, c.cfg, 0);
        LOG_INFO("m_info_" + std::string(c.cfg));
        LOG_WARN("m_warn_" + std::string(c.cfg));
        LOG_ERROR("m_error_" + std::string(c.cfg));
        LOG_DEBUG("m_debug_" + std::string(c.cfg));
        std::string content = read_file(path);
        assert((content.find(std::string("m_info_") + c.cfg) != std::string::npos) == c.exp_info);
        assert((content.find(std::string("m_warn_") + c.cfg) != std::string::npos) == c.exp_warn);
        assert((content.find(std::string("m_error_") + c.cfg) != std::string::npos) == c.exp_error);
        assert((content.find(std::string("m_debug_") + c.cfg) != std::string::npos) == c.exp_debug);
    }

    // Rotation: once the file reaches max_size it is renamed to a
    // timestamped backup and a fresh file is created.
    {
        const std::string rpath = "/tmp/gala_test_rotate.log";
        unlink(rpath.c_str());
        for (const auto &entry : std::filesystem::directory_iterator("/tmp")) {
            if (entry.path().filename().string().rfind("gala_test_rotate.log.", 0) == 0) {
                std::filesystem::remove(entry.path());
            }
        }
        Logger::init(rpath, "debug", 100);
        for (int i = 0; i < 12; ++i) {
            LOG_INFO("rotation test line " + std::to_string(i) + " padding padding");
        }
        size_t backups = 0;
        for (const auto &entry : std::filesystem::directory_iterator("/tmp")) {
            if (entry.path().filename().string().rfind("gala_test_rotate.log.", 0) == 0) {
                backups++;
            }
        }
        assert(backups >= 1);
        // a fresh file must have been created and hold the most recent line
        std::string content = read_file(rpath);
        assert(content.find("rotation test line 11") != std::string::npos);
        unlink(rpath.c_str());
    }

    std::cout << "Logger unit tests passed." << std::endl;
    return 0;
}
