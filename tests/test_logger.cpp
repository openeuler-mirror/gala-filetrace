#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include "logger.hpp"

int main()
{
    const std::string path = "/tmp/gala_test_logger.log";
    // remove existing log file if any
    unlink(path.c_str());

    // init with info level
    Logger::init(path, "info", 1024);
    LOG_INFO("unit test info1");
    LOG_DEBUG("unit test debug1");

    std::ifstream ifs(path);
    assert(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    assert(content.find("INFO") != std::string::npos);
    // debug should be filtered at info level
    assert(content.find("DEBUG") == std::string::npos);

    // re-init with debug level and ensure DEBUG appears
    Logger::init(path, "debug", 1024);
    LOG_DEBUG("unit test debug2");
    std::ifstream ifs2(path);
    assert(ifs2.is_open());
    std::string content2((std::istreambuf_iterator<char>(ifs2)), std::istreambuf_iterator<char>());
    assert(content2.find("DEBUG") != std::string::npos);

    std::cout << "Logger unit tests passed." << std::endl;
    return 0;
}
