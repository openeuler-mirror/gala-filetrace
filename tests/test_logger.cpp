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
    // A log path whose parent directories do not exist yet must be created
    // recursively. A single mkdir() only handles one missing level and would
    // leave the log file unopenable.
    {
        const std::string nested = "/tmp/gala_ft_nested/a/b/c/run.log";
        std::filesystem::remove_all("/tmp/gala_ft_nested");
        // Run creation under a permissive umask: create_directories() would then
        // make 0777 dirs, but explicit-0755 creation must stay safe.
        mode_t old_umask = umask(0);
        Logger::init(nested, "info", 0);
        umask(old_umask);
        LOG_INFO("nested directory test line");
        assert(std::ifstream(nested).good());
        assert(read_file(nested).find("nested directory test line") != std::string::npos);
        // Created directories must not be world-writable. create_directories()
        // applies 0777 & ~umask, so under umask 0 the log dir becomes 0777 and a
        // local user could plant a run.log symlink for a root daemon to follow.
        // The explicit-0755 creation keeps the "other write" bit clear.
        {
            const std::string dir = "/tmp/gala_ft_nested/a/b/c";
            struct stat st{};
            assert(stat(dir.c_str(), &st) == 0);
            assert((st.st_mode & S_IWOTH) == 0);
        }
        // Hardening must cover the log file too, not just its directory.
        // ofstream::open() would create it as 0666 & ~umask == 0666 here;
        // the explicit 0644 creation must keep the "other write" bit clear.
        {
            struct stat st{};
            assert(stat(nested.c_str(), &st) == 0);
            assert(S_ISREG(st.st_mode));
            assert((st.st_mode & S_IWOTH) == 0);
        }
        std::filesystem::remove_all("/tmp/gala_ft_nested");
    }

    // A log file that already exists with a loose mode must be tightened on
    // init, not only files created fresh by this process.
    {
        const std::string loose = "/tmp/gala_ft_loose.log";
        std::filesystem::remove_all(loose);
        {
            std::ofstream ofs(loose);
            ofs << "seed";
        }
        chmod(loose.c_str(), 0666);
        struct stat before{};
        assert(stat(loose.c_str(), &before) == 0);
        assert((before.st_mode & S_IWOTH) != 0);
        Logger::init(loose, "info", 0);
        struct stat after{};
        assert(stat(loose.c_str(), &after) == 0);
        assert((after.st_mode & S_IWOTH) == 0);
        std::filesystem::remove_all(loose);
    }

    // A symlink directory component that resolves to a real directory is
    // legitimate (e.g. /var/run -> /run) and must keep working. The previous
    // lstat-based check killed all symlinks and silently degraded logging to
    // stderr; resolving with stat() must accept this case and still write.
    {
        const std::string root = "/tmp/gala_ft_symlink_ok";
        const std::string target = root + "_target";
        std::filesystem::remove_all(root);
        std::filesystem::remove_all(target);
        std::filesystem::create_directories(target);
        assert(symlink(target.c_str(), root.c_str()) == 0);
        const std::string logpath = root + "/run.log";
        Logger::init(logpath, "info", 0);
        LOG_INFO("symlink component line");
        assert(std::ifstream(target + "/run.log").good());
        assert(read_file(target + "/run.log").find("symlink component line") != std::string::npos);
        std::filesystem::remove_all(root);
        std::filesystem::remove_all(target);
    }

    // A symlink component pointing at a regular file (not a directory) must be
    // refused. NOTE: asserting !ifstream(logpath).good() here is TAUTOLOGICAL -
    // the kernel returns ENOTDIR for ".../root/run.log" when root is a symlink
    // to a regular file, regardless of our own validation, so that assertion
    // can never fail even if all symlink checks are deleted. Assert instead the
    // security invariant that actually distinguishes implementations: the link
    // target must never be treated as (appended to) the log file. A buggy
    // implementation that follows the link and opens the target as the log
    // would corrupt it, and this assertion would catch that.
    {
        const std::string root = "/tmp/gala_ft_symlink_bad";
        const std::string target = root + "_file";
        const std::string sentinel = "not a directory\n";
        std::filesystem::remove_all(root);
        std::filesystem::remove_all(target);
        {
            std::ofstream ofs(target);
            ofs << sentinel;
        }
        assert(symlink(target.c_str(), root.c_str()) == 0);
        const std::string logpath = root + "/run.log";
        Logger::init(logpath, "info", 0);
        LOG_INFO("bad symlink line");
        // The link target is a plain file, not a directory: its content must
        // remain exactly the sentinel (no log lines appended into it).
        assert(read_file(target) == sentinel);
        std::filesystem::remove_all(root);
        std::filesystem::remove_all(target);
    }

    // A FIFO at the log path must be rejected WITHOUT BLOCKING. The previous
    // code called open(O_WRONLY) directly; on a FIFO with no reader that blocks
    // forever (the S_ISREG check came too late, after open returned). The
    // lstat pre-check must reject it before open. An alarm() guard turns a
    // blocking-open regression into a hard test failure instead of a hang.
    {
        const std::string fifo = "/tmp/gala_ft_fifo.log";
        unlink(fifo.c_str());
        assert(mkfifo(fifo.c_str(), 0644) == 0);
        alarm(3);
        Logger::init(fifo, "info", 0);
        LOG_INFO("fifo line");
        alarm(0);
        // The FIFO must still be a FIFO: it was refused, not replaced by a
        // regular log file (SIGALRM default action kills us if init blocked).
        struct stat st{};
        assert(lstat(fifo.c_str(), &st) == 0);
        assert(S_ISFIFO(st.st_mode));
        unlink(fifo.c_str());
    }

    // The log FILE path itself being a symlink must be refused even when its
    // parent directory is perfectly safe. ensure_log_file() uses lstat +
    // O_NOFOLLOW so a planted run.log -> /etc/passwd link cannot redirect a
    // root daemon's writes. Assert the link target stays untouched.
    {
        const std::string root = "/tmp/gala_ft_filelink";
        const std::string target = "/tmp/gala_ft_filelink_target";
        std::filesystem::remove_all(root);
        std::filesystem::remove_all(target);
        std::filesystem::create_directories(root);
        {
            std::ofstream ofs(target);
            ofs << "sentinel";
        }
        const std::string logpath = root + "/run.log";
        assert(symlink(target.c_str(), logpath.c_str()) == 0);
        Logger::init(logpath, "info", 0);
        LOG_INFO("must not land in symlink target");
        assert(read_file(target) == "sentinel");
        std::filesystem::remove_all(root);
        std::filesystem::remove_all(target);
    }

    // Hardening must never WIDEN a stricter mode. A file created under umask
    // 077 is 0600; a blind fchmod(0644) would make it world-readable. The fix
    // strips only group/other write bits, leaving 0600 intact.
    {
        const std::string strict = "/tmp/gala_ft_strict.log";
        std::filesystem::remove_all(strict);
        mode_t old_umask = umask(077);
        Logger::init(strict, "info", 0);
        umask(old_umask);
        LOG_INFO("strict umask line");
        struct stat st{};
        assert(stat(strict.c_str(), &st) == 0);
        assert((st.st_mode & S_IRGRP) == 0);
        assert((st.st_mode & S_IROTH) == 0);
        assert((st.st_mode & S_IWGRP) == 0);
        assert((st.st_mode & S_IWOTH) == 0);
        assert(read_file(strict).find("strict umask line") != std::string::npos);
        std::filesystem::remove_all(strict);
    }

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
