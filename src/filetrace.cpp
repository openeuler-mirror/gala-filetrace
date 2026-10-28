#include <iostream>
#include <cstdio>
#include <vector>
#include <linux/bpf.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <sys/utsname.h>

#include "filetrace.skel.h" 
#include "filetrace.h"
#include "post.hpp"

using namespace std;

static struct filetrace_bpf *skel;
PostData *postdata_i = nullptr;
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    //trace libbpf messages to stderr
    #ifdef GALA_DEBUG
    vfprintf(stderr, format, args);
    #endif
    return 0;
}

// The copy_file_range probe comes in two variants: an fentry program used on
// kernels >= 6.6 (where the fd table can no longer be resolved from
// task_struct) and the sys_enter tracepoint used before that. Both are built
// into the object; pick the one matching the kernel we are actually running on
// instead of the kernel headers the binary was built against.
static bool running_kernel_at_least(int want_major, int want_minor)
{
    struct utsname info;
    if (uname(&info) != 0) {
        return false;
    }
    int major = 0;
    int minor = 0;
    if (std::sscanf(info.release, "%d.%d", &major, &minor) != 2) {
        return false;
    }
    return major > want_major || (major == want_major && minor >= want_minor);
}

static void select_copy_file_range_probe(struct filetrace_bpf *skel)
{
    bool use_fentry = running_kernel_at_least(6, 6);
    bpf_program__set_autoload(skel->progs.trace_copy_file_range, use_fentry);
    bpf_program__set_autoload(skel->progs.copy_file_range, !use_fentry);
}

static void sig_handler(int sig)
{
    std::cout << "Signal received: Exiting BPF program." << std::endl;
    if (skel) {
        filetrace_bpf__destroy(skel); 
    }
    exit(0);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    if(data == nullptr || postdata_i == nullptr) {
        std::cerr << "Received null data or PostData instance is null, skipping event." << std::endl;
        return -1;
    }
    if (data_sz < sizeof(struct event)) {
        std::cerr << "Received event with insufficient data size: [" << data_sz << "] skip." << std::endl;
        return -1;
    }
    struct event *e = (struct event *)data;
    postdata_i->process_event(*e);
    return 0;
}

int main(int argc, char **argv)
{
    int err;
    struct ring_buffer *ringbuf = NULL;
    std::string config_file = "/etc/gala-filetrace/gala-filetrace.json";
    std::string file_path;
    bool verbose = false;
    int opt;
    while ((opt = getopt(argc, argv, "c:f:")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'f':
                file_path = optarg;
                if (file_path.length() > 0 && file_path[0] != '/') {
                    std::cerr << "Error: File path must be absolute." << std::endl;
                    return 1;
                }
                if(!std::ifstream(file_path).good()) {
                    std::cerr << "Error: File path does not exist or is not accessible." << std::endl;
                    return 1;
                }
                verbose = true;
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " [-c <config_file>] [-f <file_path>]" << std::endl;
                return 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_print(libbpf_print_fn);

    // Open the skeleton first so the tracer's TGID can be written to rodata
    // before the BPF object is loaded and verified.
    skel = filetrace_bpf__open();
    if (!skel) 
    {
        std::cerr << "Failed to open eBPF skeleton!" << std::endl;
        std::cerr << "Error: " << strerror(errno) << std::endl;
        return errno;
    }
    skel->rodata->self_tgid = static_cast<__u32>(getpid());
    select_copy_file_range_probe(skel);
    err = filetrace_bpf__load(skel);
    if (err)
    {
        std::cerr << "Failed to load eBPF skeleton: " << strerror(-err) << std::endl;
        filetrace_bpf__destroy(skel);
        return err;
    }
    //init PostData instance
    postdata_i = new PostData(skel, config_file, verbose, file_path); 
    if (!postdata_i) 
    {
        std::cerr << "Failed to create PostData instance!" << std::endl;
        filetrace_bpf__destroy(skel);
        return -ENOMEM;
    }
    // Attach the eBPF program to its hook
    err = filetrace_bpf__attach(skel);
    if (err) 
    {
        std::cerr << "Failed to attach eBPF program!" << std::endl;
        delete postdata_i;
        filetrace_bpf__destroy(skel);
        return err;
    }
    ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!ringbuf) 
    {
        err = -errno;
        std::cerr << "Error: " << strerror(errno) << std::endl;
        delete postdata_i;
        filetrace_bpf__destroy(skel);
        return err;
    }

    std::cout << "eBPF program attached, press Ctrl+C to exit." << std::endl;
    // Poll the ring buffer for events
    while (true) 
    {
        err = ring_buffer__poll(ringbuf, 100); 
        if (err < 0) {
            std::cerr << "Error: " << strerror(errno) << "("<< errno <<")"<< std::endl;
            break;
        }
    }

    if (ringbuf)
    {
        ring_buffer__free(ringbuf);
    }
    delete postdata_i;
    filetrace_bpf__destroy(skel);
    return err;
}
