#include <iostream>
#include <vector>
#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <unistd.h>
#include <signal.h>

#include "filetrace.skel.h" 
#include "filetrace.h"
#include "post.hpp"

using namespace std;

static struct filetrace_bpf *skel;
PostData *Postdata_i = nullptr;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    //trace libbpf messages to stderr
    //vfprintf(stderr, format, args);
    return 0;
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
    if (data_sz < sizeof(struct event)) {
        std::cerr << "Received event with insufficient data size: " << data_sz << std::endl;
        return -1;
    }
    const struct event *e = (struct event *)data;
    std::string file_full_path;

    #ifdef DEBUG
    std::cout << "Command: " << e->cmd << ", PID: " << e->pid << ",filename: "
              << (!file_full_path.empty() ? file_full_path : std::string(e->filename))
              << ", func: " << nr_map[e->flag] << std::endl; 
    #endif
    Postdata_i->send(*e);
    return 0;
}

int main() 
{
    int err;
    struct ring_buffer *ringbuf = NULL;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_print(libbpf_print_fn);

    // Load and verify the eBPF program
    skel = filetrace_bpf__open_and_load();
    if (!skel) 
    {
        std::cerr << "Failed to open and load eBPF skeleton!" << std::endl;
        std::cerr << "Error: " << strerror(errno) << std::endl;
        return errno;
    }
    //init PostData instance
    Postdata_i = new PostData(skel);
    if (!Postdata_i) 
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
        filetrace_bpf__destroy(skel);
        return err;
    }
    ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!ringbuf) 
    {
        err = -errno;
        std::cerr << "Error: " << strerror(errno) << std::endl;
        filetrace_bpf__destroy(skel);
        return err;
    }

    std::cout << "eBPF program attached, press Ctrl+C to exit." << std::endl;

    // Poll the ring buffer for events
    while (true) 
    {
        err = ring_buffer__poll(ringbuf, 100); // timeout in ms
        if (err < 0) {
            std::cerr << "Error: " << strerror(errno) << "("<< errno <<")"<< std::endl;
            break;
        }
    }

    if (ringbuf)
    {
        ring_buffer__free(ringbuf);
    }
    filetrace_bpf__destroy(skel);
    return err;
}
