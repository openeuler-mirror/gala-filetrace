#ifndef FILETRACE_H
#define FILETRACE_H

#include <linux/version.h>

#define MAX_DEPTH 4
#define MAX_DIRNAME_LEN 16
#define MAX_FILENAME_LEN 64
#define MAX_CMD_LEN 32
#define MAX_TASK_COMM_LEN 32
#define ARGSIZE 16
#define MAX_ARGS 4
#define MAX_ARGS_COUNT 20 

#ifndef S_IFMT
#define S_IFMT  00170000
#endif

#ifndef S_IFREG
#define S_IFREG 0100000
#endif

#ifndef S_ISREG
#define S_ISREG(m)  (((m) & 00170000) == 0100000)
#endif
#define PF_KTHREAD 0x00200000

#define sys_enter_unlinkat_nr 0;
#define sys_enter_copy_file_range_nr 1;
#define sys_enter_rename_nr 2;
#define sys_enter_renameat_nr 3;
#define sys_enter_renameat2_nr 4;
#define sys_enter_write_nr 5;
#define AT_FDCWD -100
struct event {
    unsigned int pid;
    unsigned int ppid;
    char cmd[16];
    char pcmd[16];
    unsigned long i_ino;
    char filename[MAX_FILENAME_LEN];
    char dir1[MAX_DIRNAME_LEN];
    char dir2[MAX_DIRNAME_LEN];
    char dir3[MAX_DIRNAME_LEN];
    char dir4[MAX_DIRNAME_LEN];

    char oldfilename[MAX_FILENAME_LEN];
    char odir1[MAX_DIRNAME_LEN];
    char odir2[MAX_DIRNAME_LEN];
    char odir3[MAX_DIRNAME_LEN];
    char odir4[MAX_DIRNAME_LEN];
    int flag;
    unsigned int uid,gid;
};

//save parent process info
struct pinfo_t {
    unsigned int pid;       // parent pid
    char comm[MAX_CMD_LEN]; //pid command
    char arg1[ARGSIZE];     // pid arguments ... 
    char arg2[ARGSIZE];
    char arg3[ARGSIZE];
    char arg4[ARGSIZE];
};
enum syscall_flag {
    SYS_unlinkat = 0,
    SYS_copy_file_range,
    SYS_rename,
    SYS_renameat,
    SYS_renameat2,
    SYS_write,
    SYS_openat,
    SYS_dup2,
    SYS_NR_MAX
};
static const char *nr_map[] = {
    "sys_enter_unlinkat",        // SYS_unlinkat = 0
    "sys_enter_copy_file_range", // SYS_copy_file_range = 1
    "sys_enter_rename",          // SYS_rename = 2
    "sys_enter_renameat",        // SYS_renameat = 3
    "sys_enter_renameat2",       // SYS_renameat2 = 4
    "sys_enter_write"            // SYS_write = 5
};
#endif // FILETRACE_H