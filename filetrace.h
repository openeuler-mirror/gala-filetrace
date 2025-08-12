#ifndef FILETRACE_H
#define FILETRACE_H

 
#define MAX_DEPTH 4
#define MAX_DIRNAME_LEN 16
#define MAX_FILENAME_LEN 32
#define MAX_CMD_LEN 32
#define MAX_TASK_COMM_LEN 32
#define ARGSIZE 16
#define MAX_ARGS 4

#ifndef S_IFMT
#define S_IFMT  00170000
#endif

#ifndef S_IFREG
#define S_IFREG 0100000
#endif

#ifndef S_ISREG
#define S_ISREG(m)  (((m) & 00170000) == 0100000)
#endif


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

struct pinfo_t {
    unsigned int ppid;
    char comm[MAX_CMD_LEN];
    char arg1[ARGSIZE];
    char arg2[ARGSIZE];
    char arg3[ARGSIZE];
    char arg4[ARGSIZE];
};
#endif // FILETRACE_H