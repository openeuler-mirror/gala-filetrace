#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "filetrace.h"

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct pinfo_t);
    __uint(max_entries, 1024);
} exec_map SEC(".maps");

// Define a ring buffer map for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} events SEC(".maps");

//for rm command
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int enter_unlinkat(const struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct* t;
    struct task_struct* p;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
    {
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->flag = 4;

    t = (struct task_struct*)bpf_get_current_task();
    bpf_probe_read(&e->pid, sizeof(e->pid), &t->tgid);
    bpf_probe_read(&e->cmd, sizeof(e->cmd), &t->comm);
    bpf_probe_read(&p, sizeof(p), &t->real_parent);
    bpf_probe_read(&e->ppid, sizeof(e->ppid), &p->tgid);
    bpf_probe_read(&e->pcmd, sizeof(e->pcmd), &p->comm);

    // 对于 unlinkat(int dfd, const char *pathname, int flags)
    // args[0]: dfd (int)
    // args[1]: pathname (const char *)
    // args[2]: flags (int)
    const char *pathname_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user(&e->filename, sizeof(e->filename), pathname_ptr);
    bpf_printk("unlinkat detected: PID %d, file '%s'\n", e->pid, e->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//for copy command
// copy_file_range(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)
// args[0]: fd_in (int)
// args[1]: off_in (loff_t *) 
// args[2]: fd_out (int)
// args[3]: off_out (loff_t *) 
// args[4]: len (size_t)
// args[5]: flags (unsigned int)

SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int copy_file_range(const struct trace_event_raw_sys_enter *ctx)    
{
    struct task_struct* t;
    struct task_struct* p;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
    {
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));

    e->flag = 2;

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;        // low 32 bit is UID
    u32 gid = (u32)(uid_gid >> 32); // hight 32 bit is GID
    bpf_probe_read(&e->uid, sizeof(e->uid), &uid);
    bpf_probe_read(&e->gid, sizeof(e->gid), &gid);

    int fd = (__s32)ctx->args[2];
    t = (struct task_struct*)bpf_get_current_task();

    struct files_struct *f = NULL;
    struct fdtable *fdt = NULL;
    struct file **fd_array = NULL;
    struct file *file = NULL;
    bpf_probe_read(&f, sizeof(f), &t->files);
    bpf_probe_read(&fdt, sizeof(fdt), &f->fdt);
    bpf_probe_read(&fd_array, sizeof(fd_array), &fdt->fd);
    struct file *file_ptr = NULL;
    bpf_probe_read(&file_ptr, sizeof(file_ptr), &fd_array[fd]);
    file = file_ptr;

    //fill pid cmd ppid pcmd
    bpf_probe_read(&e->pid, sizeof(e->pid), &t->tgid);
    bpf_probe_read(&e->cmd, sizeof(e->cmd), &t->comm);
    bpf_probe_read(&p, sizeof(p), &t->real_parent);
    bpf_probe_read(&e->ppid, sizeof(e->ppid), &p->tgid);
    bpf_probe_read(&e->pcmd, sizeof(e->pcmd), &p->comm);

    struct inode *inode = NULL;
    bpf_probe_read(&inode, sizeof(inode), &file->f_inode);
    bpf_probe_read(&e->i_ino, sizeof(inode->i_ino), &inode->i_ino);

    umode_t mode = 0;
    bpf_probe_read(&mode, sizeof(mode), &inode->i_mode);
    //fixme 
    /*if(!S_ISREG(mode))
    {
        return 0;
    }*/
    //get filename  
    struct path path;
    struct dentry* dentry;
    struct qstr pathname;
    bpf_probe_read(&path, sizeof(path), &file->f_path);
    bpf_probe_read(&dentry, sizeof(dentry), &path.dentry);
    bpf_probe_read(&pathname, sizeof(pathname), &dentry->d_name);

    struct dentry* d_parent;
    #pragma unroll
    for (int i = 0; i < MAX_DEPTH; i++) 
    {
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);
        if (d_parent == dentry) {
            break;
        }
        //fix me 
        if(i == 0){
            bpf_probe_read(&e->dir1, sizeof(d_parent->d_iname), (const void*)&d_parent->d_iname);
        }else if(i == 1){
            bpf_probe_read(&e->dir2, sizeof(d_parent->d_iname), (const void*)&d_parent->d_iname);
        }else if(i == 2){
            bpf_probe_read(&e->dir3, sizeof(d_parent->d_iname), (const void*)&d_parent->d_iname);
        }else if(i == 3){
            bpf_probe_read(&e->dir4, sizeof(d_parent->d_iname), (const void*)&d_parent->d_iname);
        }    
        dentry = d_parent;
    }
    
    bpf_probe_read_str((void*)&e->filename, sizeof(e->filename), (const void*)pathname.name);
    bpf_printk("copy_file_range detected: PID %d, file '%s'\n", e->pid, e->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//for sed command
// rename(const char *oldpath, const char *newpath)
// args[0]: oldpath (const char *)
// args[1]: newpath (const char *)
#ifdef __x86_64__
SEC("tracepoint/syscalls/sys_enter_rename")
int rename(const struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct* t;
    struct task_struct* p;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
    {
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));

    e->flag = 1;

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;        // low 32 bit is UID
    u32 gid = (u32)(uid_gid >> 32); // hight 32 bit is GID
    bpf_probe_read(&e->uid, sizeof(e->uid), &uid);
    bpf_probe_read(&e->gid, sizeof(e->gid), &gid);

    t = (struct task_struct*)bpf_get_current_task();
    //fill pid cmd ppid pcmd
    bpf_probe_read(&e->pid, sizeof(e->pid), &t->tgid);
    bpf_probe_read(&e->cmd, sizeof(e->cmd), &t->comm);
    bpf_probe_read(&p, sizeof(p), &t->real_parent);
    bpf_probe_read(&e->ppid, sizeof(e->ppid), &p->tgid);
    bpf_probe_read(&e->pcmd, sizeof(e->pcmd), &p->comm);
    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_str(&e->filename, sizeof(e->filename), filename_ptr);
    bpf_printk("Process calling sys_enter_rename newfilename:%s \n", e->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif

static __always_inline int handle_rename(const struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct* t;
    struct task_struct* p;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
    {
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));

    e->flag = 1;

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;
    u32 gid = (u32)(uid_gid >> 32);
    bpf_probe_read(&e->uid, sizeof(e->uid), &uid);
    bpf_probe_read(&e->gid, sizeof(e->gid), &gid);

    t = (struct task_struct*)bpf_get_current_task();
    bpf_probe_read(&e->pid, sizeof(e->pid), &t->tgid);
    bpf_probe_read(&e->cmd, sizeof(e->cmd), &t->comm);
    bpf_probe_read(&p, sizeof(p), &t->real_parent);
    bpf_probe_read(&e->ppid, sizeof(e->ppid), &p->tgid);
    bpf_probe_read(&e->pcmd, sizeof(e->pcmd), &p->comm);

    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_str(&e->filename, sizeof(e->filename), filename_ptr);
    bpf_printk("Process calling sys_enter_rename newfilename:%s\n", e->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// rename(const char *oldpath, const char *newpath)
// args[0]: oldpath (const char *)
// args[1]: newpath (const char *)
SEC("tracepoint/syscalls/sys_enter_renameat")
int renameat(const struct trace_event_raw_sys_enter *ctx)
{
    return handle_rename(ctx);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int renameat2(const struct trace_event_raw_sys_enter *ctx)
{
    return handle_rename(ctx);
}

//for vim echo ...
// write(int fd, const void *buf, size_t count)
// args[0]: fd (int)
// args[1]: buf (const void *)
// args[2]: count (size_t)
SEC("tracepoint/syscalls/sys_enter_write")
int write(const struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct* t;
    struct task_struct* p;
    t = (struct task_struct*)bpf_get_current_task();
    //skip kernel threads
    unsigned int flags;
    bpf_probe_read(&flags, sizeof(flags), &t->flags);
    if (flags & PF_KTHREAD) 
    {
        return 0; 
    }
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
    {
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->flag = 0;
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;         // low 32 bit is UID
    u32 gid = (u32)(uid_gid >> 32); // hight 32 bit is GID
    bpf_probe_read(&e->uid, sizeof(e->uid), &uid);
    bpf_probe_read(&e->gid, sizeof(e->gid), &gid);
    int fd = (__s32)ctx->args[0];
    if (fd == 0 || fd == 1 || fd == 2 ) {
        bpf_ringbuf_discard(e, 0);
        return 0; 
    }
    //get file struct from task_struct
    struct files_struct *f = NULL;
    struct fdtable *fdt = NULL;
    struct file **fd_array = NULL;
    struct file *file = NULL;
    bpf_probe_read(&f, sizeof(f), &t->files);
    bpf_probe_read(&fdt, sizeof(fdt), &f->fdt);
    bpf_probe_read(&fd_array, sizeof(fd_array), &fdt->fd);
    struct file *file_ptr = NULL;
    bpf_probe_read(&file_ptr, sizeof(file_ptr), &fd_array[fd]);
    file = file_ptr;
   
    //fill pid cmd ppid pcmd
    bpf_probe_read(&e->pid, sizeof(e->pid), &t->tgid);
    bpf_probe_read(&e->cmd, sizeof(e->cmd), &t->comm);
    bpf_probe_read(&p, sizeof(p), &t->real_parent);
    bpf_probe_read(&e->ppid, sizeof(e->ppid), &p->tgid);
    bpf_probe_read(&e->pcmd, sizeof(e->pcmd), &p->comm);

    //get file ino from struct file
    struct inode *inode = NULL;
    bpf_probe_read(&inode, sizeof(inode), &file->f_inode);
    bpf_probe_read(&e->i_ino, sizeof(inode->i_ino), &inode->i_ino);

    umode_t mode = 0;
    bpf_probe_read(&mode, sizeof(mode), &inode->i_mode);
    if ((mode & S_IFMT) != S_IFREG)
    {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    //skip kernel processes
    /*if (e->pid == 0 || e->pid == 1 || e->pid == 2 || e->pid == 3) {
        bpf_ringbuf_discard(e, 0);
        return 0; 
    }*/

    //get filename from struct file
    struct path path;
    struct dentry* dentry;
    struct qstr pathname;
    bpf_probe_read(&path, sizeof(path), &file->f_path);
    bpf_probe_read(&dentry, sizeof(dentry), &path.dentry);
    bpf_probe_read(&pathname, sizeof(pathname), &dentry->d_name);

    struct dentry* d_parent;
    #pragma unroll
    for (int i = 0; i < MAX_DEPTH; i++) 
    {
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);
        if (d_parent == dentry) {
            break;
        }
        //fix me 
        if(i == 0){
            bpf_probe_read(&e->dir1, sizeof(d_parent->d_iname), (const void*)&d_parent->d_iname);
        }else if(i == 1){
            bpf_probe_read(&e->dir2, sizeof(d_parent->d_iname), (const void*)&d_parent->d_iname);
        }else if(i == 2){
            bpf_probe_read(&e->dir3, sizeof(d_parent->d_iname), (const void*)&d_parent->d_iname);
        }else if(i == 3){
            bpf_probe_read(&e->dir4, sizeof(d_parent->d_iname), (const void*)&d_parent->d_iname);
        }    
        dentry = d_parent;
    }

    bpf_probe_read_str((void*)&e->filename, sizeof(e->filename), (const void*)pathname.name);
    bpf_printk("sys_enter_write detected: PID %d, file '%s'\n", e->pid, e->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}   
/*
//writev(int fd, const struct iovec *iov, int iovcnt) for cache write to fd
// args[0]: fd (int)
// args[1]: buf (const void *)
// args[2]: iovcnt (struct iovec)
SEC("tracepoint/syscalls/sys_enter_writev")
int writev(const struct trace_event_raw_sys_enter *ctx)
{
    return write(ctx);
}
*/
// execve(const char *pathname, char *const argv[], char *const envp[])
// args[0]: pathname (const char *)
SEC("tracepoint/syscalls/sys_enter_execve")
int execve(const struct trace_event_raw_sys_enter *ctx){
    struct pinfo_t p = {};
    u64 tgid_pid;
    u32 tgid, pid;
    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *pp;
    bpf_probe_read(&pp, sizeof(pp), &t->real_parent);
    bpf_probe_read(&p.ppid, sizeof(p.ppid), &pp->tgid);
    bpf_get_current_comm(&p.comm, sizeof(p.comm));
    
    const char *pathname_ptr = (const char *)ctx->args[0];
    char *const *argv_ptr = (char *const *)ctx->args[1];
    #pragma unroll
    int i = 0;
    char *arg_ptr;
    char arg_buf[64]; 
    for (i = 0; i < MAX_ARGS_COUNT; i++) {
        bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_ptr[i]);
    }

    bpf_map_update_elem(&exec_map, &pid, &p, BPF_ANY);
    return 0;

}
SEC("tracepoint/syscalls/sys_exit_execve")
int exit(const struct trace_event_raw_sys_enter *ctx){
    u64 tgid_pid;
    u32 tgid, pid;
    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;
    bpf_map_delete_elem(&exec_map, &pid);
    return 0;
}
