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
    __uint(max_entries, 4096); 
} exec_map SEC(".maps");

// Define a ring buffer map for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} events SEC(".maps");

static __inline struct event* bpf_create_ringbuf(void)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return NULL;
    }
    __builtin_memset(e, 0, sizeof(struct event));
    return e;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(const struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct* t;
    struct task_struct* p;

    struct event *e = bpf_create_ringbuf();
    if(!e) {
        return 0;
    }
    e->flag = SYS_openat;

    t = (struct task_struct*)bpf_get_current_task();
    bpf_probe_read(&e->pid, sizeof(e->pid), &t->tgid);
    bpf_probe_read(&e->cmd, sizeof(e->cmd), &t->comm);
    bpf_probe_read(&p, sizeof(p), &t->real_parent);
    bpf_probe_read(&e->ppid, sizeof(e->ppid), &p->tgid);
    bpf_probe_read(&e->pcmd, sizeof(e->pcmd), &p->comm);

    // For openat(int dfd, const char *pathname, int flags, mode_t mode)
    // args[0]: dfd (int)
    // args[1]: pathname (const char *)
    // args[2]: flags (int)
    // args[3]: mode (mode_t) - only when O_CREAT is specified in flags
    const char *pathname_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user(&e->filename, sizeof(e->filename), pathname_ptr);
    #ifdef DEBUG
    bpf_printk("openat detected: PID %d, file '%s'\n", e->pid, e->filename);
    #endif
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//for rm command
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int enter_unlinkat(const struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct* t;
    struct task_struct* p;

    struct event *e = bpf_create_ringbuf();
    if(!e) {
        return 0;
    }
    e->flag = SYS_unlinkat;

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
    #ifdef DEBUG
    bpf_printk("unlinkat detected: PID %d, file '%s'\n", e->pid, e->filename);
    #endif
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

    struct event *e = bpf_create_ringbuf();
    if(!e) {
        return 0;
    }

    e->flag = SYS_copy_file_range;

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;        // low 32 bit is UID
    u32 gid = (u32)(uid_gid >> 32); // high 32 bit is GID
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
    #ifdef DEBUG
    bpf_printk("copy_file_range detected: PID %d, file '%s'\n", e->pid, e->filename);
    #endif
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int handle_rename(const struct trace_event_raw_sys_enter *ctx, struct event *e)
{
    struct task_struct* t;
    struct task_struct* p;
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;
    u32 gid = (u32)(uid_gid >> 32);
    bpf_probe_read(&e->uid, sizeof(e->uid), &uid);
    bpf_probe_read(&e->gid, sizeof(e->gid), &gid);

    t = (struct task_struct*)bpf_get_current_task();
    bpf_probe_read(&e->pid, sizeof(e->pid), &t->tgid);
    bpf_get_current_comm(&e->cmd, sizeof(e->cmd));
    bpf_probe_read(&p, sizeof(p), &t->real_parent);
    bpf_probe_read(&e->ppid, sizeof(e->ppid), &p->tgid);
    bpf_probe_read(&e->pcmd, sizeof(e->pcmd), &p->comm);

    const char *filename_ptr = (const char *)ctx->args[1];
    const char *oldfilename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_str(&e->filename, sizeof(e->filename), filename_ptr);
    bpf_probe_read_str(&e->oldfilename, sizeof(e->oldfilename), oldfilename_ptr);
    bpf_printk("rename detected: handle_rename cmd=%s\n", e->cmd);
    bpf_printk("Process calling handle_rename newfilename:%s\n", e->filename);
    bpf_printk("Process calling handle_rename oldfilename:%s\n", e->oldfilename);
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
    struct event *e = bpf_create_ringbuf();
    if(!e) {
        return 0;
    }
    e->flag = SYS_rename;

    return handle_rename(ctx, e);
}
#endif
// rename(const char *oldpath, const char *newpath)
// args[0]: oldpath (const char *)
// args[1]: newpath (const char *)
SEC("tracepoint/syscalls/sys_enter_renameat")
int renameat(const struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_create_ringbuf();
    if(!e) {
        return 0;
    }
    e->flag = SYS_renameat;

    return handle_rename(ctx, e);
}
//for move
/*  move oldfile newfile  
    f == newfile  
    #mv /tmp/hosts /etc/hosts
    f == oldfile
    #mv /tmp/hosts /etc 
    #mv /etc/hosts /tmp/hosts 
    #mv /etc/hosts /tmp/ 
*/
SEC("tracepoint/syscalls/sys_enter_renameat2")
int renameat2(const struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct* t;
    struct task_struct* p;
    struct event *e;

    e = bpf_create_ringbuf();
    if(!e) {
        return 0;
    }

    e->flag = SYS_renameat2;

    t = (struct task_struct*)bpf_get_current_task();
    bpf_probe_read(&e->pid, sizeof(e->pid), &t->tgid);
    bpf_probe_read(&e->cmd, sizeof(e->cmd), &t->comm);
    bpf_probe_read(&p, sizeof(p), &t->real_parent);
    bpf_probe_read(&e->ppid, sizeof(e->ppid), &p->tgid);
    bpf_probe_read(&e->pcmd, sizeof(e->pcmd), &p->comm);

    const char *oldpath = (const char *)ctx->args[1];
    const char *newpath = (const char *)ctx->args[3];


    bpf_probe_read_str((void*)&e->filename, sizeof(e->filename), (const void*)newpath);
    bpf_probe_read_str((void*)&e->oldfilename, sizeof(e->oldfilename), (const void*)oldpath);

    struct fs_struct *fs; 
    struct path pwd;
    bpf_probe_read(&fs, sizeof(fs), (const void*)&t->fs);
    bpf_probe_read(&pwd, sizeof(pwd), (const void*)&fs->pwd);

    struct dentry* dentry;
    bpf_probe_read(&dentry, sizeof(dentry), (const void*)&pwd.dentry);

    struct dentry* d_parent;

    unsigned int olddfd = (__u32)ctx->args[0];
    unsigned int newdfd = (__u32)ctx->args[2];

    if (newdfd == AT_FDCWD) {
        #pragma unroll
        for (int i = 0; i < MAX_DEPTH; i++) {
            bpf_probe_read(&d_parent, sizeof(d_parent), (const void*)&dentry->d_parent);
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
    }

    if (olddfd == AT_FDCWD) {
        #ifdef DEBUG
        bpf_printk("oldfilename relative to CWD: %s\\n", e->oldfilename);
        #endif
    }

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;
    u32 gid = (u32)(uid_gid >> 32);
    bpf_probe_read(&e->uid, sizeof(e->uid), &uid);
    bpf_probe_read(&e->gid, sizeof(e->gid), &gid);
    #ifdef DEBUG
    bpf_printk("Process calling sys_enter_renameat2 newfilename:%s\n", e->filename);
    #endif
    bpf_ringbuf_submit(e, 0);

    return 0;

}
// execve(const char *pathname, char *const argv[], char *const envp[])
// args[0]: pathname (const char *)
SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct pinfo_t p = {};
    unsigned int pid;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&pid, sizeof(pid), &t->pid);

    struct task_struct *p_parent;
    bpf_probe_read(&p_parent, sizeof(p_parent), &t->real_parent);
    bpf_probe_read(&p.pid, sizeof(p.pid), &p_parent->pid);

    bpf_get_current_comm(&p.comm, sizeof(p.comm));
    #ifdef DEBUG
    bpf_printk("sys_enter_execve detected: PID=%u, ppid=%u, comm=%s\n", pid, p.pid, p.comm);
    #endif
    bpf_map_update_elem(&exec_map, &pid, &p, BPF_ANY);
    return 0;

}
SEC("tracepoint/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct pinfo_t p = {};
    unsigned int pid;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&pid, sizeof(pid), &t->pid);

    struct task_struct *p_parent;
    bpf_probe_read(&p_parent, sizeof(p_parent), &t->real_parent);
    bpf_probe_read(&p.pid, sizeof(p.pid), &p_parent->pid);

    bpf_get_current_comm(&p.comm, sizeof(p.comm));
    #ifdef DEBUG
    bpf_printk("sched_process_exec detected: PID=%u, ppid=%u, comm=%s\n", pid, p.pid, p.comm);
    #endif
    bpf_map_update_elem(&exec_map, &pid, &p, BPF_ANY);
    return 0;
}

static __inline int bpf_strcmp(const char *s1, const char *s2)
{
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        char c1 = s1[i];
        char c2 = s2[i];
        if (c1 != c2)
            return 1;
        if (c1 == '\0')
            break;
    }
    return 0;
}
//openEuler 2503 LTS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_dup2(struct trace_event_raw_sys_enter *ctx)
{
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    int oldfd = ctx->args[0];
    int newfd = ctx->args[1];
    if(oldfd != 3 || newfd != 1 ){
       return 0;
    }
    struct task_struct *t = (struct task_struct*)bpf_get_current_task();
    /*struct files_struct *files = t->files;
    if(files == NULL){
       bpf_printk("dup files_struct is null.\n");
       return 0;
    }*/
    char fname[16];
    bpf_fd2path(fname, sizeof(fname), oldfd);
    if(!bpf_strcmp(fname, "/dev/null")){
	    return 0 ;
    }
    if(fname[0]!='/'){
	    return 0 ;
    }
    #ifdef DEBUG
    bpf_printk("dup2 comm = %s,filename=%s , oldfd=%d, newfd=%d\n",comm,fname, oldfd, newfd);
    #endif
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct* t;
    struct task_struct* p;
    struct event *e;

    e = bpf_create_ringbuf();
    if(!e) {
        return 0;
    }
    e->flag = SYS_write;
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;         // low 32 bit is UID
    u32 gid = (u32)(uid_gid >> 32); // high 32 bit is GID
    bpf_probe_read(&e->uid, sizeof(e->uid), &uid);
    bpf_probe_read(&e->gid, sizeof(e->gid), &gid);

    t = (struct task_struct*)bpf_get_current_task();
    bpf_probe_read(&e->pid, sizeof(e->pid), &t->tgid);
    bpf_probe_read(&e->cmd, sizeof(e->cmd), &t->comm);
    bpf_probe_read(&p, sizeof(p), &t->real_parent);
    bpf_probe_read(&e->ppid, sizeof(e->ppid), &p->tgid);
    bpf_probe_read(&e->pcmd, sizeof(e->pcmd), &p->comm);

    int fd = (__s32)ctx->args[0];
    if (fd == 0 || fd == 1 || fd == 2 ) {
        bpf_ringbuf_discard(e, 0);
        return 0; 
    }
    if(fd < 3 ){
        return 0;
    }
    bpf_fd2path(e->filename, sizeof(e->filename), fd);
    #ifdef DEBUG
    bpf_printk("sys_enter_write: cmd [%s],filename [%s] \n", e->cmd, e->filename);
    #endif
    bpf_ringbuf_submit(e, 0);
    return 0;
}
#else
/*for vim echo ...
write(int fd, const void *buf, size_t count)
args[0]: fd (int)
args[1]: buf (const void *)
args[2]: count (size_t)*/
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
    e = bpf_create_ringbuf();
    if(!e) {
        return 0;
    }
    e->flag = SYS_write;

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;         // low 32 bit is UID
    u32 gid = (u32)(uid_gid >> 32); // high 32 bit is GID
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
    //fixme mode is not always correct, in different kernel versions or architectures
    if ((mode & S_IFMT) != S_IFREG)
    {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

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
    #ifdef DEBUG
    bpf_printk("sys_enter_write detected: PID %d, file '%s'\n", e->pid, e->filename);
    #endif
    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif
