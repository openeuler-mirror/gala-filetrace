# 1. gala-filetrace

gala-filetrace is a functional component in A-OPS, mainly used for real-time monitoring of configuration files in the openEuler systems, and can also push monitoring information to gala-ragdoll. Supports monitoring the following commands and system calls:

* Commands: vim/vi, sed, echo, cp, move
* System calls: write

---
# 2. Implementation Architecture

# 3. Compilation and Running

Currently supported openEuler versions:
| System Version      | Architecture         |  Compatibility          | Description         |
| :---         |    :----:   |          ---: |  ---: |
| openEuler 2203_SP3   | aarch64       |  OK   |None  |
| openEuler 2203_SP3   | x86           |  OK   |None  |
| openEuler 2403_SP1   | aarch64       |  OK   |None  |
| openEuler 2403_SP1   | x86           |  OK   |None  |
| openEuler 2503       | aarch64       |  OK   |Requires adding a new helper_func to the kernel  |
| openEuler 2503       | x86           |  OK   |Requires adding a new helper_func to the kernel  |
For the added helper_func interface fd2path, refer to: 4. Kernel Upgrade.
---

## 3.1 Dependency Installation

| System Version      | Dependency Installation         |
| :---         |    :----:   |
| openEuler 2203_SP3   | # yum install bpftrace libcurl-devel libbpf-devel cpp-httplib-devel zlib-devel nlohmann-json-devel bpftool clang llvm  cpp-httplib-devel   |

## 3.2 Compilation

### 3.2.1 Source Compilation

```bash
# make
#debug add bpf_printk cat /sys/kernel/debug/tracing/trace_pipe
#make DEBUG=1
```

### 3.2.1 RPM Build

```bash
# wget -O ~/rpmbuild/SOURCES/master.zip https://gitee.com/openEuler/gala-filetrace/repository/archive/master.zip
# git clone https://gitee.com/openeuler/gala-filetrace.git
# rpmbuild -ba config/gala-filetrace.spec
```

After successful build, the gala-filetrace RPM package will be located in the ~/rpmbuild/RPMS/\<arch> directory.

## 3.3 Installation

### 3.3.1 Compilation Installation

```bash
#default install
# make install
#Custom installation dir
# make install DESTDIR=/your/install/path
```

### 3.3.2 RPM Installation

```bash
cd ~/rpmbuild/RPMS/<arch>
rpm -ivh gala-filetrace-<version>-<release>.<arch>.rpm
```

## 3.4 Startup

* Start via command

```bash
# filetrace
```

* Start via systemd service

```bash
# systemctl start gala-filetrace
```

## 3.5 Configuration Description

Configuration description:
| Configuration Item        | Value         |Description         |
| :---         |    :----:   |          ---: |
| host_id       | string          |     |
| domain_name       | string           |     |
| ragdoll_api       | string           |     |
| publish       | bool         |     Whether to push to ragdoll |

# 4. Kernel Upgrade

In kernel 6.6.0, it's no longer possible to get the fd list from task_struct in a process. Therefore, this can only be implemented by adding interfaces to the kernel. The following diagram shows the method to get file names from eBPF probes:
![Architecture Diagram](./img/getfilename.png)

The following kernel upgrade is a reference example, specific execution should be based on the actual environment.

## 4.1 Kernel Source Installation

```bash
# yum download kernel-source-6.6.0-72.6.0.56.oe2503.x86_64
# rpm -ivh kernel-source-6.6.0-72.6.0.56.oe2503.x86_64*
# cp /boot/config-6.6.0-72.6.0.56.oe2503.x86_64 .config
```

### Apply Patch

```bash
# patch -p1 < /path/to/my_patch.patch
```

## 4.2 Compilation

```bash
# make O=out
```

## 4.3 Install Modules

```bash
# make O=out modules_install
```

Default installation to /lib/modules/

## 4.4 Install Kernel Image

```bash
# make O=out install
```

Install vmlinuz, System.map, config, etc. to /boot/
