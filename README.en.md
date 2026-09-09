# 1. gala-filetrace

English | [简体中文](./README.md)

gala-filetrace is a functional component in A-OPS, mainly used for real-time monitoring of configuration files in the openEuler systems, and can also push monitoring information to gala-ragdoll.

## Features

* Monitors the following commands and system calls:
  * Commands: vim/vi, sed, echo, cp, mv
  * System calls: write
* Integrates with Prometheus
* Provides an API to configure the monitored files
* Web UI (to be developed)

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
| openEuler 2503       | aarch64       |  OK   |None  |
| openEuler 2503       | x86           |  OK   |None  |

## 3.1 Dependency Installation

| System Version      | Dependency Installation         |
| :---         |    :----:   |
| openEuler 2203_SP3   | # yum install bpftrace libcurl-devel libbpf-devel cpp-httplib-devel zlib-devel nlohmann-json-devel bpftool clang llvm   |

## 3.2 Compilation

### 3.2.1 Source Compilation

```bash
# make
#debug add bpf_printk cat /sys/kernel/debug/tracing/trace_pipe
#make DEBUG=1
```

### 3.2.1 RPM Build

```bash
# wget -O ~/rpmbuild/SOURCES/master.zip https://raw.atomgit.com/openeuler/gala-filetrace/archive/refs/heads/master.zip
# git clone https://atomgit.com/openeuler/gala-filetrace.git
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

# 4. QA

## 4.1 The following log appears in dmesg

```text
permission error while running as root; try raising 'ulimit -l'? current value: 64.0 KiB.
 ```

Solution：

```bash
# ulimit -l 819200  
```
