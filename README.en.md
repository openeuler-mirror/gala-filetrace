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
| openEuler 2403_SP4   | aarch64       |  OK   |None  |
| openEuler 2403_SP4   | x86           |  OK   |None  |
| openEuler 2503       | aarch64       |  OK   |None  |
| openEuler 2503       | x86           |  OK   |None  |

## 3.1 Dependency Installation

### 3.1.1 Install from Repository

| System Version      | Dependency Installation         |
| :---         |    :----:   |
| openEuler 2203_SP3   | # yum install bpftrace libcurl-devel libbpf-devel cpp-httplib-devel zlib-devel nlohmann-json-devel bpftool clang llvm   |

---
<font color="red">Note: If cpp-httplib version is below 0.22.0, replace cpp-httplib-devel with cpp-httplib; libbpf must be version 0.8 or above.</font>

---

### 3.1.2 Install from Source (when not available in repository)

* Source installation

```bash
# git clone https://atomgit.com/gh_mirrors/pr/prometheus-cpp.git
# cd prometheus-cpp
# git submodule init && git submodule update
# mkdir build && cd build
# cmake .. -DBUILD_SHARED_LIBS=ON -DENABLE_PULL=ON -DENABLE_PUSH=OFF
# make -j && sudo make install
```

---
<font color="red">Note: Source-installed prometheus-cpp libraries are installed to /usr/local/include/ by default.</font>

---

* RPM package installation

```bash
# cmake -B_build -DCPACK_GENERATOR=RPM -DBUILD_SHARED_LIBS=ON
# cmake --build _build --target package --parallel $(nproc)
# Result: /root/prometheus-cpp/_build/prometheus-cpp-<version>-<release>.<arch>.rpm
```

## 3.2 Compilation

### 3.2.1 Source Compilation

```bash
# Install dependencies before building
# make deps
# make
# Debug mode: make DEBUG=1 defines GALA_DEBUG macro, BPF side outputs debug via bpf_printk
# View in real-time: cat /sys/kernel/debug/tracing/trace_pipe
# make DEBUG=1
```

### 3.2.2 RPM Build

```bash
# Method 1: make rpm (automatically downloads source archive and runs rpmbuild)
make rpm

# Method 2: manual
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
| Configuration Item        | Value         | Description         |
| :---         |    :----:   |          ---: |
| host_id       | string          | Host UUID |
| domain_name       | string           | Domain / data center where the host resides |
| ragdoll_api       | string           | Ragdoll server address |
| publish       | bool         | Whether to push to ragdoll |
| exporter_address  | string   | Prometheus Node Exporter listening address |

Visit <http://IP:9090/Metrics> in a browser to view monitoring metrics.

# 4. QA

## 4.1 The following log appears in dmesg

```text
permission error while running as root; try raising 'ulimit -l'? current value: 64.0 KiB.
 ```

Solution：

```bash
# ulimit -l 819200  
```
