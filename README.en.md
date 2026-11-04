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

gala-filetrace uses eBPF to collect configuration-file changes in kernel space and process them in user space. The overall data flow is:

```text
┌─────────────────────── Kernel space (eBPF) ─────────────────────┐
│  tracepoint/fentry hooks                                         │
│   - sys_enter_openat / unlinkat / rename(at/at2) / execve        │
│   - sys_enter_copy_file_range / write (or fentry security_*)     │
│   - sched_process_exec                                           │
│        │ build struct event (pid/ppid/cmd/uid/gid/inode/path)    │
│        ├──► exec_map (HASH): process lineage for ptrace backtrace│
│        └──► events  (RINGBUF, 16MB): deliver file events         │
└───────────────────────────────┬─────────────────────────────────┘
                                │ ring_buffer__poll
┌───────────────────────────────▼───── User space ────────────────┐
│  handle_event → PostData::process_event                          │
│        │ is_valid_event filtering (path in config_list, skip)    │
│        ├──► PrometheusExporter: file_access_total / gauge        │
│        ├──► curl HTTP POST → gala-ragdoll (when publish=true)    │
│        └──► cache_event: cache into memory queue for API         │
│                                                                  │
│  cpp-httplib HTTP Server (server:port) serves config/query API   │
└──────────────────────────────────────────────────────────────────┘
```

Core modules:

| Module | File | Responsibility |
| :--- | :--- | :--- |
| eBPF program | `src/filetrace.bpf.c` | Attach syscall/VFS hooks, collect events into the ring buffer |
| Main program | `src/filetrace.cpp` | Load/attach skeleton, poll the ring buffer and dispatch events |
| Event handling | `src/post.cpp` | Filtering, config loading, push to ragdoll, process lineage, HTTP API |
| Metrics export | `src/exporter.cpp` | Integrate with Prometheus, expose counter/gauge metrics |
| Logging | `src/logger.cpp` | Layered logging and file rotation |

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

Configuration description (default path `/etc/gala-filetrace/gala-filetrace.json`, overridable via `-c`):
| Configuration Item | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| host_id | string | none | Host UUID, **required**, startup fails if empty |
| domain_name | string | none | Domain / data center where the host resides, **required** |
| cluster_id | string | `""` | Cluster ID, optional |
| config_list | array | none | Absolute paths of config files to monitor, **required and non-empty** |
| skip_processes_list | array | none | Process names to ignore (noise processes), **required** |
| ragdoll_api | string | none | gala-ragdoll receiving address |
| publish | bool | `false` | Whether to push events to ragdoll; also enables the built-in HTTP Server |
| exporter_address | string | `0.0.0.0:8080` | Prometheus Exporter listening address |
| server | string | `0.0.0.0` | Listening address of the config/query API (must be a valid IPv4) |
| port | int | `8080` | Listening port of the config/query API |
| cache_data | bool | `false` | Whether to cache events in memory for `/monitor_file_status` |
| cache_timeout_seconds | int | `30` | Timeout (seconds) for Prometheus gauge cache records |
| max_event_queue_size | int | `1000` | Maximum number of events kept in the memory queue |
| max_dir_level | int | `4` | Maximum directory depth allowed for `config_list` paths |
| log_level | string | `info` | Log level (debug/info/warn/error) |
| log_file | string | `/var/log/filetrace.log` | Log file path |
| log_size | int | `100` | Maximum size of a single log file (MB) |

Visit <http://IP:9090/Metrics> in a browser to view monitoring metrics.

## 3.6 API Endpoints

The built-in HTTP Server is started only when `publish` is `true` (listening on `server:port`) and provides the endpoints below. `POST /filetrace` and `GET /filetrace` are always available once the server is up; `/monitor_file_status` is registered only when `cache_data` is `true`.

### 3.6.1 Add / remove a monitored file

```
POST /filetrace
Content-Type: application/json

{"conf": "/etc/hosts", "action": "add"}
```

- `action` is `add` or `remove`; `conf` is the absolute path of a config file.
- On success the change is persisted back to the config file.
- Response: `200` on success (`Configuration updated successfully`); `400` for invalid parameters; `500` when writing to disk fails.

Query the current monitored list:

```
GET /filetrace
```

Example response:

```json
{
  "status": "ok",
  "conf_list": ["/etc/hosts"]
}
```

### 3.6.2 Query monitored events

```
GET /monitor_file_status?count=10
```

- `count` is the number of events to return; defaults to `10` when missing/invalid, capped at `max_event_queue_size`.
- `200` when events are returned; `204` with `status` `no_event` when the queue is empty.

Example response:

```json
{
  "status": "ok",
  "count": 1,
  "events": [
    {
      "pid": 1234,
      "ppid": 5678,
      "cmd": "vim",
      "flag": 5,
      "syscall": "sys_enter_write",
      "filename": "hosts",
      "oldfilename": "",
      "dir1": "etc",
      "dir2": "",
      "dir3": "",
      "dir4": ""
    }
  ]
}
```

# 4. QA

## 4.1 The following log appears in dmesg

```text
permission error while running as root; try raising 'ulimit -l'? current value: 64.0 KiB.
 ```

Cause: loading eBPF programs requires raising `RLIMIT_MEMLOCK` (the maximum amount of lockable memory); the default 64 KiB is insufficient.

* Started as a systemd service (recommended): `config/gala-filetrace.service` already sets `LimitMEMLOCK=infinity`, so no manual step is needed.

* When running `filetrace` directly from the command line, raise the limit in the current shell first:

```bash
# ulimit -l 819200  
```
