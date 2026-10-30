# 1.gala-filetrace

[English](./README.en.md) | 简体中文

gala-filetrace是A-OPS中一个功能组件，主要用于对openEuler系统中配置文件实时监控，也可以监控信息推送到gala-ragdoll。

## 功能介绍

1. 支持监控以下命令和系统调用：
   * 命令：vim/vi、sed、echo、cp、mv
   * 系统调用：write
2. 支持对接 Prometheus
3. 提供API设置监控文件
4. web UI(待开发）

---

# 2.实现架构

gala-filetrace 基于 eBPF 实现对配置文件变更的内核态采集与用户态处理，整体数据流如下：

```text
┌───────────────────────── 内核态 (eBPF) ─────────────────────────┐
│  tracepoint/fentry 钩子                                          │
│   - sys_enter_openat / unlinkat / rename(at/at2) / execve        │
│   - sys_enter_copy_file_range / write (或 fentry security_*)     │
│   - sched_process_exec                                           │
│        │ 组装 struct event（pid/ppid/cmd/uid/gid/inode/路径链）  │
│        ├──► exec_map (HASH)：缓存进程血缘，供用户态回溯 ptrace   │
│        └──► events  (RINGBUF, 16MB)：投递文件事件到用户态        │
└───────────────────────────────┬─────────────────────────────────┘
                                │ ring_buffer__poll
┌───────────────────────────────▼───── 用户态 ────────────────────┐
│  handle_event → PostData::process_event                          │
│        │ is_valid_event 过滤（路径命中 config_list、跳过噪声进程）│
│        ├──► PrometheusExporter：更新 file_access_total / gauge    │
│        ├──► curl HTTP POST → gala-ragdoll（publish=true 时）      │
│        └──► cache_event：缓存到内存队列，供 API 查询             │
│                                                                  │
│  cpp-httplib HTTP Server（server:port）提供监控文件配置/查询 API │
└──────────────────────────────────────────────────────────────────┘
```

核心模块：

| 模块 | 文件 | 职责 |
| :--- | :--- | :--- |
| eBPF 程序 | `src/filetrace.bpf.c` | 挂载系统调用/VFS 钩子，采集事件并写入 ring buffer |
| 主程序 | `src/filetrace.cpp` | 加载/attach skeleton，轮询 ring buffer 并分发事件 |
| 事件处理 | `src/post.cpp` | 过滤、配置加载、推送 ragdoll、进程血缘回溯、HTTP API |
| 指标导出 | `src/exporter.cpp` | 对接 Prometheus，暴露 counter/gauge 指标 |
| 日志 | `src/logger.cpp` | 分级日志与文件轮转 |

# 3.编译和运行

目前适配支持的openEuler版本:
| 系统版本      | 架构         |  适配          |说明          |
| :---         |    :----:   |          ---: |  ---: |
| openEuler 2203_SP3   | aarch64       |  OK   |无  |
| openEuler 2203_SP3   | x86           |  OK   |无  |
| openEuler 2403_SP1   | aarch64       |  OK   |  |
| openEuler 2403_SP1   | x86           |  OK   |  |
| openEuler 2403_SP4   | aarch64       |  OK   |  |
| openEuler 2403_SP4   | x86           |  OK   |  |
| openEuler 2503       | aarch64       |  OK   |  |
| openEuler 2503       | x86           |  OK   |  |

## 3.1 依赖安装

### 3.1.1 依赖安装（仓库存在）

| 系统版本      | 依赖安装         |
| :---         |    :----:   |
| openEuler 2203_SP3   | # yum install bpftrace libcurl-devel libbpf-devel cpp-httplib-devel zlib-devel nlohmann-json-devel bpftool clang llvm   |
---
<font color="red">注意：cpp-httplib 版本小于 0.22.0 时，cpp-httplib-devel 替换为 cpp-httplib；libbpf 版本 0.8 以上</font>

---

### 3.1.2 依赖安装（仓库不存在）

* 源码安装

```bash
# git clone https://atomgit.com/gh_mirrors/pr/prometheus-cpp.git
# cd prometheus-cpp
# git submodule init && git submodule update
# mkdir build && cd build
# cmake .. -DBUILD_SHARED_LIBS=ON -DENABLE_PULL=ON -DENABLE_PUSH=OFF
# make -j && sudo make install
```

---
<font color="red">注意：源码安装的prometheus-cpp库默认安装位置/usr/local/include/</font>

---

* RPM包安装

```bash
#run cmake
# cmake -B_build -DCPACK_GENERATOR=RPM -DBUILD_SHARED_LIBS=ON # or OFF for static libraries

#build and package
# cmake --build _build --target package --parallel $(nproc)
/root/prometheus-cpp/_build/prometheus-cpp-<version>-<release>.<arch>.rpm
```

## 3.2 编译

### 3.2.1 直接编译

```bash
#编译之前安装依赖包
# make deps
# make
#调试模式：make DEBUG=1 定义 GALA_DEBUG 宏，BPF 侧通过 bpf_printk 输出调试信息
#实时查看：cat /sys/kernel/debug/tracing/trace_pipe
# make DEBUG=1
```

### 3.2.2 rpm 构建

```bash
# 方式一：make rpm（自动下载源码包并执行 rpmbuild）
make rpm

# 方式二：手动执行
# wget -O ~/rpmbuild/SOURCES/master.zip https://raw.atomgit.com/openeuler/gala-filetrace/archive/refs/heads/master.zip
# git clone https://atomgit.com/openeuler/gala-filetrace.git
# rpmbuild -ba config/gala-filetrace.spec  
```

构建成功后，在~/rpmbuild/RPMS/\<arch>目录下存在gala-filetrace的rpm包。

## 3.3 安装

### 3.3.1 编译安装

```bash
#default install
# make install
#Custom installation dir
# make install DESTDIR=/your/install/path
```

### 3.3.2 rpm 安装

```bash
cd ~/rpmbuild/RPMS/<arch>
rpm -ivh gala-filetrace-<version>-<release>.<arch>.rpm
```

## 3.4 启动

* 通过命令启动

```bash
# filetrace
```

* 通过 systemd 服务启动

```bash
# systemctl start gala-filetrace
```

## 3.5 配置说明

配置说明（配置文件默认路径 `/etc/gala-filetrace/gala-filetrace.json`，可用 `-c` 指定）:
| 配置项 | 类型 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| host_id | string | 无 | 主机 UUID，**必填**，为空时启动失败 |
| domain_name | string | 无 | 主机所在域/数据中心，**必填** |
| cluster_id | string | `""` | 集群 ID，可选 |
| config_list | array | 无 | 需监控的配置文件绝对路径列表，**必填且不能为空** |
| skip_processes_list | array | 无 | 忽略的进程名列表（噪声进程），**必填** |
| ragdoll_api | string | 无 | gala-ragdoll 接收地址 |
| publish | bool | `false` | 是否将事件推送到 ragdoll，为 `true` 时启用内置 HTTP Server |
| exporter_address | string | `0.0.0.0:8080` | Prometheus Exporter 监听地址 |
| server | string | `0.0.0.0` | 配置/查询 API 的监听地址（需为合法 IPv4） |
| port | int | `8080` | 配置/查询 API 的监听端口 |
| cache_data | bool | `false` | 是否在内存缓存事件以供 `/monitor_file_status` 查询 |
| cache_timeout_seconds | int | `30` | Prometheus gauge 缓存记录的超时秒数 |
| max_event_queue_size | int | `1000` | 事件内存队列保留的最大条数 |
| max_dir_level | int | `4` | `config_list` 路径允许的最大目录层级 |
| log_level | string | `info` | 日志级别（debug/info/warn/error） |
| log_file | string | `/var/log/filetrace.log` | 日志文件路径 |
| log_size | int | `100` | 单个日志文件大小上限（MB） |

浏览器访问 <http://IP:9090/Metrics>，可以查看监控指标。

## 3.6 API 接口

内置 HTTP Server 仅在 `publish` 为 `true` 时启动（监听 `server:port`），提供以下接口。其中 `POST /filetrace` 与 `GET /filetrace` 在服务启动后始终可用；`/monitor_file_status` 仅在 `cache_data` 为 `true` 时注册。

### 3.6.1 添加/移除监控文件

```
POST /filetrace
Content-Type: application/json

{"conf": "/etc/hosts", "action": "add"}
```

- `action` 取 `add` 或 `remove`；`conf` 为配置文件绝对路径。
- 更新成功后会回写持久化到配置文件。
- 响应：成功 `200`（`Configuration updated successfully`）；参数非法 `400`；写盘失败 `500`。

查询当前监控列表：

```
GET /filetrace
```

响应示例：

```json
{
  "status": "ok",
  "conf_list": ["/etc/hosts"]
}
```

### 3.6.2 查询监控事件

```
GET /monitor_file_status?count=10
```

- `count` 为返回条数，缺省或非法时取 `10`，上限为 `max_event_queue_size`。
- 事件有返回时 `200`；队列为空时 `204` 且 `status` 为 `no_event`。

响应示例：

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

# 4.QA

## 4.1 dmesg中出现以下日志

```text
permission error while running as root; try raising 'ulimit -l'? current value: 64.0 KiB.
 ```

原因：加载 eBPF 程序需要提升 `RLIMIT_MEMLOCK`（可锁定内存上限），默认的 64 KiB 不够用。

* 通过 systemd 服务启动（推荐）：`config/gala-filetrace.service` 已配置 `LimitMEMLOCK=infinity`，无需再手动处理。

* 通过命令行直接运行 `filetrace` 时，需先在当前 shell 提升限制：

```bash
# ulimit -l 819200
```
