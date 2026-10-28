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

## 3.3 终端 UI（top 风格）

在配置文件 `/etc/gala-filetrace/gala-filetrace.json` 的 `config_list` 中配置需要监控的文件，然后以 TUI 模式运行：

```bash
# TUI 模式（读取 config_list，实时显示哪些进程修改了监控文件）
filetrace -t

# 指定配置文件 / 刷新间隔
filetrace -t -c /path/to/gala-filetrace.json -r 500

# 独立预览（不加载 eBPF，用模拟数据演示界面）
filetrace-tui -d
```

界面分为三部分：顶部状态栏（事件总数、进程数、刷新时间）、上方"Monitored Files"面板（每个监控文件的操作分类计数：OPS/WRITE/OPEN/UNLINK/RENAME/OTHER）、下方进程表（PID/PPID/USER/%CPU/%MEM/OPS/COMMAND）。

按键说明：

| 按键 | 操作 |
| ---- | ---- |
| h / ? | 打开/关闭帮助，仍继续采样 |
| q | 主界面退出；帮助/详情页返回 |
| Tab | 切换设备 / 进程列表焦点 |
| 上下箭头、j / k | 进程焦点时移动选择；设备焦点时滚动列表 |
| PageUp / PageDown、Home / End | 翻页或到首尾 |
| 左右箭头 | 横向查看长命令行 |
| 鼠标左键点击 %MEM / %CPU / OPS 表头 | 切换排序列时默认降序，再点当前列切换升降序 |
| s / S | 按 OPS → %MEM → %CPU 循环切换排序列，每次切换恢复降序 |
| / | 反转当前排序方向 |
| 鼠标左键点击进程行 | 选中进程；点击排序表头以外的非进程区域取消选择 |
| Enter | 打开选中进程的详情；详情页内返回进程列表 |
| Esc | 帮助/详情返回；列表中先取消选择，无选择时退出 |

## 3.4 安装

### 3.4.1 编译安装

```bash
#default install
# make install
#Custom installation dir
# make install DESTDIR=/your/install/path
```

### 3.4.2 rpm 安装

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

配置说明:
| 配置项        | 值         |  说明          |
| :---         |    :----:   |          ---: |
| host_id       | string          | 主机UUID
| domain_name       | string      | 主机所在域/数据中心    |
| ragdoll_api       | string           |  ragdoll 地址   |
| publish       | bool         |     是否推送到ragdoll |
| exporter_address  |string   |  Prometheus Node Exporter监听地址 |

浏览器访问 <http://IP:9090/Metrics>，可以查看监控指标。

# 4.QA

## 4.1 dmesg中出现以下日志

```text
permission error while running as root; try raising 'ulimit -l'? current value: 64.0 KiB.
 ```

解决方法：

```bash
# ulimit -l 819200
```
