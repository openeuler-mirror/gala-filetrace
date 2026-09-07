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

### 3.2.1 rpm 构建

```bash
# wget -O ~/rpmbuild/SOURCES/master.zip https://raw.atomgit.com/openeuler/gala-filetrace/archive/refs/heads/master.zip
# git clone https://atomgit.com/openeuler/gala-filetrace.git
# rpmbuild -ba config/gala-filetrace.spec  
```

构建成功后，在/root/rpmbuild/RPMS/\<arch>目录下存在gala-filetrace的rpm包。

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

配置说明:
| 配置项        | 值         |  说明          |
| :---         |    :----:   |          ---: |
| host_id       | string          | 主机UUID
| domain_name       | string      | 主机所在域/数据中心    |
| ragdoll_api       | string           |  ragdoll 地址   |
| publish       | bool         |     是否推送到ragdoll |
| exporter_address  |string   |  Prometheus Node Exporter监听地址 |
|

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
