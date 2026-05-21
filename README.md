# 1.gala-filetrace

gala-filetrace是A-OPS中一个功能组件，主要用于对openEuler系统中配置文件实时监控，也可以监控信息推送到gala-ragdoll。
### 功能介绍：
1. 支持监控以下命令和系统调用：
* 命令：vim/vi、sed、echo、cp、move
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
| openEuler 2403_SP1   | aarch64       |  OK   |需要在内核新增一个helper_func  |
| openEuler 2403_SP1   | x86           |  OK   |需要在内核新增一个helper_func  |
| openEuler 2503       | aarch64       |  OK   |需要在内核新增一个helper_func  |
| openEuler 2503       | x86           |  OK   |需要在内核新增一个helper_func  |
---
关于增加的helper_func接口fd2path具体实现，具体方法参照：4.内核升级。

## 3.1 依赖安装

### 3.1.1 依赖安装（仓库存在）

| 系统版本      | 依赖安装         |
| :---         |    :----:   |
| openEuler 2203_SP3   | # yum install bpftrace libcurl-devel libbpf-devel cpp-httplib-devel zlib-devel nlohmann-json-devel bpftool clang llvm  cpp-httplib-devel   |
---
<font color="red">注意：openeuler 2203 lts 中cpp-httplib-devel替换为cpp-httplib；libbpf版本0.8以上</font>

---

### 3.1.2 依赖安装（仓库不存在）

* 源码安装

```bash
# git clone https://github.com/jupp0r/prometheus-cpp.git
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
#debug add bpf_printk cat /sys/kernel/debug/tracing/trace_pipe
# make DEBUG=1
```

### 3.2.1 rpm 构建

```bash
# wget -O ~/rpmbuild/SOURCES/master.zip https://atomgit.com/openEuler/gala-filetrace/repository/archive/master.zip
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
主要包括：iPad mini 、罗技键盘、吹风机，以及台式机配件。

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

浏览器访问http://IP:9090/Metrics，可以查看监控指标。


# 4.内核升级

在内核6.6.0中，无法从task_struct中获取进程中fd列表了。所以只能通过在内核中增加接口来实现。
下图是从ebpf探针中获取文件名称的方法：
<img src="./img/getfilename.png" width="600" height="400">

以下升级内核参照示例，具体需要根据实际环境执行。

## 4.1 kernel源码安装

```bash
# yum download kernel-source-6.6.0-72.6.0.56.oe2503.x86_64
# rpm -ivh kernel-source-6.6.0-72.6.0.56.oe2503.x86_64*
# cp /boot/config-6.6.0-72.6.0.56.oe2503.x86_64 .config
```

### 应用patch

```bash
# patch -p1 < /path/to/my_patch.patch
```

## 4.2 编译

```bash
# make O=out
```

## 4.3 安装模块

```bash
# make O=out modules_install
```

默认安装到/lib/modules/

## 4.4  安装内核映像

```bash
# make O=out install
```

安装 vmlinuz、System.map、config 等到 /boot/

# 5.QA

## 1.dmesg中出现以下日志

```text
permission error while running as root; try raising 'ulimit -l'? current value: 64.0 KiB.
 ```

解决方法：

```bash
# ulimit -l 819200
```
