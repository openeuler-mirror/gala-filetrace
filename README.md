# 1.gala-filetrace

gala-filetrace是A-OPS中一个功能组件，主要用于对openEuler系统中配置文件实时监控,也可以监控信息推送到gala-ragdoll。
支持监控以下命令和系统调用：
命令：
#### vim/vi,sed,echo,cp,move
#### syscall write

# 2.编译和运行

目前适配支持的openEuler版本:
| 系统版本      | 架构         |  适配          |
| :---         |    :----:   |          ---: |
| openEuler 2203_SP3   | aarch64       |  OK   |
| openEuler 2203_SP3   | x86           |  OK   |
| openEuler 2403_SP1   | aarch64       |  OK   |
| openEuler 2403_SP1   | x86           |  OK   |
| openEuler 2503       | aarch64       |  OK   |
| openEuler 2503       | x86           |  OK   |
---
### 2.1 依赖安装
| 系统版本      | 依赖安装         |
| :---         |    :----:   | 
| openEuler 2203_SP3   | # yum install bpftrace libcurl-devel libbpf-devel cpp-httplib-devel zlib-devel nlohmann-json-devel bpftool clang llvm  cpp-httplib-devel   |


### 2.2 编译
```bash
# make
#debug  add bpf_printk cat /sys/kernel/debug/tracing/trace_pipe
#make DEBUG=1
    
```
### 2.3 运行
```bash
# ./filetrace
```
## 2.4 配置说明
配置说明:
| 配置项        | 值         |  说明          |
| :---         |    :----:   |          ---: |
| host_id       | string          |     |
| domain_name       | string           |     |
| ragdoll_api       | string           |     |
| publish       | bool         |     是否推送到ragdoll |

