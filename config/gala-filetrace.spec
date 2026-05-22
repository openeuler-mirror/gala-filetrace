Name:           gala-filetrace
Version:        1.0
Release:        2%{?dist}
Summary:        Real-time file trace tool for openEuler

License:        MIT
Source0:        https://raw.atomgit.com/openeuler/gala-filetrace/archive/refs/heads/master.zip

BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  bpftool
BuildRequires:  libcurl-devel
#BuildRequires:  libelf-devel
BuildRequires:  libbpf-devel
BuildRequires:  zlib-devel
BuildRequires:  nlohmann-json-devel
BuildRequires:  cpp-httplib-devel

Requires:       libcurl
Requires:       libbpf
Requires:       zlib
Requires:       nlohmann-json
Requires:       cpp-httplib

%define debug_package %{nil}

%description
gala-filetrace is a real-time file trace tool for openEuler.

%prep

%setup -q -n gala-filetrace-master

%build
make

%install
install -d %{buildroot}/usr/bin
install -m 755 filetrace %{buildroot}/usr/bin/filetrace

install -d %{buildroot}/etc/gala-filetrace/gala-filetrace.json
install -m 644 config/filetrace.json %{buildroot}/etc/gala-filetrace/gala-filetrace.json

install -d %{buildroot}/usr/lib/systemd/system
install -m 644 config/gala-filetrace.service %{buildroot}/usr/lib/systemd/system/gala-filetrace.service

%post
# 安装后设置服务自启动并启动服务
systemctl enable gala-filetrace.service >/dev/null 2>&1 || :
systemctl restart gala-filetrace.service >/dev/null 2>&1 || :

%preun
# 卸载前关闭服务并禁用自启动
if [ $1 -eq 0 ]; then
    systemctl stop gala-filetrace.service >/dev/null 2>&1 || :
    systemctl disable gala-filetrace.service >/dev/null 2>&1 || :
fi
rm -rf /etc/gala-filetrace/filetrace.json 2>&1
rm -rf /usr/lib/systemd/system/gala-filetrace.service 2>&1

%files
/usr/bin/filetrace
/etc/gala-filetrace/gala-filetrace.json
/usr/lib/systemd/system/gala-filetrace.service

%clean
rm -rf %{buildroot}

%changelog
* Fri May 22 2026 yang-zongw <zwyangah@isoftstone.com> - 1.0-2
- Switch Source0 to official openEuler repository on AtomGit

* Fri Aug 15 2025 zhangdaolong <dlzhangak@isoftstone.com> - 1.0-1
- Initial package
