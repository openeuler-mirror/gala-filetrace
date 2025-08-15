Name:           gala-filetrace
Version:        1.0
Release:        1%{?dist}
Summary:        Real-time file trace tool for openEuler

License:        MIT
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  bpftool
BuildRequires:  libcurl-devel
BuildRequires:  libelf-devel
BuildRequires:  libbpf-devel
BuildRequires:  zlib-devel
BuildRequires:  nlohmann-json-devel
BuildRequires:  cpp-httplib-devel

Requires:       libcurl
Requires:       libelf
Requires:       libbpf
Requires:       zlib
Requires:       nlohmann-json
Requires:       cpp-httplib

%description
gala-filetrace is a real-time file trace tool for openEuler.

%prep
%setup -q

%build
make

%install
install -d %{buildroot}/usr/bin
install -m 755 filetrace %{buildroot}/usr/bin/filetrace

%files
/usr/bin/filetrace

%changelog
* Fri Aug 15 2025 zhangdaolong <dlzhangak@isoftstone.con> - 1.0-1
- Initial package
