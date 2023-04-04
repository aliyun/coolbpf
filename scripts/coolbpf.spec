%define anolis_release 1
%define debug_package %{nil}
%global libver       1.0.0

Name:           coolbpf
Version:        1.0.0
Release:        %{anolis_release}%{?dist}
Summary:        coolbpf library

License:        LGPLv2 or BSD
URL:            https://gitee.com/anolis/%{name}
Source:         https://gitee.com/anolis/%{name}/archive/coolbpf-v%{version}.tar.gz
BuildRequires:  gcc elfutils-libelf-devel elfutils-devel
BuildRequires:  cmake

%description
coolbpf's target is to build a platform for bpf compile collection,
which is for creating efficient kernel tracing and manipulation
programs, is to wrapper main functions of libbpf for user development.

%package devel
Summary:        Development files for %{name}
Requires:       %{name} = %{EVR}
Requires:       kernel-headers >= 5.10.0
Requires:       zlib

%description devel
The %{name}-devel package contains libraries header files for
developing applications that use %{name}

%define _lto_cflags %{nil}
%undefine _package_note_file

%prep
%autosetup -n %{name}-v%{version} -p1

%build
mkdir -p build
cd build
cmake -DINSTALL_LIB_DIR=%{buildroot}/%{_libdir} -DINSTALL_INCLUDE_DIR=%{buildroot}/%{_includedir} ..
make

%install
cd build
make install 


%files
%{_libdir}/libcoolbpf.so.*
%{_libdir}/libcoolbpf.so

%files devel
%{_libdir}/libcoolbpf.so
%{_includedir}/coolbpf/
%{_libdir}/pkgconfig/coolbpf.pc

%changelog
* Mon Apr 03 2023 Shuyi Cheng <chengshuyi.csy@linux.alibaba.com> - 1.0.0-1
- Init for Anolis OS 23
