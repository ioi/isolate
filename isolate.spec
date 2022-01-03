%define name isolate
%define version 1.8.2
%define unmangled_version c6de75994cd50040b82b70bf6e5f8dbd02a2cd96
%define release 1
# %define boxdir %{_sharedstatedir}/%{name}
%define boxdir /var/local/lib/%{name}
%define confdir %{_sysconfdir}/%{name}
%define conffile %{confdir}/default.cf

Summary: Isolate sandbox built for safely running untrusted executables
Name: %{name}
Version: %{version}
Release: %{release}
Source0: https://github.com/ReCodEx/%{name}/archive/%{unmangled_version}.tar.gz#/%{name}-%{unmangled_version}.tar.gz
# Patch0: https://raw.githubusercontent.com/ReCodEx/utils/master/isolate-fix-rlimit-nofile.patch
License: GPLv2+
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
Url: https://github.com/ReCodEx/isolate
BuildRequires: gcc asciidoc libcap-devel
Requires: libcap

%global debug_package %{nil}

%description
Isolate is a sandbox built to safely run untrusted executables, offering them a
limited-access environment and preventing them from affecting the host system.
It takes advantage of features specific to the Linux kernel, like namespaces
and control groups.

%prep
%autosetup -n %{name}-%{unmangled_version}

%build
%make_build BINDIR=%{_bindir} CONFIG=%{conffile}

%install
mkdir -p %{buildroot}%{confdir} %{buildroot}%{boxdir}
%make_install BINDIR=%{buildroot}%{_bindir} CONFIG=%{buildroot}%{conffile} BOXDIR=%{buildroot}%{boxdir}
make install-doc MANDIR=%{buildroot}/%{_mandir}

%clean
make clean

%post

%postun

%pre

%preun

%files
%defattr(-,root,root)
%dir %{confdir}
%dir %{boxdir}

%{_bindir}/%{name}
%{_bindir}/isolate-check-environment
%config(noreplace) %{conffile}
%{_mandir}/man1/%{name}.1.gz

%changelog

