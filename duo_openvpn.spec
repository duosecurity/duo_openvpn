%define name	duo_openvpn
%define version	0.1
%define release 2
%define prefix	/usr

%define mybuilddir %{_builddir}/%{name}-%{version}-root

Summary:	Duo two-factor authentication for OpenVPN
Name:		%{name}
Version:	%{version}
License:	BSD
Release:	%{release}
Packager:	Jan Schaumann <jschauma@etsy.com>
Group:		Utilities/Misc
Source:		%{name}-%{version}.tar.gz
BuildRoot:	/tmp/%{name}-%{version}-root

Requires:	python26, perl, perl-JSON-XS, perl-Digest-HMAC, perl-URI

%description
Duo provides simple two-factor authentication as a service via:

* Phone callback
* SMS-delivered one-time passcodes
* Duo mobile app to generate one-time passcodes
* Duo mobile app for smartphone push authentication
* Duo hardware token to generate one-time passcodes

This package provides the OpenVPN authentication plugin and scripts.

%prep
%setup -q

%setup
mkdir -p %{mybuilddir}%{prefix}/bin
mkdir -p %{mybuilddir}%{prefix}/lib
mkdir -p %{mybuilddir}%{prefix}/share/duo

%build
make

%install
cp ca_certs.pem %{mybuilddir}%{prefix}/share/duo/ca_certs.pem
cp %{name}.pl %{mybuilddir}%{prefix}/share/duo/%{name}.pl
cp %{name}.py %{mybuilddir}%{prefix}/share/duo/%{name}.py
cp %{name}.so %{mybuilddir}%{prefix}/lib/%{name}.so
cp https_wrapper.py %{mybuilddir}%{prefix}/share/duo/https_wrapper.py
ln -s %{prefix}/share/duo/%{name}.py %{mybuilddir}%{prefix}/bin/%{name}

%files
%defattr(0755,root,root)
%{prefix}/bin/%{name}
%{prefix}/lib/%{name}.so
%{prefix}/share/duo/ca_certs.pem
%{prefix}/share/duo/%{name}.pl
%{prefix}/share/duo/%{name}.py
%attr(0644,root,root)%{prefix}/share/duo/https_wrapper.py

%changelog
* Mon Jul 09 2012 Jan Schaumann <jschauma@etsy.com>
- first rpm version
