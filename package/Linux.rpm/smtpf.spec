%define libver 1.65.912

Summary: SMTP Filtering Proxy for Anti-Spam/Anti-Virus protection
Name: smtpf
Version: 1.0
Release: 147
Vendor: Fort Systems Ltd.
Packager: Steve Freegard <steve.freegard@fsl.com>
License: propritary
Group: Internet/E-Mail
URL: http://www.snertsoft.com/smtp/smtpf/
Source: libsnert-%{libver}.tar.gz
Source1: smtpf-%{version}.%{release}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: gcc gcc-c++ tcl-devel
Requires: /sbin/chkconfig, /sbin/service, /usr/sbin/useradd, /usr/sbin/groupadd, /usr/sbin/groupdel, /usr/sbin/userdel
AutoReqProv: no

%description
smtpf sits in front of one or more mail transfer agents (MTA) on SMTP port 25. It acts as a proxy, filtering and forwarding mail to one or more MTAs, which can be on the same machine or different machines.

smtpf supports a variety of well blended anti-spam filtering techniques that can be individually enabled or disabled according to the rigours of the postmaster's local filtering policy.

%prep
# Delete any old directories from previous runs
rm -rf $RPM_BUILD_DIR/com $RPM_BUILD_DIR/org
# Unpack libsnert
%setup -T -b 0 -n com
# Unpack smtpf, do not delete the com directory first!
%setup -D -b 1 -n com

%build
# Build libsnert
cd snert/src/lib
%configure --without-db --enable-fcntl-locks
make
# Build smtpf
cd ../%{name}-%{version}
%configure
make

%install
rm -rf $RPM_BUILD_ROOT
cd snert/src/%{name}-%{version}
make DESTDIR=$RPM_BUILD_ROOT install

# Handle ghost files
touch $RPM_BUILD_ROOT/etc/smtpf/access.sq3
touch $RPM_BUILD_ROOT/etc/smtpf/route.sq3
touch $RPM_BUILD_ROOT/var/cache/smtpf/stats.sq3
touch $RPM_BUILD_ROOT/var/cache/smtpf/cache.sq3

%pre
# Create user if missing
/usr/sbin/groupadd -r %{name} 2> /dev/null || :
/usr/sbin/useradd -c %{name} -s /sbin/nologin -r -d /var/tmp -g %{name} %{name} 2> /dev/null || :

%post
/sbin/chkconfig --add %{name} 2>&1 > /dev/null || :

if [ $1 -gt 1 ]; then
	# Upgrade
	# Build a new smtpf.cf file
	make -C/etc/smtpf newconfig 2>&1 > /dev/null
	# Restart smtpf if it was already running
	/usr/sbin/smtpf +restart-if
else 
	# Install - build maps
	make -C/etc/smtpf 2>&1 > /dev/null
fi

%preun
if [ $1 -eq 0 ]; then
	# Uninstall
	/etc/init.d/smtpf stop 2>&1 > /dev/null ||:
	/sbin/chkconfig --del smtpf 2>&1 > /dev/null ||:
fi

%postun
if [ $1 -eq 0 ]; then
	# Uninstall
	/usr/sbin/userdel smtpf 2> /dev/null ||:
  /usr/sbin/groupdel smtpf 2> /dev/null ||:
fi
	
%clean
rm -rf $RPM_BUILD_DIR/com $RPM_BUILD_DIR/org
rm -rf $RPM_BUILD_ROOT

%files
%attr(2770,root,smtpf) %dir /etc/smtpf
%attr(444,root,smtpf) /etc/smtpf/Makefile
%attr(444,root,smtpf) /etc/smtpf/dump.mk
%attr(664,root,smtpf) %config(noreplace) /etc/smtpf/access.cf
%attr(664,root,smtpf) %config(noreplace) /etc/smtpf/route.cf
%attr(664,root,smtpf) %config(noreplace) /etc/smtpf/smtpf.cf
%attr(555,root,root) /usr/bin/sqlite3t
%attr(555,root,root) /usr/sbin/kvmap
%attr(555,root,root) /usr/sbin/kvmc
%attr(555,root,root) /usr/sbin/kvmd
%attr(555,root,root) /usr/sbin/mcc
%attr(550,root,smtpf) /usr/sbin/%{name}
%attr(775,root,root) /etc/init.d/%{name}
%doc /usr/share/man/cat1/%{name}.0
# Documentation
%docdir /usr/share/doc/%{name}
/usr/share/doc/%{name}
%docdir /usr/share/examples/%{name}
/usr/share/examples/%{name}
# Databases
%attr(664,root,smtpf) %ghost /etc/smtpf/access.sq3
%attr(664,root,smtpf) %ghost /etc/smtpf/route.sq3
%attr(6770,smtpf,smtpf) %dir /var/cache/smtpf
%attr(664,smtpf,smtpf) %ghost /var/cache/smtpf/stats.sq3
%attr(664,smtpf,smtpf) %ghost /var/cache/smtpf/cache.sq3

%changelog
* Thu Jun 14 2007 Steve Freegard <steve.freegard@fsl.com>
- Added restart-if functionality to upgrades
* Mon May 7 2007 Steve Freegard <steve.freegard@fsl.com>
- First version
