%if %{?debug:0}%{!?debug:1}
%define debug 0
%endif

%if %{?profiling:0}%{!?profiling:1}
%define profiling 0
%endif


# Libnsert version to use
%define libver 1.69.24

Name: smtpf
Summary: SMTP Filtering Proxy for Anti-Spam/Anti-Virus protection
Version: 2.2
Release: 2
Vendor: Fort Systems Ltd.
Packager: Steve Freegard <steve.freegard@fsl.com>
License: propritary
Group: Internet/E-Mail
URL: http://www.snertsoft.com/smtp/smtpf/
Source: libsnert-%{libver}.tar.gz
Source1: smtpf-%{version}.%{release}.tar.gz
Source2: p0f.tgz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: gcc gcc-c++ tcl-devel libpcap
Requires: /sbin/chkconfig, /sbin/service, /usr/sbin/useradd, /usr/sbin/groupadd, /usr/sbin/groupdel, /usr/sbin/userdel
Provides: smtpf
Obsoletes: smtpf smtpf-debug
AutoReqProv: no
# Patch0: smtpf-uribl-shortcut.patch

%description
smtpf sits in front of one or more mail transfer agents (MTA) on SMTP port 25. It acts as a proxy, filtering and forwarding mail to one or more MTAs, which can be on the same machine or different machines.

smtpf supports a variety of well blended anti-spam filtering techniques that can be individually enabled or disabled according to the rigours of the postmaster's local filtering policy.

%prep
# Delete any old directories from previous runs
rm -rf $RPM_BUILD_DIR/com $RPM_BUILD_DIR/org

# Build p0f first
%setup -T -b 2 -n p0f
make

# Unpack libsnert
%setup -T -b 0 -n com
# Unpack smtpf, do not delete the com directory first!
%setup -D -b 1 -n com
# %patch -p1

%build
# Build libsnert
cd ../com
%if %profiling
 echo -en "\n\n==========\nEnabling Profiling\n==========\n\n"
 CFLAGS=-pg
 LDFLAGS=-pg
 sleep 2
%endif 
# Build libsnert
cd snert/src/lib
FLAGS="--without-db --enable-fcntl-locks --enable-pdq"
BITS=`uname -m | grep "64"` ||:
if [ -n "$BITS" ];
then
 echo -en "\n\n==========\n64bit support enabled\n==========\n\n"
 FLAGS="$FLAGS --enable-64bit"
 sleep 2
fi
%if %debug
 # Set no optimizations to aid debugging
 echo -en "\n\n==========\nDebugging enabled\n==========\n\n"
 sleep 2
 CFLAGS="$CFLAGS -O0" %configure $FLAGS --enable-debug
%else
 %configure $FLAGS
%endif
make
# Build smtpf
cd ../smtpf-%{version}
%configure --with-p0f=$RPM_BUILD_DIR/p0f
make

%install
rm -rf $RPM_BUILD_ROOT
cd snert/src/smtpf-%{version}
#cd snert/src/smtpf-2.0
make DESTDIR=$RPM_BUILD_ROOT install

# Handle ghost files
touch $RPM_BUILD_ROOT/etc/smtpf/access.sq3
touch $RPM_BUILD_ROOT/etc/smtpf/route.sq3
touch $RPM_BUILD_ROOT/var/cache/smtpf/stats.sq3
touch $RPM_BUILD_ROOT/var/cache/smtpf/cache.sq3

# Create empty smtpf.cf file
$RPM_BUILD_ROOT/usr/sbin/smtpf file=/dev/null +help > $RPM_BUILD_ROOT/etc/smtpf/smtpf.cf || :

# Copy Perl utility script
mkdir -p $RPM_BUILD_ROOT/etc/cron.daily
mkdir -p $RPM_BUILD_ROOT/etc/cron.hourly
mv $RPM_BUILD_ROOT/usr/share/examples/smtpf/extra/bmx-uribl-update.pl $RPM_BUILD_ROOT/etc/cron.daily/
mv $RPM_BUILD_ROOT/usr/share/examples/smtpf/extra/bmx-antiphishingreply-update.pl $RPM_BUILD_ROOT/etc/cron.hourly/

# Move this
mv $RPM_BUILD_ROOT/usr/share/examples/smtpf/spamassassin/barricademx.cf $RPM_BUILD_ROOT/usr/share/examples/smtpf
# Nuke these
rm $RPM_BUILD_ROOT/usr/share/examples/smtpf/spamassassin/smf.cf
rm $RPM_BUILD_ROOT/usr/share/examples/smtpf/spamassassin/smf.pm


%pre
# Create user if missing
mkdir -p /var/tmp > /dev/null 2>&1 ||:
/usr/sbin/useradd -s /sbin/nologin -r -d /var/tmp smtpf > /dev/null 2>&1 || :
# Check for 1.x upgrade
if [ -x /usr/sbin/smtpf ]; then
 /usr/sbin/smtpf +help | grep 'smtpf 1.0' > /dev/null 2>&1
 if [ $? -eq 0 ]; then
  # 1.x upgrade
  touch /etc/smtpf/v1-upgrade
 fi
fi

%post
/sbin/chkconfig --add smtpf > /dev/null 2>&1 || :

# Disable sync-on-write on maillog; this greatly improves
# performance and reduces CPU usage on mail servers.
if [ -z "`grep '\-/var/log/maillog' /etc/syslog.conf`" ]; then
 perl -pi - /etc/syslog.conf << 'EOF'
s!\s*/var/log/maillog!-/var/log/maillog!g;
EOF
 # Restart syslog
 /sbin/service syslog restart > /dev/null 2>&1
fi

if [ "$1" -gt 1 ]; then
 # Upgrade
 if [ -a /etc/smtpf/v1-upgrade ]; 
 then
  /usr/sbin/smtpf +grey-content +help > /etc/smtpf/smtpf.cf.new
  mv /etc/smtpf/smtpf.cf.new /etc/smtpf/smtpf.cf
  grep -E '^cache-path=' /etc/smtpf/smtpf.cf | xargs rm -f
  rm -f /etc/smtpf/v1-upgrade
 else
  # Build a new smtpf.cf file
  make -C/etc/smtpf newconfig > /dev/null 2>&1
 fi

 # Restart smtpf if it was already running
 /usr/sbin/smtpf +restart-if ||:
else 
 # Install - build maps
 make -C/etc/smtpf > /dev/null 2>&1
fi

%preun
if [ $1 -eq 0 ]; then
 # Uninstall
 /etc/init.d/smtpf stop > /dev/null 2>&1 ||:
 /sbin/chkconfig --del smtpf > /dev/null 2>&1 ||:
fi

%postun
if [ $1 -eq 0 ]; then
 # Uninstall
 /usr/sbin/userdel smtpf > /dev/null 2>&1 ||:
 /usr/sbin/groupdel smtpf > /dev/null 2>&1 ||:
fi

%triggerin -- fsl-spamassassin, spamassassin
# Only run on first installation of this package
if [ "$2" = "1" ]; then
 echo "smtpf install trigger: spamassassin" 
 # Install BarricadeMX rules for SpamAssassin
 cp /usr/share/examples/smtpf/barricademx.cf /etc/mail/spamassassin/
 # Enable SA if it is disabled and MailScanner is not installed
 if [ ! -e "/usr/sbin/MailScanner" ]; then
  %{__perl} -pi - /etc/smtpf/smtpf.cf << 'EOF'
s+^spamd-socket=$+spamd-socket=127.0.0.1:783+i;
EOF
  # Start SpamAssassin
  /sbin/chkconfig --add spamassassin 2>&1 > /dev/null || :
  /sbin/chkconfig spamassassin on || :
  /sbin/service spamassassin start  > /dev/null 2>&1 ||:
 else 
  echo "Not enabling spamassassin in smtpf.cf as MailScanner is installed."
 fi
fi

%triggerun -- fsl-spamassassin, spamassassin
# Only run on uninstall
if [ "$2" = "0" ]; then 
 echo "smtpf uninstall trigger: fsl-spamassassin"
 # Disable spamd if it is enabled
 %{__perl} -pi - /etc/smtpf/smtpf.cf << 'EOF'
 s+^spamd-socket=127.0.0.1:783+spamd-socket=+i;
EOF
fi

%triggerin -- clamd
# Only run on install
if [ "$2" = "1" ]; then
 echo "smtpf install trigger: clamd"
 # Add clamav to the smtpf group so that clamd can read temp files
 /usr/sbin/usermod -a -G smtpf clamav
 # Enable clamd only if MailScanner is not installed
 if [ ! -e "/usr/sbin/MailScanner" ]; then
  %{__perl} -pi - /etc/smtpf/smtpf.cf << 'EOF'
s!^clamd-socket=$!clamd-socket=SCAN!;
EOF
  # Enable and start clamd service
  /sbin/chkconfig clamd on > /dev/null 2>&1 ||:
  /sbin/service clamd restart > /dev/null 2>&1 ||:
  # Enable and start freshclam service
  /sbin/chkconfig freshclam on > /dev/null 2>&1 ||:
  /sbin/service freshclam restart > /dev/null 2>&1 ||:
 else
  echo "Not enabling clamd in smtpf.cf as MailScanner is installed."
 fi
fi

%triggerun -- clamd
# Only run on uninstall
if [ "$2" = "0" ]; then
 echo "smtpf uninstall trigger: clamd"
 %{__perl} -pi - /etc/smtpf/smtpf.cf << 'EOF'
s!^clamd-socket=SCAN!clamd-socket=!;
EOF
fi

%triggerin -- fsmg-web
# Only run on first install
if [ "$2" = "1" ]; then
 echo "smtpf install trigger: fsmg-web"
 %{__perl} -pi - /opt/Fortress/defaults/incoming.mc << 'EOF'
s+^dnl DAEMON_OPTIONS\(\`Port=smtp,Addr=127.0.0.1, Name=MTA\'\)dnl+DAEMON_OPTIONS\(\`Port=26,Addr=127.0.0.1, Name=MTA\'\)dnl+;
s+^sinclude\(+dnl sinclude\(+;
EOF
 /usr/bin/m4 /opt/Fortress/defaults/incoming.mc > /opt/Fortress/defaults/incoming.cf ||:
 /sbin/service MailScanner restart > /dev/null 2>&1 ||:
fi

%triggerin -- sendmail-cf
# Only run on install
if [ "$2" = "1" ]; then
 echo "smtpf install trigger: sendmail-cf"
 %{__perl} -pi - /etc/mail/sendmail.mc << 'EOF'
s+^DAEMON_OPTIONS\(\`Port=smtp, Name=MTA\'\)dnl+DAEMON_OPTIONS\(\`Port=26,Addr=127.0.0.1,Name=MTA\'\)dnl+;
s+^DAEMON_OPTIONS\(\`Port=smtp,Addr=127.0.0.1, Name=MTA\'\)dnl+DAEMON_OPTIONS\(\`Port=26,Addr=127.0.0.1,Name=MTA\'\)dnl+;
EOF
 make -C/etc/mail > /dev/null 2>&1
 if [ -e "/etc/init.d/MailScanner" ]; then
  /sbin/service MailScanner restart > /dev/null 2>&1 ||:
 elif [ -e "/opt/Fortress/engine/bin/MailScanner" ]; then
  # DefenderMX v1 installed - skip; fsmg-web trigger will handle set-up
  :
 else
  /sbin/chkconfig sendmail on
  /sbin/service sendmail condrestart > /dev/null 2>&1 ||:
 fi
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
%attr(664,root,smtpf) /etc/smtpf/access-defaults.cf
%attr(555,root,root) /usr/bin/sqlite3t
%attr(555,root,root) /usr/bin/uri
%attr(555,root,root) /usr/bin/spf
%attr(555,root,root) /usr/bin/show
%attr(555,root,root) /usr/sbin/kvmap
%attr(555,root,root) /usr/sbin/kvmc
%attr(555,root,root) /usr/sbin/kvmd
%attr(555,root,root) /usr/sbin/mcc
%attr(550,root,smtpf) /usr/sbin/smtpf
%attr(775,root,root) /etc/init.d/smtpf
%attr(775,root,root) /etc/cron.daily/bmx-uribl-update.pl
%attr(775,root,root) /etc/cron.hourly/bmx-antiphishingreply-update.pl
%doc /usr/share/man/cat1/smtpf.0
# Documentation
%docdir /usr/share/doc/smtpf
/usr/share/doc/smtpf
%docdir /usr/share/examples/smtpf
/usr/share/examples/smtpf
# Databases
%attr(664,root,smtpf) %ghost /etc/smtpf/access.sq3
%attr(664,root,smtpf) %ghost /etc/smtpf/route.sq3
%attr(6770,smtpf,smtpf) %dir /var/cache/smtpf
%attr(664,smtpf,smtpf) %ghost /var/cache/smtpf/stats.sq3
%attr(664,smtpf,smtpf) %ghost /var/cache/smtpf/cache.sq3

%changelog
* Fri Jan 1 2009 Steve Freegard <steve.freegard@fsl.com>
- Disabled sync-on-write for /var/log/maillog for extra performance
- Added triggers for Sendmail, Clamd, SpamAssassin and MailScanner
* Wed Sep 19 2007 Steve Freegard <steve.freegard@fsl.com>
- Added debug conditionals
* Thu Jun 14 2007 Steve Freegard <steve.freegard@fsl.com>
- Added restart-if functionality to upgrades
* Mon May 7 2007 Steve Freegard <steve.freegard@fsl.com>
- First version
