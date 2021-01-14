%define __perl_requires %{SOURCE8}

Name:     squid
Version:  4.9
Release:  4
Summary:  The Squid proxy caching server
Epoch:    7
License:  GPLv2+ and (LGPLv2+ and MIT and BSD and Public Domain)
URL:      http://www.squid-cache.org
Source0:  http://www.squid-cache.org/Versions/v4/squid-4.9.tar.xz
Source1:  http://www.squid-cache.org/Versions/v4/squid-4.9.tar.xz.asc
Source2:  squid.logrotate
Source3:  squid.sysconfig
Source4:  squid.pam
Source5:  squid.nm
Source6:  squid.service
Source7:  cache_swap.sh
Source8: perl-requires-squid.sh

Patch0: squid-4.0.11-config.patch
Patch1: squid-3.1.0.9-location.patch
Patch2: squid-3.0.STABLE1-perlpath.patch
Patch3: squid-3.5.9-include-guards.patch
Patch4: squid-4.0.21-large-acl.patch
Patch5: CVE-2019-12528.patch
Patch6: CVE-2020-8517.patch
Patch7: CVE-2020-8449_CVE-2020-8450.patch
Patch8: squid-fix-detection-of-sys-sysctl.h-detection-511.patch
Patch9: CVE-2019-12519.patch

Buildroot: %{_tmppath}/squid-4.9-1-root-%(%{__id_u} -n)
Requires: bash >= 2.0
Requires(pre): shadow-utils
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
BuildRequires: openldap-devel pam-devel openssl-devel krb5-devel libdb-devel expat-devel
BuildRequires: libxml2-devel libcap-devel libecap-devel gcc-c++ libtool libtool-ltdl-devel
BuildRequires: perl-generators pkgconfig(cppunit) autoconf

%description
Squid is a high-performance proxy caching server. It handles all requests in a single,
non-blocking, I/O-driven process and keeps meta data and implements negative caching of failed requests.

%prep
%autosetup -p1

%build
autoconf

CXXFLAGS="$RPM_OPT_FLAGS -fPIC"
CFLAGS="$RPM_OPT_FLAGS -fPIC"
LDFLAGS="$RPM_LD_FLAGS -pie -Wl,-z,relro -Wl,-z,now -Wl,--warn-shared-textrel"

%configure \
   --exec_prefix=%{_prefix} --libexecdir=%{_libdir}/squid \
   --localstatedir=%{_localstatedir} --datadir=%{_datadir}/squid \
   --sysconfdir=%{_sysconfdir}/squid  --with-logdir='%{_localstatedir}/log/squid' \
   --with-pidfile='%{_localstatedir}/run/squid.pid' \
   --disable-dependency-tracking --enable-eui \
   --enable-follow-x-forwarded-for --enable-auth \
   --enable-auth-basic="DB,fake,getpwnam,LDAP,NCSA,PAM,POP3,RADIUS,SASL,SMB,SMB_LM" \
   --enable-auth-ntlm="SMB_LM,fake"  --enable-auth-digest="file,LDAP" \
   --enable-auth-negotiate="kerberos" \
   --enable-external-acl-helpers="LDAP_group,time_quota,session,unix_group,wbinfo_group,kerberos_ldap_group" \
   --enable-storeid-rewrite-helpers="file" --enable-cache-digests \
   --enable-cachemgr-hostname=localhost --enable-delay-pools \
   --enable-epoll --enable-icap-client --enable-ident-lookups \
   %ifnarch %{power64} ia64 x86_64 s390x aarch64
   --with-large-files \
   %endif
   --enable-linux-netfilter --enable-removal-policies="heap,lru" \
   --enable-snmp --enable-ssl --enable-ssl-crtd \
   --enable-storeio="aufs,diskd,ufs,rock" --enable-diskio --enable-wccpv2 \
   --enable-esi --enable-ecap --with-aio --with-default-user="squid" \
   --with-dl --with-openssl --with-pthreads --disable-arch-native \
   --with-pic --disable-security-cert-validators

make DEFAULT_SWAP_DIR=%{_localstatedir}/spool/squid %{?_smp_mflags}

%check
make check
	
%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install
echo "
#
# This is %{_sysconfdir}/httpd/conf.d/squid.conf
#

ScriptAlias /Squid/cgi-bin/cachemgr.cgi %{_libdir}/squid/cachemgr.cgi

# Only allow access from localhost by default
<Location /Squid/cgi-bin/cachemgr.cgi>
 Require local
 # Add additional allowed hosts as needed
 # Require host example.com
</Location>" > $RPM_BUILD_ROOT/squid.httpd.tmp

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig \
         $RPM_BUILD_ROOT%{_sysconfdir}/pam.d $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/ \
         $RPM_BUILD_ROOT%{_sysconfdir}/NetworkManager/dispatcher.d $RPM_BUILD_ROOT%{_unitdir} \
         $RPM_BUILD_ROOT%{_libexecdir}/squid $RPM_BUILD_ROOT%{_sysconfdir}/rc.d/init.d
install -m 644 %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/squid
install -m 644 %{SOURCE3} $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/squid
install -m 644 %{SOURCE4} $RPM_BUILD_ROOT%{_sysconfdir}/pam.d/squid
install -m 644 %{SOURCE6} $RPM_BUILD_ROOT%{_unitdir}
install -m 755 %{SOURCE7} $RPM_BUILD_ROOT%{_libexecdir}/squid
install -m 644 $RPM_BUILD_ROOT/squid.httpd.tmp $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/squid.conf
install -m 644 %{SOURCE5} $RPM_BUILD_ROOT%{_sysconfdir}/NetworkManager/dispatcher.d/20-squid
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/log/squid $RPM_BUILD_ROOT%{_localstatedir}/spool/squid \
         $RPM_BUILD_ROOT%{_localstatedir}/run/squid
chmod 644 contrib/url-normalizer.pl contrib/user-agents.pl
iconv -f ISO88591 -t UTF8 ChangeLog -o ChangeLog.tmp
mv -f ChangeLog.tmp ChangeLog

mkdir -p ${RPM_BUILD_ROOT}%{_tmpfilesdir}
cat > ${RPM_BUILD_ROOT}%{_tmpfilesdir}/squid.conf <<EOF

d /run/squid 0755 squid squid - -
EOF

mkdir -p $RPM_BUILD_ROOT/usr/share/snmp/mibs
mv $RPM_BUILD_ROOT/usr/share/squid/mib.txt $RPM_BUILD_ROOT/usr/share/snmp/mibs/SQUID-MIB.txt

%files
%license COPYING 
%doc CONTRIBUTORS README ChangeLog QUICKSTART src/squid.conf.documented
%doc contrib/url-normalizer.pl contrib/user-agents.pl

%{_unitdir}/squid.service
%attr(755,root,root) %dir %{_libexecdir}/squid
%attr(755,root,root) %{_libexecdir}/squid/cache_swap.sh
%attr(755,root,root) %dir %{_sysconfdir}/squid
%attr(755,root,root) %dir %{_libdir}/squid
%attr(770,squid,root) %dir %{_localstatedir}/log/squid
%attr(750,squid,squid) %dir %{_localstatedir}/spool/squid
%attr(755,squid,squid) %dir %{_localstatedir}/run/squid

%config(noreplace) %attr(644,root,root) %{_sysconfdir}/httpd/conf.d/squid.conf
%config(noreplace) %attr(640,root,squid) %{_sysconfdir}/squid/squid.conf
%config(noreplace) %attr(644,root,squid) %{_sysconfdir}/squid/cachemgr.conf
%config(noreplace) %{_sysconfdir}/squid/mime.conf
%config(noreplace) %{_sysconfdir}/squid/errorpage.css
%config(noreplace) %{_sysconfdir}/sysconfig/squid
%config %{_sysconfdir}/squid/squid.conf.default
%config %{_sysconfdir}/squid/mime.conf.default
%config %{_sysconfdir}/squid/errorpage.css.default
%config %{_sysconfdir}/squid/cachemgr.conf.default
%config(noreplace) %{_sysconfdir}/pam.d/squid
%config(noreplace) %{_sysconfdir}/logrotate.d/squid

%dir %{_datadir}/squid
%attr(-,root,root) %{_datadir}/squid/errors
%attr(755,root,root) %{_sysconfdir}/NetworkManager/dispatcher.d/20-squid
%{_datadir}/squid/icons
%{_sbindir}/squid
%{_bindir}/squidclient
%{_bindir}/purge
%{_mandir}/man8/*
%{_mandir}/man1/*
%{_libdir}/squid/*
%{_datadir}/snmp/mibs/SQUID-MIB.txt
%{_tmpfilesdir}/squid.conf
%exclude %{_sysconfdir}/squid/squid.conf.documented
%exclude %{_bindir}/{RunAccel,RunCache}
%exclude  /squid.httpd.tmp

%pre
if ! getent group squid >/dev/null 2>&1; then
  /usr/sbin/groupadd -g 23 squid
fi

if ! getent passwd squid >/dev/null 2>&1 ; then
  /usr/sbin/useradd -g 23 -u 23 -d /var/spool/squid -r -s /sbin/nologin squid >/dev/null 2>&1 || exit 1 
fi

for i in /var/log/squid /var/spool/squid ; do
        if [ -d $i ] ; then
                for adir in `find $i -maxdepth 0 \! -user squid`; do
                        chown -R squid:squid $adir
                done
        fi
done

exit 0

%post
%systemd_post squid.service

%preun
%systemd_preun squid.service

%postun
%systemd_postun_with_restart squid.service

%triggerin -- samba-common
if ! getent group wbpriv >/dev/null 2>&1 ; then
  /usr/sbin/groupadd -g 88 wbpriv >/dev/null 2>&1 || :
fi
/usr/sbin/usermod -a -G wbpriv squid >/dev/null 2>&1 || \
    chgrp squid /var/cache/samba/winbindd_privileged >/dev/null 2>&1 || :

%changelog
* Mon Jan 11 2021 openEuler Buildteam <buildteam@openeuler.org> - 4.9-4
- Type:cves
- ID:CVE-2019-12519
- SUG:restart
- DESC:fix CVE-2019-12519

* Mon Aug 03 2020 gaihuiying <gaihuiying1@huawei.com> - 4.9-3
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix build error

* Wed Apr 22 2020 openEuler Buildteam <buildteam@openeuler.org> - 4.9-2
- Type:cves
- ID:CVE-2019-12528 CVE-2020-8517 CVE-2020-8449 CVE-2020-8450
- SUG:restart
- DESC:fix CVE-2019-12528 CVE-2020-8517 CVE-2020-8449 CVE-2020-8450

* Tue Jan 14 2020 openEuler Buildteam <buildteam@openeuler.org> - 4.9-1
- Type:NA
- ID:NA
- SUG:NA
- DESC:Package upgrade

* Fri Dec 20 2019  openEuler Buildteam <buildteam@openeuler.org>- 4.2-4
- Type:bugfix
- ID:
- SUG:restart
- DESC:fix bugs

* Wed Sep 25 2019 majun<majun65@huawei.com> - 4.2-3
- Type:cves
- ID:CVE-2019-12525 CVE-2019-12527 CVE-2019-12529 CVE-2019-12854 CVE-2019-13345
- SUG:restart
- DESC:fix cves

* Thu Sep 12 2019 openEuler Buildteam <buildteam@openeuler.org> - 4.2-2
- Package init
