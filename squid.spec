%define __perl_requires %{SOURCE8}

Name:     squid
Version:  5.7
Release:  2
Summary:  The Squid proxy caching server
Epoch:    7
License:  GPLv2+ and (LGPLv2+ and MIT and BSD and Public Domain)
URL:      http://www.squid-cache.org
Source0:  http://www.squid-cache.org/Versions/v5/squid-%{version}.tar.xz
Source1:  http://www.squid-cache.org/Versions/v5/squid-%{version}.tar.xz.asc
Source2:  squid.logrotate
Source3:  squid.sysconfig
Source4:  squid.pam
Source5:  squid.nm
Source6:  squid.service
Source7:  cache_swap.sh
Source8:  perl-requires-squid.sh

Patch0:   squid-4.0.11-config.patch
Patch1:   squid-3.1.0.9-location.patch
Patch2:   squid-3.0.STABLE1-perlpath.patch
Patch3:   squid-3.5.9-include-guards.patch

Requires: bash
Requires: httpd-filesystem
BuildRequires: openldap-devel pam-devel openssl-devel krb5-devel libtdb-devel expat-devel
BuildRequires: libxml2-devel libcap-devel libecap-devel gcc-c++ libtool libtool-ltdl-devel
BuildRequires: perl-generators pkgconfig(cppunit)
BuildRequires: chrpath systemd-devel libatomic

%systemd_requires

Conflicts: NetworkManager < 1.20

%description
Squid is a high-performance proxy caching server. It handles all requests in a single,
non-blocking, I/O-driven process and keeps meta data and implements negative caching of failed requests.

%prep
%autosetup -p1

sed -i 's|@SYSCONFDIR@/squid.conf.documented|%{_pkgdocdir}/squid.conf.documented|' src/squid.8.in

%build
%configure \
   --libexecdir=%{_libdir}/squid --datadir=%{_datadir}/squid \
   --sysconfdir=%{_sysconfdir}/squid  --with-logdir='%{_localstatedir}/log/squid' \
   --with-pidfile='/run/squid.pid' \
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
   --disable-security-cert-validators \
   --with-tdb --disable-strict-error-checking \
   --with-swapdir=%{_localstatedir}/spool/squid

mkdir -p src/icmp/tests
mkdir -p tools/squidclient/tests
mkdir -p tools/tests

%make_build

%check
if ! getent passwd squid >/dev/null 2>&1 && [ `id -u` -eq 0 ];then
  /usr/sbin/useradd -u 23 -d /var/spool/squid -r -s /sbin/nologin squid >/dev/null 2>&1 || exit 1
  make check
 /usr/sbin/userdel squid
else
  make check
fi

%install
%make_install
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
         $RPM_BUILD_ROOT%{_prefix}/lib/NetworkManager/dispatcher.d $RPM_BUILD_ROOT%{_unitdir} \
         $RPM_BUILD_ROOT%{_libexecdir}/squid
install -m 644 %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/squid
install -m 644 %{SOURCE3} $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/squid
install -m 644 %{SOURCE4} $RPM_BUILD_ROOT%{_sysconfdir}/pam.d/squid
install -m 644 %{SOURCE6} $RPM_BUILD_ROOT%{_unitdir}
install -m 755 %{SOURCE7} $RPM_BUILD_ROOT%{_libexecdir}/squid
install -m 644 $RPM_BUILD_ROOT/squid.httpd.tmp $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/squid.conf
install -m 755 %{SOURCE5} $RPM_BUILD_ROOT%{_prefix}/lib/NetworkManager/dispatcher.d/20-squid
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/log/squid $RPM_BUILD_ROOT%{_localstatedir}/spool/squid \
         $RPM_BUILD_ROOT/run/squid
chmod 644 contrib/url-normalizer.pl contrib/user-agents.pl

mkdir -p ${RPM_BUILD_ROOT}%{_tmpfilesdir}
cat > ${RPM_BUILD_ROOT}%{_tmpfilesdir}/squid.conf <<EOF

d /run/squid 0755 squid squid - -
EOF

mkdir -p $RPM_BUILD_ROOT/usr/share/snmp/mibs
mv $RPM_BUILD_ROOT/usr/share/squid/mib.txt $RPM_BUILD_ROOT/usr/share/snmp/mibs/SQUID-MIB.txt

chrpath -d %{buildroot}%{_sbindir}/squid

mkdir -p %{buildroot}/etc/ld.so.conf.d
echo "%{_libdir}" > %{buildroot}/etc/ld.so.conf.d/%{name}-%{_arch}.conf

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
%attr(755,squid,squid) %dir /run/squid

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
%config(noreplace) /etc/ld.so.conf.d/*

%dir %{_datadir}/squid
%attr(-,root,root) %{_datadir}/squid/errors
%{_prefix}/lib/NetworkManager
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

%pretrans -p <lua>
-- temporarilly commented until https://bugzilla.redhat.com/show_bug.cgi?id=1936422 is resolved
-- previously /usr/share/squid/errors/es-mx was symlink, now it is directory since squid v5
-- see https://docs.fedoraproject.org/en-US/packaging-guidelines/Directory_Replacement/
-- Define the path to the symlink being replaced below.
--
-- path = "/usr/share/squid/errors/es-mx"
-- st = posix.stat(path)
-- if st and st.type == "link" then
--   os.remove(path)
-- end

-- Due to a bug #447156
paths = {"/usr/share/squid/errors/zh-cn", "/usr/share/squid/errors/zh-tw"}
for key,path in ipairs(paths)
do
  st = posix.stat(path)
  if st and st.type == "directory" then
    status = os.rename(path, path .. ".rpmmoved")
    if not status then
      suffix = 0
      while not status do
        suffix = suffix + 1
        status = os.rename(path .. ".rpmmoved", path .. ".rpmmoved." .. suffix)
      end
      os.rename(path, path .. ".rpmmoved")
    end
  end
end


%post
%systemd_post squid.service
/sbin/ldconfig

%preun
%systemd_preun squid.service

%postun
%systemd_postun_with_restart squid.service
/sbin/ldconfig

%triggerin -- samba-common
if ! getent group wbpriv >/dev/null 2>&1 ; then
  /usr/sbin/groupadd -g 88 wbpriv >/dev/null 2>&1 || :
fi
/usr/sbin/usermod -a -G wbpriv squid >/dev/null 2>&1 || \
    chgrp squid /var/cache/samba/winbindd_privileged >/dev/null 2>&1 || :

%changelog
* Wed Jul 19 2023 yoo <sunyuechi@iscas.ac.cn> - 7:5.7-2
- Type:requirements
- ID:NA
- SUG:NA
- DESC:fix clang build error

* Mon Nov 14 2022 xinghe <xinghe2@h-partners.com> - 7:5.7-1
- Type:requirements
- ID:NA
- SUG:NA
- DESC:upgrade to 5.7

* Fri Nov 11 2022 xinghe <xinghe2@h-partners.com> - 7:4.9-17
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix build failed

* Tue Sep 27 2022 gaihuiying <eaglegai@163.com> - 7:4.9-16
- Type:cves
- ID:CVE-2022-41318
- SUG:NA
- DESC:fix CVE-2022-41318

* Sat Sep 24 2022 gaihuiying <eaglegai@163.com> - 7:4.9-15
- Type:cves
- ID:CVE-2022-41317
- SUG:NA
- DESC:fix CVE-2022-41317

* Mon Jun 27 2022 gaihuiying <eaglegai@163.com> - 4.9-14
- Type:cves
- ID:CVE-2021-46784
- SUG:NA
- DESC:fix CVE-2021-46784

* Mon Apr 18 2022 gaihuiying <eaglegai@163.com> - 4.9-13
- Type:cves
- ID:CVE-2021-28116
- SUG:NA
- DESC:fix CVE-2021-28116

* Wed Feb 23 2022 xihaochen <xihaochen@h-partner.com> - 4.9-12
- Type:requirement
- ID:NA
- SUG:NA
- DESC:use libtdb instead of libdb

* Tue Sep 07 2021 gaihuiying <gaihuiying1@huawei.com> - 4.9-11
- Type:requirement
- ID:NA
- SUG:NA
- DESC:remove rpath of squid

* Fri Jul 30 2021 gaihuiying <gaihuiying1@huawei.com> - 4.9-10
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix build error with gcc 10

* Wed Jun 30 2021 gaihuiying <gaihuiying1@huawei.com> - 4.9-9
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix squid-conf-tests failed when use 'rpmbuild' command

* Wed Jun 16 2021 xihaochen<xihaochen@huawei.com> - 4.9-8
- Type:cves
- ID:CVE-2021-28651 CVE-2021-28652 CVE-2021-28662 CVE-2021-31806 CVE-2021-31808 CVE-2021-33620
- SUG:NA
- DESC:fix CVE-2021-28651 CVE-2021-28652 CVE-2021-28662 CVE-2021-31806 CVE-2021-31808 CVE-2021-33620

* Wed Mar 31 2021 gaihuiying <gaihuiying1@huawei.com> - 4.9-7
- Type:cves
- ID:NA
- SUG:NA
- DESC:fix CVE-2020-25097 

* Wed Mar 17 2021 openEuler Buildteam <buildteam@openeuler.org> - 4.9-6
- Type:cves
- ID:CVE-2020-14058, CVE-2020-15049, CVE-2020-15810, CVE-2020-15811, CVE-2020-24606
- SUG:restart
- DESC:fix CVE-2020-14058,CVE-2020-15049,CVE-2020-15810,CVE-2020-15811,CVE-2020-24606

* Mon Mar 8 2021 openEuler Buildteam <buildteam@openeuler.org> - 4.9-5
- Type:cves
- ID:CVE-2020-11945
- SUG:restart
- DESC:fix CVE-2020-11945

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
