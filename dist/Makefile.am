
install: install-exec-hook
	if test ! -e ${DESTDIR}/@sysconfdir@/tcsd.conf; then mkdir -p ${DESTDIR}/@sysconfdir@ && cp tcsd.conf ${DESTDIR}/@sysconfdir@; fi
	/bin/chown tss:tss ${DESTDIR}/@sysconfdir@/tcsd.conf
	/bin/chmod 0600 ${DESTDIR}/@sysconfdir@/tcsd.conf

install-exec-hook:
	/usr/sbin/groupadd tss || true
	/usr/sbin/useradd -r tss -g tss || true
	/bin/chown tss:tss ${DESTDIR}/@sbindir@/tcsd
	/bin/sh -c 'if [ ! -e ${DESTDIR}/@localstatedir@/lib/tpm ];then mkdir -p ${DESTDIR}/@localstatedir@/lib/tpm; fi'
	/bin/chown tss:tss ${DESTDIR}/@localstatedir@/lib/tpm
	/bin/chmod 0700 ${DESTDIR}/@localstatedir@/lib/tpm

uninstall-hook:
	/usr/sbin/userdel tss
	/usr/sbin/groupdel tss
