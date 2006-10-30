sbin_PROGRAMS=tcsd

tcsd_CFLAGS=-DAPPID=\"TCSD\" -DVAR_PREFIX=\"@localstatedir@\" -DETC_PREFIX=\"@sysconfdir@\"
tcsd_LDADD=../tcs/libtcs.a ../tddl/libtddl.a -lpthread @CRYPTOLIB@

tcsd_SOURCES=svrside.c tcsd_conf.c tcsd_threads.c platform.c
