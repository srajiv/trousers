sbin_PROGRAMS=tcsd

tcsd_SOURCES=svrside.c tcsd_wrap.c tcsd_conf.c tcsd_threads.c platform.c
tcsd_CFLAGS=-DAPPID=\"TCSD\" -DVAR_PREFIX=\"@localstatedir@\" -DETC_PREFIX=\"@sysconfdir@\"
tcsd_LDFLAGS=../tcs/libtcs.a ../tddl/libtddl.a -lpthread
