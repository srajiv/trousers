noinst_LIBRARIES=libtcs.a

libtcs_a_LIBADD=../tddl/libtddl.a
libtcs_a_SOURCES=cache.c cxt.c tcscm.c tcsem.c imaem.c biosem.c tcskcm.c tcspbg.c tcs_utils.c log.c ps/ps_utils.c ps/tcsps.c req_mgr.c auth_mgr.c
libtcs_a_CFLAGS=-DAPPID=\"TCS\" -DVAR_PREFIX=\"@localstatedir@\" -DETC_PREFIX=\"@sysconfdir@\"
