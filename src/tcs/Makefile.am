noinst_LIBRARIES=libtcs.a

AM_OBJS=atmel.o cache.o cxt.o tcscm.o tcsem.o imaem.o tcskcm.o tcspbg.o tcs_utils.o ../log/log.o ps/ps_utils.o ps/tcsps.o req_mgr.o auth_mgr.o
AM_CFLAGS=-DAPPID=\"TCS\" -DVAR_PREFIX=\"@localstatedir@\" -DETC_PREFIX=\"@sysconfdir@\"

.c.o:
	$(CC) $(CFLAGS) $(AM_CFLAGS) -c -o $@ $<

libtcs.a: $(AM_OBJS)
	ar -r libtcs.a $(AM_OBJS) ../tddl/libtddl.a

clean:
	rm -rf *.o *.lo *.so *.0 *.a ps/*.o

