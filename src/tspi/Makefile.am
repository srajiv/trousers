all: libtspi.so

if HAVE_GTK
AM_CFLAGS=-I../include -DAPPID=\"TSPI\" -DVAR_PREFIX=\"@localstatedir@\" -DETC_PREFIX=\"@sysconfdir@\" @GTK_CFLAGS@
AM_LDFLAGS=../trspi/libtrousers.a @GTK_LIBS@ -lcrypto -lpthread

AM_OBJS=ConvertLib.o obj.o spi_context.o spi_getset.o spi_key.o spi_policy.o spi_utils.o keyreg.o memmgr.o secrets.o spi_data.o spi_hash.o spi_pcr.o spi_tpm.o ../tcsd_api/calltcsapi.o ../tcsd_api/tcstp.o ../tcsd_api/hosttable.o ../tcsd_api/clntside.o gtk/main.o gtk/support.o gtk/interface.o gtk/callbacks.o ps/tspps.o ps/ps_utils.o log.o

else

AM_CFLAGS=-I../include -DAPPID=\"TSPI\" -DVAR_PREFIX=\"@localstatedir@\" -DETC_PREFIX=\"@sysconfdir@\"
AM_LDFLAGS=../trspi/libtrousers.a -lcrypto -lpthread

AM_OBJS=ConvertLib.o obj.o spi_context.o spi_getset.o spi_key.o spi_policy.o spi_utils.o keyreg.o memmgr.o secrets.o spi_data.o spi_hash.o spi_pcr.o spi_tpm.o ../tcsd_api/calltcsapi.o ../tcsd_api/tcstp.o ../tcsd_api/hosttable.o ../tcsd_api/clntside.o ps/tspps.o ps/ps_utils.o log.o ssh_askpass/readpass.o

endif

.c.o:
	$(CC) $(CFLAGS) $(AM_CFLAGS) -c -o $@ $<

libtspi.so: $(AM_OBJS)
	$(CC) -shared -o libtspi.so $(AM_OBJS) $(AM_LDFLAGS)

clean:
	rm -rf *.o *.lo *.so *.0 *.a ps/*.o ../tcsd_api/*.o gtk/*.o ssh_askpass/*.o

install:
	mkdir -p ${DESTDIR}/@libdir@
	cp libtspi.so ${DESTDIR}/@libdir@
	chown root:root ${DESTDIR}/@libdir@/libtspi.so
	chmod 0755 ${DESTDIR}/@libdir@/libtspi.so
	/sbin/ldconfig

