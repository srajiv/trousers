lib_LTLIBRARIES=libtspi.la

libtspi_la_LIBADD=../trspi/libtrousers.la

# On setting -version-info, from the libtool manual:
#
# -version-info current:revision:age
#
# 1. Start with version information of 0:0:0 for each libtool library.
# 2. Update the version information only immediately before a public release of your software.
#    More frequent updates are unnecessary, and only guarantee that the current interface
#    number gets larger faster.
# 3. If the library source code has changed at all since the last update, then increment
#    revision (c:r:a becomes c:r+1:a).
# 4. If any interfaces have been added, removed, or changed since the last update, increment
#    current, and set revision to 0.
# 5. If any interfaces have been added since the last public release, then increment age.
# 6. If any interfaces have been removed since the last public release, then set age to 0.

libtspi_la_LDFLAGS=-version-info 0:7:0 -lcrypto -lpthread

libtspi_la_CFLAGS=-I../include -DAPPID=\"TSPI\" -DVAR_PREFIX=\"@localstatedir@\" -DETC_PREFIX=\"@sysconfdir@\"
libtspi_la_SOURCES=obj.c spi_context.c spi_getset.c spi_key.c spi_policy.c spi_utils.c memmgr.c secrets.c spi_data.c spi_hash.c spi_pcr.c spi_tpm.c ../tcsd_api/calltcsapi.c ../tcsd_api/tcstp.c ../tcsd_api/hosttable.c ../tcsd_api/clntside.c log.c obj_rsakey.c obj_policy.c obj_tpm.c obj_hash.c obj_pcrs.c obj_encdata.c obj_context.c keyreg.c ps/tspps.c ps/ps_utils.c

libtspi_la_CFLAGS+=@GTK_CFLAGS@
libtspi_la_LDFLAGS+=@GTK_LIBS@

libtspi_la_SOURCES+=gtk/main.c gtk/support.c gtk/interface.c gtk/callbacks.c
