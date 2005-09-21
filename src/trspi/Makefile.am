noinst_LTLIBRARIES=libtrousers.la

libtrousers_la_SOURCES=trousers.c crypto/@CRYPTO_PACKAGE@/crypto.c
libtrousers_la_CFLAGS=-DAPPID=\"TSPI\"

clean:
	rm -f libtrousers.a *.o crypto/*/*.o
