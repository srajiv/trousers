noinst_LIBRARIES=libtrousers.a

libtrousers_a_SOURCES=trousers.c crypto/@CRYPTO_PACKAGE@/crypto.c
libtrousers_a_CFLAGS=-DAPPID=\"TSPI\"

clean:
	rm -f libtrousers.a *.o crypto/*/*.o
