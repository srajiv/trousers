noinst_LTLIBRARIES=libtrousers.la

libtrousers_la_SOURCES=trousers.c crypto/@CRYPTO_PACKAGE@/hash.c
libtrousers_la_CFLAGS=-DAPPID=\"TSPI\"

if TSS_BUILD_ASYM_CRYPTO
libtrousers_la_SOURCES+=crypto/@CRYPTO_PACKAGE@/rsa.c
endif
if TSS_BUILD_SYM_CRYPTO
libtrousers_la_SOURCES+=crypto/@CRYPTO_PACKAGE@/symmetric.c
endif
