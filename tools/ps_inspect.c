
/*
 * ps_inspect.c
 *
 *   Inspect a persistent storage file, printing information about it based
 *   on best guesses.
 *
 *   There are 2 different types of persistent storage files:
 *
 * A)
 *
 * [UINT32   num_keys_on_disk]
 * [TSS_UUID uuid0           ]
 * [TSS_UUID uuid_parent0    ]
 * [UINT32   pub_data_size0  ]
 * [UINT32   blob_size0      ]
 * [UINT16   cache_flags0    ]
 * [BYTE[]   pub_data0       ]
 * [BYTE[]   blob0           ]
 * [...]
 *
 * B)
 *
 * [BYTE     TrouSerS PS version='1']
 * [UINT32   num_keys_on_disk       ]
 * [TSS_UUID uuid0                  ]
 * [TSS_UUID uuid_parent0           ]
 * [UINT16   pub_data_size0         ]
 * [UINT16   blob_size0             ]
 * [UINT32   vendor_data_size0      ]
 * [UINT16   cache_flags0           ]
 * [BYTE[]   pub_data0              ]
 * [BYTE[]   blob0                  ]
 * [BYTE[]   vendor_data0           ]
 * [...]
 *
 * In B, version must be > 0.
 *
 */




#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <trousers/tss.h>

#define PRINTERR(...)	fprintf(stderr, ##__VA_ARGS__)
#define PRINT		printf

/* any number of keys found that's greater than MAX_NUM_LIKELY_KEYS
 * will trigger some logic
 */
#define MAX_NUM_LIKELY_KEYS	25

/* one global buffer we read into from the PS file */
unsigned char buf[4096];

void
usage(char *argv0)
{
	PRINTERR("usage: %s filename\n", argv0);
	exit(-1);
}

int
printkey_0(int num, FILE *f)
{
}

int
printkey_1(int num, FILE *f)
{
}

int
version_0_print(FILE *f)
{
	int i, rc;
	UINT32 *u32 = (UINT32 *)buf;

	PRINT("PS version:        0\n");
	PRINT("PS number of keys: %u\n", *u32);

	for (i = 0; i < *u32; i++) {
		if (rc = printkey_0(i, f))
			return rc;
	}

	return 0;
}

int
version_1_print(FILE *f)
{
	int i, rc;
	UINT32 *u32 = (UINT32 *)&buf[1];

	PRINT("PS version:        1\n");
	PRINT("PS number of keys: %u\n", *u32);

	for (i = 0; i < *u32; i++) {
		if (rc = printkey_1(i, f))
			return rc;
	}

	return 0;
}

int
inspect(FILE *f)
{
	int members = 0;
	UINT32 *num_keys;

	if ((members = fread(buf, 5, 1, f)) != 1) {
		PRINTERR("fread: %s", strerror(errno));
		return -1;
	}

	if (buf[0] == '\1') {
		num_keys = (UINT32 *)&buf[1];
		if (*num_keys == 0 || *num_keys > MAX_NUM_LIKELY_KEYS)
			goto version0;

		return version_1_print(f);
	}

version0:
	return version_0_print(f);
}

int
main(int argc, char ** argv)
{
	FILE *f = NULL;
	int rc;

	if (argc != 2)
		usage(argv[0]);

	if ((f = fopen(argv[1], "r")) == NULL) {
		PRINTERR("fopen: %s", strerror(errno));
		return -1;
	}

	rc = inspect(f);

	fclose(f);

	return rc;
}
