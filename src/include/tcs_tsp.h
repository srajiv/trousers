
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#ifndef _TCS_TSP_H_
#define _TCS_TSP_H_

/* Structures and defines needed to be known by the
 * TSP layer and the TCS layer.
 */

/*
 * disk store format:
 *
 *                             cached?
 * [UINT32   num_keys_on_disk]
 * [TSS_UUID uuid0           ] yes
 * [TSS_UUID uuid_parent0    ] yes
 * [UINT16   pub_data_size0  ] yes
 * [UINT16   blob_size0      ] yes
 * [UINT16   cache_flags0    ] yes
 * [BYTE[]   pub_data0       ]
 * [BYTE[]   blob0           ]
 * [...]
 *
 */

/*
 * PS disk cache flags
 */
/* A key may be written to disk, in cache and yet be invalid if it has
 * since been unregistered. */
#define CACHE_FLAG_VALID                0x0001
/* set if the key's parent is stored in system PS */
#define CACHE_FLAG_PARENT_PS_SYSTEM     0x0002

/* the structure that makes up the in-memory PS disk cache */
struct key_disk_cache
{
        unsigned int offset;
        UINT16 pub_data_size;
        UINT16 blob_size;
        UINT16 flags;
        TSS_UUID uuid;
        TSS_UUID parent_uuid;
        struct key_disk_cache *next;
};

/* offsets into each key on disk. These should be passed a (struct key_disk_cache *) */
#define NUM_KEYS_OFFSET         (0)
#define KEYS_OFFSET             (NUM_KEYS_OFFSET + sizeof(UINT32))
#define UUID_OFFSET(c)          (c->offset)
#define PARENT_UUID_OFFSET(c)   (c->offset + sizeof(TSS_UUID))
#define PUB_DATA_SIZE_OFFSET(c) (c->offset + (2 * sizeof(TSS_UUID)))
#define BLOB_SIZE_OFFSET(c)     (c->offset + (2 * sizeof(TSS_UUID)) + sizeof(UINT16))
#define CACHE_FLAGS_OFFSET(c)   (c->offset + (2 * sizeof(TSS_UUID)) + (2 * sizeof(UINT16)))
#define PUB_DATA_OFFSET(c)      (c->offset + (2 * sizeof(TSS_UUID)) + (3 * sizeof(UINT16)))
#define BLOB_DATA_OFFSET(c)     (c->offset + (2 * sizeof(TSS_UUID)) + (3 * sizeof(UINT16)) + c->pub_data_size)

#define MAX_KEY_CHILDREN	10

#define STRUCTURE_PACKING_ATTRIBUTE	__attribute__((packed))

typedef unsigned char *POINTER;
typedef POINTER B_KEY_OBJ;
typedef POINTER B_ALGORITHM_OBJ;
typedef struct _CRTKEY {
	BYTE exp1[256];
	BYTE exp2[256];
	BYTE mod1[256];
	BYTE mod2[256];
	BYTE crt[256];
} CRTKEY;

typedef struct _HMAC_Struct {
	UINT32 secretSize;
	BYTE *secret;
	UINT32 bufferSize;
	BYTE *buffer;
} HMAC_Struct;

typedef struct _HASH_Struct {
	BYTE hashType;
/*      UINT32 bufSize; */
/*      BYTE* buffer; */
	B_ALGORITHM_OBJ algObject;
} HASH_Struct;

#endif
