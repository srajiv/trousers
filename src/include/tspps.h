
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _TSPPS_H_
#define _TSPPS_H_

#include <pthread.h>

#define TSP_KEY_DIR		VAR_PREFIX "/lib/tpm"
#define TSP_KEY_FILE_NAME	TSP_KEY_DIR "/user."

extern struct key_disk_cache *key_disk_cache_head;
/* file handles for the persistent stores */
extern int user_ps_fd;
/* The lock that surrounds all manipulations of the disk cache */
extern pthread_mutex_t disk_cache_lock;

int get_file();
int put_file(int fd);
void ps_destroy();
inline TSS_RESULT read_data(int, void *, UINT32);
inline TSS_RESULT write_data(int, void *, UINT32);
int write_key_init(int, UINT32, UINT32);
TSS_RESULT cache_key(UINT32, UINT16, TSS_UUID *, TSS_UUID *, UINT16, UINT32);
TSS_RESULT psfile_get_parent_uuid_by_uuid(int, TSS_UUID *, TSS_UUID *);
TSS_RESULT psfile_remove_key_by_uuid(int, TSS_UUID *);
TSS_RESULT psfile_get_key_by_uuid(int, TSS_UUID *, BYTE *, UINT16 *);
TSS_RESULT psfile_get_parent_ps_type_by_uuid(int, TSS_UUID *, UINT32 *);
TSS_RESULT psfile_is_pub_registered(int, TCPA_STORE_PUBKEY *, TSS_BOOL *);
TSS_RESULT psfile_get_uuid_by_pub(int, TCPA_STORE_PUBKEY *, TSS_UUID **);
TSS_RESULT psfile_write_key(int, TSS_UUID *, TSS_UUID *, UINT32 *, BYTE *, UINT16);

#endif
