
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _TCSPS_H_
#define _TCSPS_H_

#include <pthread.h>

extern struct key_disk_cache *key_disk_cache_head;
/* file handles for the persistent stores */
extern int system_ps_fd;
/* The lock that surrounds all manipulations of the disk cache */
extern pthread_mutex_t disk_cache_lock;


int		   get_file();
int		   put_file(int);
void		   close_file(int);
void		   destroy_ps();
inline TSS_RESULT  read_data(int, void *, UINT32);
inline TSS_RESULT  write_data(int, void *, UINT32);
int		   write_key_init(int, UINT32, UINT32);
TSS_RESULT	   cache_key(UINT32, UINT16, TSS_UUID *, TSS_UUID *, UINT16, UINT32);
TSS_RESULT	   UnloadBlob_KEY_PS(UINT16 *, BYTE *, TCPA_KEY *);
TSS_RESULT	   ps_get_parent_uuid_by_uuid(int, TSS_UUID *, TSS_UUID *);
TSS_RESULT	   ps_remove_key_by_uuid(int, TSS_UUID *);
TSS_RESULT	   ps_get_key_by_uuid(int, TSS_UUID *, BYTE *, UINT16 *);
TSS_RESULT	   ps_get_key_by_cache_entry(int, struct key_disk_cache *, BYTE *, UINT16 *);
TSS_RESULT	   ps_get_parent_ps_type_by_uuid(int, TSS_UUID *, UINT32 *);
TSS_RESULT	   ps_is_pub_registered(int, TCPA_STORE_PUBKEY *, TSS_BOOL *);
TSS_RESULT	   ps_get_uuid_by_pub(int, TCPA_STORE_PUBKEY *, TSS_UUID **);
TSS_RESULT	   ps_write_key(int, TSS_UUID *, TSS_UUID *, UINT32 *, BYTE *, UINT16);
TCPA_STORE_PUBKEY *ps_get_pub_by_tpm_handle(int, TCPA_KEY_HANDLE);
TSS_RESULT	   ps_get_tpm_handle_by_pub(int, TCPA_STORE_PUBKEY *, TCPA_KEY_HANDLE *);
TSS_RESULT	   ps_get_tcs_handle_by_pub(int, TCPA_STORE_PUBKEY *, TCS_KEY_HANDLE *);
TSS_RESULT	   ps_get_parent_tcs_handle_by_pub(int, TCPA_STORE_PUBKEY *, TCS_KEY_HANDLE *);
TCPA_STORE_PUBKEY *ps_get_pub_by_tcs_handle(int, TCS_KEY_HANDLE);
TSS_RESULT	   ps_get_key_by_pub(int, TCPA_STORE_PUBKEY *, UINT32 *, BYTE **);
TSS_RESULT	   removeRegisteredKey(TSS_UUID *);
int		   init_disk_cache(int fd);
int		   close_disk_cache(int fd);

#endif
