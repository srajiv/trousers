
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _AUTH_MGR_H_
#define _AUTH_MGR_H_

struct auth_map
{
	TSS_BOOL full;
	TPM_AUTHHANDLE tpm_handle;
	TCS_CONTEXT_HANDLE tcs_ctx;
	BYTE *swap; /* These 'swap' variables manage blobs received from TPM_SaveAuthContext */
	UINT32 swap_size;
};

/*
 * it appears that there's no way to query a v1.1 TPM for the
 * max number of simultaneous auth sessions. We'll make the
 * default relatively large and let the TPM return
 * TCPA_RESOURCES to tell us when we cross the line.
 */
#define TSS_DEFAULT_AUTH_TABLE_SIZE	16
#define TSS_DEFAULT_OVERFLOW_AUTHS	16

struct _auth_mgr
{
	short max_auth_sessions;
	short open_auth_sessions;
	short sleeping_threads;
	COND_VAR **overflow;	/* queue of TCS contexts waiting for an auth session to become
				 * available */
	int of_head, of_tail;	/* head and tail of the overflow queue */
	struct auth_map *auth_mapper; /* table of currently tracked auth sessions */
	UINT32 auth_mapper_size;
} auth_mgr;

MUTEX_DECLARE_INIT(auth_mgr_lock);

TSS_RESULT auth_mgr_init();
TSS_RESULT auth_mgr_final();
TSS_RESULT auth_mgr_check(TCS_CONTEXT_HANDLE, TPM_AUTHHANDLE *);
TSS_RESULT auth_mgr_release_auth_handle(TCS_AUTHHANDLE, TCS_CONTEXT_HANDLE, TSS_BOOL);
void       auth_mgr_release_auth(TPM_AUTH *, TPM_AUTH *, TCS_CONTEXT_HANDLE);
TSS_RESULT auth_mgr_oiap(TCS_CONTEXT_HANDLE, TCS_AUTHHANDLE *, TCPA_NONCE *);
TSS_RESULT auth_mgr_osap(TCS_CONTEXT_HANDLE, TCPA_ENTITY_TYPE, UINT32, TCPA_NONCE,
			 TCS_AUTHHANDLE *, TCPA_NONCE *, TCPA_NONCE *);
TSS_RESULT auth_mgr_close_context(TCS_CONTEXT_HANDLE);

TSS_RESULT TPM_SaveAuthContext(TPM_AUTHHANDLE, UINT32 *, BYTE **);
TSS_RESULT TPM_LoadAuthContext(UINT32, BYTE *, TPM_AUTHHANDLE *);

#endif
