
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _TCS_INTERNAL_TYPES_H_
#define _TCS_INTERNAL_TYPES_H_

struct keys_loaded
{
	TCS_KEY_HANDLE key_handle;
	struct keys_loaded *next;
};


struct tcs_context {
	TCS_CONTEXT_HANDLE handle;
	union {
		pthread_cond_t cond; /* used in waiting for an auth
					ctx to become available */
		void *blob; /* auth context blobs will be saved off here */
	} u_auth;
	struct keys_loaded *keys;
	struct tcs_context *next;
};

#endif

