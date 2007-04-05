
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */

#ifndef _OBJ_CONTEXT_H_
#define _OBJ_CONTEXT_H_

/* structures */
struct tr_context_obj {
	TSS_FLAG silentMode;
	UINT32 hashMode;
	TSS_HPOLICY policy;
	TCS_CONTEXT_HANDLE tcsHandle;
	BYTE *machineName;
	UINT32 machineNameLength;
	UINT32 connection_policy, current_connection;
};

/* obj_context.c */
TSS_BOOL   obj_is_context(TSS_HOBJECT);
TSS_RESULT obj_context_get_policy(TSS_HCONTEXT, TSS_HPOLICY *);
TSS_BOOL   obj_context_is_silent(TSS_HCONTEXT);
TSS_RESULT obj_context_set_policy(TSS_HCONTEXT, TSS_HPOLICY);
TSS_RESULT obj_context_get_machine_name(TSS_HCONTEXT, UINT32 *, BYTE **);
TSS_RESULT obj_context_get_machine_name_attrib(TSS_HCONTEXT, UINT32 *, BYTE **);
TSS_RESULT obj_context_set_machine_name(TSS_HCONTEXT, BYTE *, UINT32);
TSS_RESULT obj_context_add(TSS_HOBJECT *);
TSS_RESULT obj_context_set_mode(TSS_HCONTEXT, UINT32);
TSS_RESULT obj_context_get_mode(TSS_HCONTEXT, UINT32 *);
TSS_BOOL   obj_context_has_popups(TSS_HCONTEXT);
TSS_RESULT obj_context_get_hash_mode(TSS_HCONTEXT, UINT32 *);
TSS_RESULT obj_context_set_hash_mode(TSS_HCONTEXT, UINT32);
TSS_RESULT obj_context_get_connection_version(TSS_HCONTEXT, UINT32 *);
TSS_RESULT obj_context_set_connection_policy(TSS_HCONTEXT, UINT32);

#define CONTEXT_LIST_DECLARE		struct obj_list context_list
#define CONTEXT_LIST_DECLARE_EXTERN	extern struct obj_list context_list
#define CONTEXT_LIST_INIT()		list_init(&context_list)
#define CONTEXT_LIST_CONNECT(a,b)	obj_connectContext_list(&context_list, a, b)
#define CONTEXT_LIST_CLOSE(a)		obj_list_close(&context_list, a)

#endif
