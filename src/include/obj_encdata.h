
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */

#ifndef _OBJ_ENCDATA_H_
#define _OBJ_ENCDATA_H_

#ifdef TSS_BUILD_ENCDATA_LIST

/* structures */
struct tr_encdata_obj {
	TSS_HPOLICY usagePolicy;
	TSS_HPOLICY migPolicy;
	UINT32 encryptedDataLength;
	BYTE encryptedData[512]; /* XXX get rid of hardcoded size */
	TCPA_PCR_INFO pcrInfo; /* XXX use a link to a PCR object here */
	UINT32 type;
};

/* obj_encdata.c */
TSS_BOOL   obj_is_encdata(TSS_HOBJECT);
TSS_RESULT obj_encdata_set_policy(TSS_HKEY, UINT32, TSS_HPOLICY);
TSS_RESULT obj_encdata_set_data(TSS_HENCDATA, UINT32, BYTE *);
TSS_RESULT obj_encdata_remove(TSS_HOBJECT, TSS_HCONTEXT);
TSS_RESULT obj_encdata_get_tsp_context(TSS_HENCDATA, TSS_HCONTEXT *);
TSS_RESULT obj_encdata_add(TSS_HCONTEXT, UINT32, TSS_HOBJECT *);
void       obj_list_encdata_close(struct obj_list *, TSS_HCONTEXT);
TSS_RESULT obj_encdata_get_data(TSS_HENCDATA, UINT32 *, BYTE **);
TSS_RESULT obj_encdata_get_pcr_atcreation(TSS_HENCDATA, UINT32 *, BYTE **);
TSS_RESULT obj_encdata_get_pcr_atrelease(TSS_HENCDATA, UINT32 *, BYTE **);
TSS_RESULT obj_encdata_get_pcr_selection(TSS_HENCDATA, UINT32 *, BYTE **);
TSS_RESULT obj_encdata_get_policy(TSS_HENCDATA, UINT32, TSS_HPOLICY *);
TSS_RESULT obj_encdata_set_pcr_info(TSS_HENCDATA, BYTE *);

#define ENCDATA_LIST_DECLARE		struct obj_list encdata_list
#define ENCDATA_LIST_DECLARE_EXTERN	extern struct obj_list encdata_list
#define ENCDATA_LIST_INIT()		list_init(&encdata_list)
#define ENCDATA_LIST_CONNECT(a,b)	obj_connectContext_list(&encdata_list, a, b)
#define ENCDATA_LIST_CLOSE(a)		obj_list_encdata_close(&encdata_list, a)

#else

#define obj_is_encdata(a)	FALSE

#define ENCDATA_LIST_DECLARE
#define ENCDATA_LIST_DECLARE_EXTERN
#define ENCDATA_LIST_INIT()
#define ENCDATA_LIST_CONNECT(a,b)
#define ENCDATA_LIST_CLOSE(a)

#endif

#endif
