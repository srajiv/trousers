
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _OBJ_H_
#define _OBJ_H_

/* prototypes */
TSS_HOBJECT getNextObjectHandle();
AnObject *createNewObject();
AnObject *concatObjects(AnObject ** first, AnObject * second);
AnObject *getAnObjectByHandle(UINT32 oHandle);

TSS_RESULT obj_connectContext(TSS_HCONTEXT, TCS_CONTEXT_HANDLE);
TSS_RESULT obj_checkSession_1(TSS_HOBJECT);
TSS_RESULT obj_checkSession_2(TSS_HOBJECT, TSS_HOBJECT);
TSS_RESULT obj_checkSession_3(TSS_HOBJECT, TSS_HOBJECT, TSS_HOBJECT);
TSS_RESULT obj_isConnected_1(TSS_HOBJECT, TCS_CONTEXT_HANDLE *);
TSS_RESULT obj_isConnected_2(TSS_HOBJECT, TSS_HOBJECT, TCS_CONTEXT_HANDLE *);
TSS_RESULT obj_isConnected_3(TSS_HOBJECT, TSS_HOBJECT, TSS_HOBJECT, TCS_CONTEXT_HANDLE *);
TSS_RESULT obj_checkType_1(TSS_HOBJECT, UINT32);
TSS_RESULT obj_checkType_2(TSS_HOBJECT, UINT32, TSS_HOBJECT, UINT32);
TSS_RESULT obj_checkType_3(TSS_HOBJECT, UINT32, TSS_HOBJECT, UINT32, TSS_HOBJECT, UINT32);

TSS_HCONTEXT obj_lookupTspContext(TCS_CONTEXT_HANDLE);
TSS_HCONTEXT obj_getTspContext(TSS_HOBJECT);
TSS_HCONTEXT obj_getTcsContext(TSS_HOBJECT);

TSS_RESULT obj_getTpmObject(UINT32, TSS_HOBJECT *);
TSS_HOBJECT obj_GetPolicyOfObject(UINT32, UINT32);
TCS_CONTEXT_HANDLE obj_getTcsHandle(TSS_HOBJECT);
void obj_closeContext(TSS_HCONTEXT);

#endif
