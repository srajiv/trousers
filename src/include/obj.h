
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

AnObject *objectList = NULL;
UINT32 nextObjectHandle = 0xC0000000;

TCSKeyHandleContainer *glKeyHandleManager = NULL;

/* prototypes */
TSS_HOBJECT getNextObjectHandle();
AnObject *createNewObject();
AnObject *concatObjects(AnObject ** first, AnObject * second);
AnObject *getAnObjectByHandle(UINT32 oHandle);

pthread_mutex_t objectlist_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t keylist_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t handle_lock = PTHREAD_MUTEX_INITIALIZER;

#endif
