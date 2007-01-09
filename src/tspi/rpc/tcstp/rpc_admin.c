
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "hosttable.h"
#include "tcsd_wrap.h"
#include "obj.h"
#include "rpc_tcstp_tsp.h"


TSS_RESULT
TSC_PhysicalPresence_TP(UINT16 physPres)
{
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_SetOwnerInstall_TP(struct host_table_entry *hte,
			TCS_CONTEXT_HANDLE hContext,	/* in */
			TSS_BOOL state)	/* in */
{
	TSS_RESULT result;

	initData(&hte->comm, 2);
	hte->comm.hdr.u.ordinal = TCSD_ORD_SETOWNERINSTALL;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_BOOL, 1, &state, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	return result;
}

TSS_RESULT
TCSP_DisableOwnerClear_TP(struct host_table_entry *hte,
			  TCS_CONTEXT_HANDLE hContext,	/* in */
			  TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result;

	initData(&hte->comm, 2);
	hte->comm.hdr.u.ordinal = TCSD_ORD_DISABLEOWNERCLEAR;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (setData(TCSD_PACKET_TYPE_AUTH, 1, ownerAuth, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	if (result == TSS_SUCCESS ){
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, &hte->comm))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	return result;
}

TSS_RESULT
TCSP_ForceClear_TP(struct host_table_entry *hte,
		   TCS_CONTEXT_HANDLE hContext)	/* in */
{
	TSS_RESULT result;

	initData(&hte->comm, 1);
	hte->comm.hdr.u.ordinal = TCSD_ORD_FORCECLEAR;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	return result;
}

TSS_RESULT
TCSP_DisableForceClear_TP(struct host_table_entry *hte,
			  TCS_CONTEXT_HANDLE hContext)	/* in */
{
	TSS_RESULT result;

	initData(&hte->comm, 1);
	hte->comm.hdr.u.ordinal = TCSD_ORD_DISABLEFORCECLEAR;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	return result;
}

TSS_RESULT
TCSP_PhysicalDisable_TP(struct host_table_entry *hte,
			TCS_CONTEXT_HANDLE hContext)	/* in */
{
	TSS_RESULT result;

	initData(&hte->comm, 1);
	hte->comm.hdr.u.ordinal = TCSD_ORD_PHYSICALDISABLE;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	return result;
}

TSS_RESULT
TCSP_PhysicalEnable_TP(struct host_table_entry *hte,
		       TCS_CONTEXT_HANDLE hContext)	/* in */
{
	TSS_RESULT result;

	initData(&hte->comm, 1);
	hte->comm.hdr.u.ordinal = TCSD_ORD_PHYSICALENABLE;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	return result;
}

TSS_RESULT
TCSP_OwnerSetDisable_TP(struct host_table_entry *hte,
			TCS_CONTEXT_HANDLE hContext,   /*  in */
			TSS_BOOL disableState,     /*  in */
			TPM_AUTH * ownerAuth)   /*  in, out */
{
	TSS_RESULT result;

	initData(&hte->comm, 3);
	hte->comm.hdr.u.ordinal = TCSD_ORD_OWNERSETDISABLE;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_BOOL, 1, &disableState, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 2, ownerAuth, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, &hte->comm))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	return result;
}

TSS_RESULT
TCSP_PhysicalSetDeactivated_TP(struct host_table_entry *hte,
			       TCS_CONTEXT_HANDLE hContext,	/* in */
			       TSS_BOOL state)	/* in */
{
	TSS_RESULT result;

	initData(&hte->comm, 2);
	hte->comm.hdr.u.ordinal = TCSD_ORD_PHYSICALSETDEACTIVATED;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_BOOL, 1, &state, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	return result;
}

TSS_RESULT
TCSP_PhysicalPresence_TP(struct host_table_entry *hte,
			 TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCPA_PHYSICAL_PRESENCE fPhysicalPresence)	/* in */
{
	TSS_RESULT result;

	initData(&hte->comm, 2);
	hte->comm.hdr.u.ordinal = TCSD_ORD_PHYSICALPRESENCE;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 1, &fPhysicalPresence, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	return result;
}

TSS_RESULT
TCSP_SetTempDeactivated_TP(struct host_table_entry *hte,
			   TCS_CONTEXT_HANDLE hContext)	/* in */
{
	TSS_RESULT result;

	initData(&hte->comm, 1);
	hte->comm.hdr.u.ordinal = TCSD_ORD_SETTEMPDEACTIVATED;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	return result;
}

TSS_RESULT
TCSP_FieldUpgrade_TP(struct host_table_entry *hte,
		     TCS_CONTEXT_HANDLE hContext,	/* in */
		     UINT32 dataInSize,	/* in */
		     BYTE * dataIn,	/* in */
		     UINT32 * dataOutSize,	/* out */
		     BYTE ** dataOut,	/* out */
		     TPM_AUTH * ownerAuth)	/* in, out */
{
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_SetRedirection_TP(struct host_table_entry *hte,
		       TCS_CONTEXT_HANDLE hContext,	/* in */
		       TCS_KEY_HANDLE keyHandle,	/* in */
		       UINT32 c1,	/* in */
		       UINT32 c2,	/* in */
		       TPM_AUTH * privAuth)	/* in, out */
{
	return TSPERR(TSS_E_NOTIMPL);

}

TSS_RESULT
TCSP_ResetLockValue_TP(struct host_table_entry *hte,
		       TCS_CONTEXT_HANDLE hContext,   /* in */
		       TPM_AUTH * ownerAuth)   /* in, out */
{
	TSS_RESULT result;

	initData(&hte->comm, 2);
	hte->comm.hdr.u.ordinal = TCSD_ORD_RESETLOCKVALUE;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 1, ownerAuth, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, &hte->comm))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	return result;
}

