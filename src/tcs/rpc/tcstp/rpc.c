
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
#include <syslog.h>
#include <string.h>
#include <netdb.h>

#include "trousers/tss.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "rpc_tcstp_tcs.h"


void
LoadBlob_Auth_Special(UINT64 *offset, BYTE *blob, TPM_AUTH *auth)
{
	LoadBlob(offset, TCPA_SHA1BASED_NONCE_LEN, blob, auth->NonceEven.nonce);
	LoadBlob_BOOL(offset, auth->fContinueAuthSession, blob);
	LoadBlob(offset, TCPA_SHA1BASED_NONCE_LEN, blob, (BYTE *)&auth->HMAC);
}

void
UnloadBlob_Auth_Special(UINT64 *offset, BYTE *blob, TPM_AUTH *auth)
{
	UnloadBlob_UINT32(offset, &auth->AuthHandle, blob);
	UnloadBlob(offset, TCPA_SHA1BASED_NONCE_LEN, blob, auth->NonceOdd.nonce);
	UnloadBlob_BOOL(offset, &auth->fContinueAuthSession, blob);
	UnloadBlob(offset, TCPA_SHA1BASED_NONCE_LEN, blob, (BYTE *)&auth->HMAC);
}

int
setData(BYTE dataType, int index, void *theData, int theDataSize, struct tcsd_packet_hdr *hdr)
{
	UINT64 offset;

	if (index == 0) {
		/* min packet size should be everything except the 1 byte 'data' field */
		hdr->packet_size = sizeof(struct tcsd_packet_hdr) - 1;
		hdr->num_parms = 0;
		memset(hdr->parm_types, 0, sizeof(hdr->parm_types));
	}
	DBG_ASSERT(hdr->packet_size + theDataSize < USHRT_MAX);
	offset = hdr->packet_size;
	if (index >= TCSD_MAX_NUM_PARMS) {
		LogError("Too many elements in TCSD packet!");
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	switch (dataType) {
	case TCSD_PACKET_TYPE_BYTE:
		LoadBlob_BYTE(&offset, *((BYTE *) (theData)), (void *)hdr);
		break;
	case TCSD_PACKET_TYPE_BOOL:
		LoadBlob_BOOL(&offset, *((TSS_BOOL *) (theData)), (void *)hdr);
		break;
	case TCSD_PACKET_TYPE_UINT16:
		LoadBlob_UINT16(&offset, *((UINT16 *) (theData)), (void *)hdr);
		break;
	case TCSD_PACKET_TYPE_UINT32:
		LoadBlob_UINT32(&offset, *((UINT32 *) (theData)), (void *)hdr);
		break;
	case TCSD_PACKET_TYPE_PBYTE:
		LoadBlob(&offset, theDataSize, (void *)hdr, theData);
		break;
	case TCSD_PACKET_TYPE_NONCE:
		LoadBlob(&offset, sizeof(TCPA_NONCE), (void *)hdr, ((TCPA_NONCE *)theData)->nonce);
		break;
	case TCSD_PACKET_TYPE_DIGEST:
		LoadBlob(&offset, sizeof(TCPA_DIGEST), (void *)hdr, ((TCPA_DIGEST *)theData)->digest);
		break;
	case TCSD_PACKET_TYPE_AUTH:
		LoadBlob_Auth_Special(&offset, (void *)hdr, ((TPM_AUTH *)theData));
		break;
	case TCSD_PACKET_TYPE_ENCAUTH:
		LoadBlob(&offset, sizeof(TCPA_ENCAUTH), (void *)hdr, ((TCPA_ENCAUTH *)theData)->authdata);
		break;
	case TCSD_PACKET_TYPE_VERSION:
		LoadBlob_VERSION(&offset, (void *)hdr, ((TCPA_VERSION *)theData));
		break;
#ifdef TSS_BUILD_PS
	case TCSD_PACKET_TYPE_KM_KEYINFO:
		LoadBlob_KM_KEYINFO(&offset, (void *)hdr, ((TSS_KM_KEYINFO *)theData));
		break;
	case TCSD_PACKET_TYPE_LOADKEY_INFO:
		LoadBlob_LOADKEY_INFO(&offset, (void *)hdr, ((TCS_LOADKEY_INFO *)theData));
		break;
	case TCSD_PACKET_TYPE_UUID:
		LoadBlob_UUID(&offset, (void *)hdr, *((TSS_UUID *)theData));
		break;
#endif
#ifdef TSS_BUILD_PCR_EVENT
	case TCSD_PACKET_TYPE_PCR_EVENT:
		LoadBlob_PCR_EVENT(&offset, (void *)hdr, ((TSS_PCR_EVENT *)theData));
		break;
#endif
	default:
		LogError("TCSD packet type unknown! (0x%x)", dataType & 0xff);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	hdr->parm_types[index] = dataType;
	hdr->packet_size = offset;
	hdr->num_parms++;
	return 0;
}

UINT32
getData(BYTE dataType, int index, void *theData, int theDataSize, struct tsp_packet * packet)
{
	UINT64 offset;

	if (index == 0)
		packet->dataSize = 0;
	offset = packet->dataSize;
	if (index >= TCSD_MAX_NUM_PARMS) {
		LogError("Too many elements in TCSD packet!");
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (index >= packet->numParms ||
	    dataType != packet->types[index]) {
		LogDebug("Data type of TCS packet element %d doesn't match.", index);
		return TSS_TCP_RPC_BAD_PACKET_TYPE;
	}
	switch (dataType) {
	case TCSD_PACKET_TYPE_BYTE:
		UnloadBlob_BYTE(&offset, (BYTE *) (theData), packet->dataBuffer);
		break;
	case TCSD_PACKET_TYPE_BOOL:
		UnloadBlob_BOOL(&offset, (TSS_BOOL *) (theData), packet->dataBuffer);
		break;
	case TCSD_PACKET_TYPE_UINT16:
		UnloadBlob_UINT16(&offset, (UINT16 *) (theData), packet->dataBuffer);
		break;
	case TCSD_PACKET_TYPE_UINT32:
		UnloadBlob_UINT32(&offset, (UINT32 *) (theData), packet->dataBuffer);
		break;
	case TCSD_PACKET_TYPE_PBYTE:
		UnloadBlob(&offset, theDataSize, packet->dataBuffer, theData);
		break;
	case TCSD_PACKET_TYPE_NONCE:
		UnloadBlob(&offset, sizeof(TCPA_NONCE), packet->dataBuffer,
			   ((TCPA_NONCE *) (theData))->nonce);
		break;
	case TCSD_PACKET_TYPE_DIGEST:
		UnloadBlob(&offset, sizeof(TCPA_DIGEST), packet->dataBuffer,
			   ((TCPA_DIGEST *) (theData))->digest);
		break;
	case TCSD_PACKET_TYPE_AUTH:
		UnloadBlob_Auth_Special(&offset, packet->dataBuffer, ((TPM_AUTH *) theData));
		break;
	case TCSD_PACKET_TYPE_ENCAUTH:
		UnloadBlob(&offset, sizeof(TCPA_ENCAUTH), packet->dataBuffer,
			   ((TCPA_ENCAUTH *) theData)->authdata);
		break;
	case TCSD_PACKET_TYPE_VERSION:
		UnloadBlob_VERSION(&offset, packet->dataBuffer, ((TCPA_VERSION *) theData));
		break;
#ifdef TSS_BUILD_PS
	case TCSD_PACKET_TYPE_KM_KEYINFO:
		UnloadBlob_KM_KEYINFO(&offset, packet->dataBuffer, ((TSS_KM_KEYINFO*)theData));
		break;
	case TCSD_PACKET_TYPE_LOADKEY_INFO:
		UnloadBlob_LOADKEY_INFO(&offset, packet->dataBuffer, ((TCS_LOADKEY_INFO *)theData));
		break;
	case TCSD_PACKET_TYPE_UUID:
		UnloadBlob_UUID(&offset, packet->dataBuffer, (TSS_UUID *) theData);
		break;
#endif
#ifdef TSS_BUILD_PCR_EVENT
	case TCSD_PACKET_TYPE_PCR_EVENT:
		if ((UnloadBlob_PCR_EVENT(&offset, packet->dataBuffer, ((TSS_PCR_EVENT *)theData))))
			return TCSERR(TSS_E_OUTOFMEMORY);
#endif
		break;
	default:
		LogError("TCSD packet type unknown! (0x%x)", dataType & 0xff);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	packet->dataSize = offset;
	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_Error(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	LogError("%s reached.", __FUNCTION__);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	(*hdr)->result = TCSERR(TSS_E_FAIL);
	(*hdr)->packet_size = size;

	return TSS_SUCCESS;
}

/* Dispatch */
typedef struct tdDispatchTable {
	TSS_RESULT (*Func) (struct tcsd_thread_data *,
			    struct tsp_packet *,
			    struct tcsd_packet_hdr **);
	const char *name;
} DispatchTable;

DispatchTable tcs_func_table[TCSD_MAX_NUM_ORDS] = {
	{tcs_wrap_Error,"Error"},   /* 0 */
	{tcs_wrap_OpenContext,"OpenContext"},
	{tcs_wrap_CloseContext,"CloseContext"},
	{tcs_wrap_Error,"Error"},
	{tcs_wrap_TCSGetCapability,"TCSGetCapability"},
	{tcs_wrap_RegisterKey,"RegisterKey"}, /* 5 */
	{tcs_wrap_UnregisterKey,"UnregisterKey"},
	{tcs_wrap_EnumRegisteredKeys,"EnumRegisteredKeys"},
	{tcs_wrap_Error,"Error"},
	{tcs_wrap_GetRegisteredKeyBlob,"GetRegisteredKeyBlob"},
	{tcs_wrap_GetRegisteredKeyByPublicInfo,"GetRegisteredKeyByPublicInfo"}, /* 10 */
	{tcs_wrap_LoadKeyByBlob,"LoadKeyByBlob"},
	{tcs_wrap_LoadKeyByUUID,"LoadKeyByUUID"},
	{tcs_wrap_EvictKey,"EvictKey"},
	{tcs_wrap_CreateWrapKey,"CreateWrapKey"},
	{tcs_wrap_GetPubkey,"GetPubkey"}, /* 15 */
	{tcs_wrap_MakeIdentity,"MakeIdentity"},
	{tcs_wrap_LogPcrEvent,"LogPcrEvent"},
	{tcs_wrap_GetPcrEvent,"GetPcrEvent"},
	{tcs_wrap_GetPcrEventsByPcr,"GetPcrEventsByPcr"},
	{tcs_wrap_GetPcrEventLog,"GetPcrEventLog"}, /* 20 */
	{tcs_wrap_SetOwnerInstall,"SetOwnerInstall"},
	{tcs_wrap_TakeOwnership,"TakeOwnership"},
	{tcs_wrap_OIAP,"OIAP"},
	{tcs_wrap_OSAP,"OSAP"},
	{tcs_wrap_ChangeAuth,"ChangeAuth"}, /* 25 */
	{tcs_wrap_ChangeAuthOwner,"ChangeAuthOwner"},
	{tcs_wrap_Error,"Error"},
	{tcs_wrap_Error,"Error"},
	{tcs_wrap_TerminateHandle,"TerminateHandle"},
	{tcs_wrap_ActivateIdentity,"ActivateIdentity"}, /* 30 */
	{tcs_wrap_Extend,"Extend"},
	{tcs_wrap_PcrRead,"PcrRead"},
	{tcs_wrap_Quote,"Quote"},
	{tcs_wrap_DirWriteAuth,"DirWriteAuth"},
	{tcs_wrap_DirRead,"DirRead"}, /* 35 */
	{tcs_wrap_Seal,"Seal"},
	{tcs_wrap_UnSeal,"UnSeal"},
	{tcs_wrap_UnBind,"UnBind"},
	{tcs_wrap_CreateMigrationBlob,"CreateMigrationBlob"},
	{tcs_wrap_ConvertMigrationBlob,"ConvertMigrationBlob"}, /* 40 */
	{tcs_wrap_AuthorizeMigrationKey,"AuthorizeMigrationKey"},
	{tcs_wrap_CertifyKey,"CertifyKey"},
	{tcs_wrap_Sign,"Sign"},
	{tcs_wrap_GetRandom,"GetRandom"},
	{tcs_wrap_StirRandom,"StirRandom"}, /* 45 */
	{tcs_wrap_GetCapability,"GetCapability"},
	{tcs_wrap_Error,"Error"},
	{tcs_wrap_GetCapabilityOwner,"GetCapabilityOwner"},
	{tcs_wrap_CreateEndorsementKeyPair,"CreateEndorsementKeyPair"},
	{tcs_wrap_ReadPubek,"ReadPubek"}, /* 50 */
	{tcs_wrap_DisablePubekRead,"DisablePubekRead"},
	{tcs_wrap_OwnerReadPubek,"OwnerReadPubek"},
	{tcs_wrap_SelfTestFull,"SelfTestFull"},
	{tcs_wrap_CertifySelfTest,"CertifySelfTest"},
	{tcs_wrap_Error,"Error"}, /* 55 */
	{tcs_wrap_GetTestResult,"GetTestResult"},
	{tcs_wrap_OwnerSetDisable,"OwnerSetDisable"},
	{tcs_wrap_OwnerClear,"OwnerClear"},
	{tcs_wrap_DisableOwnerClear,"DisableOwnerClear"},
	{tcs_wrap_ForceClear,"ForceClear"}, /* 60 */
	{tcs_wrap_DisableForceClear,"DisableForceClear"},
	{tcs_wrap_PhysicalDisable,"PhysicalDisable"},
	{tcs_wrap_PhysicalEnable,"PhysicalEnable"},
	{tcs_wrap_PhysicalSetDeactivated,"PhysicalSetDeactivated"},
	{tcs_wrap_SetTempDeactivated,"SetTempDeactivated"}, /* 65 */
	{tcs_wrap_PhysicalPresence,"PhysicalPresence"},
	{tcs_wrap_Error,"Error"},
	{tcs_wrap_Error,"Error"},
	{tcs_wrap_CreateMaintenanceArchive,"CreateMaintenanceArchive"},
	{tcs_wrap_LoadMaintenanceArchive,"LoadMaintenanceArchive"}, /* 70 */
	{tcs_wrap_KillMaintenanceFeature,"KillMaintenanceFeature"},
	{tcs_wrap_LoadManuMaintPub,"LoadManuMaintPub"},
	{tcs_wrap_ReadManuMaintPub,"ReadManuMaintPub"},
	{tcs_wrap_DaaJoin,"DaaJoin"},
        {tcs_wrap_DaaSign,"DaaSign"}, /* 75 */
	{tcs_wrap_SetCapability,"SetCapability"},
	{tcs_wrap_ResetLockValue,"ResetLockValue"}
};

int
access_control(struct tcsd_thread_data *thread_data, struct tsp_packet *tsp_data)
{
	int i = 0;
	struct hostent *local_hostent = NULL;

	if ((local_hostent = gethostbyname("localhost")) == NULL) {
		LogError("Error resolving localhost: %s", hstrerror(h_errno));
		return 1;
	}

	/* if the request comes from localhost, or is in the accepted ops list,
	 * approve it */
	if (!strncmp(thread_data->hostname, local_hostent->h_name,
		     MIN((size_t)local_hostent->h_length, strlen(thread_data->hostname)))) {
		return 0;
	} else {
		while (tcsd_options.remote_ops[i]) {
			if ((UINT32)tcsd_options.remote_ops[i] == tsp_data->ordinal) {
				LogInfo("Accepted %s operation from %s",
					tcs_func_table[tsp_data->ordinal].name,
					thread_data->hostname);
				return 0;
			}
			i++;
		}
	}

	return 1;
}

TSS_RESULT
dispatchCommand(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	/* First, check the ordinal bounds */
	if (tsp_data->ordinal >= TCSD_MAX_NUM_ORDS) {
		LogError("Illegal TCSD Ordinal");
		return TCSERR(TSS_E_FAIL);
	}

	LogDebug("Dispatching ordinal %u", tsp_data->ordinal);
	if (access_control(data, tsp_data)) {
		*hdr = calloc(1, sizeof(struct tcsd_packet_hdr));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.",
					sizeof(struct tcsd_packet_hdr));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		(*hdr)->result = TCSERR(TSS_E_FAIL);
		(*hdr)->packet_size = sizeof(struct tcsd_packet_hdr);

		LogWarn("Denied %s operation from %s", tcs_func_table[tsp_data->ordinal].name,
			data->hostname);

		return TSS_SUCCESS;
	}

	/* Now, dispatch */
	return tcs_func_table[tsp_data->ordinal].Func(data, tsp_data, hdr);
}

TSS_RESULT
getTCSDPacket(struct tcsd_thread_data *data, struct tcsd_packet_hdr **hdr)
{
	struct tsp_packet tsp_data;
	BYTE tmp_data[TSS_TCP_RPC_MAX_DATA_LEN];
	UINT64 offset = 0, tmp_offset;
	UINT32 totalSize;
	UINT32 result, operation_result;

	/* unload the wire blob (data->buf) into a host blob (tsp_data) */
	UnloadBlob_UINT32(&offset, &tsp_data.ordinal, data->buf);
	UnloadBlob_UINT32(&offset, &totalSize, data->buf);
	UnloadBlob_UINT16(&offset, &tsp_data.numParms, data->buf);

	/* Invalid packet check */
	if ((int)totalSize != data->buf_size) {
		LogDebug("Corrupt packet received. Actual size: %u, reported size: %u",
			 data->buf_size, totalSize);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	if (tsp_data.numParms > 0) {
		UnloadBlob(&offset, tsp_data.numParms, data->buf, tsp_data.types);

		/* if we've already unloaded totalSize bytes or more, the TSP's
		 * packet is bogus, return a code indicating that its the
		 * TSP's problem */
		if (offset < totalSize)
			UnloadBlob(&offset, totalSize - offset, data->buf, tsp_data.dataBuffer);
		else
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	/* dispatch the command to the TCS */
	if ((result = dispatchCommand(data, &tsp_data, hdr)))
		return result;

	operation_result = (*hdr)->result;
	totalSize = (*hdr)->packet_size;

	offset = 0;
	LoadBlob_UINT32(&offset, (*hdr)->result, (BYTE *)*hdr);
	LoadBlob_UINT32(&offset, (*hdr)->packet_size, (BYTE *)*hdr);

	if (operation_result == TSS_SUCCESS ||
	    (tsp_data.ordinal == TCSD_ORD_LOADKEYBYUUID &&
	     operation_result == TCSERR(TCS_E_KM_LOADFAILED))) {
		LoadBlob_UINT16(&offset, (*hdr)->num_parms, (BYTE *)*hdr);

		tmp_offset = 0;
		LoadBlob(&tmp_offset, TCSD_MAX_NUM_PARMS, tmp_data, (*hdr)->parm_types);
		LoadBlob(&offset, TCSD_MAX_NUM_PARMS, (BYTE *)*hdr, tmp_data);

		tmp_offset = 0;
		if (totalSize - offset > TSS_TCP_RPC_MAX_DATA_LEN)
			LogError("%s: ************** ERROR ***********************", __FUNCTION__);
		LoadBlob(&tmp_offset, totalSize - offset, tmp_data, &((*hdr)->data));
		LoadBlob(&offset, totalSize - offset, (BYTE *)*hdr, tmp_data);
	}

	return result;
}

