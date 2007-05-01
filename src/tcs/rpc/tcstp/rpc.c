
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
#include <errno.h>

#include "trousers/tss.h"
#include "spi_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "rpc_tcstp_tcs.h"


/* Lock is not static because we need to reference it in the auth manager */
MUTEX_DECLARE_INIT(tcsp_lock);


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
recv_from_socket(int sock, void *buffer, int size)
{
        int recv_size = 0, recv_total = 0;

	while (recv_total < size) {
		errno = 0;
		if ((recv_size = recv(sock, buffer+recv_total, size-recv_total, 0)) <= 0) {
			if (recv_size < 0) {
				if (errno == EINTR)
					continue;
				LogError("Socket receive connection error: %s.", strerror(errno));
			} else {
				LogDebug("Socket connection closed.");
			}

			return -1;
		}
		recv_total += recv_size;
	}

	return recv_total;
}

int
send_to_socket(int sock, void *buffer, int size)
{
	int send_size = 0, send_total = 0;

	while (send_total < size) {
		if ((send_size = send(sock, buffer+send_total, size-send_total, 0)) < 0) {
			LogError("Socket send connection error: %s.", strerror(errno));
			return -1;
		}
		send_total += send_size;
	}

	return send_total;
}


void
initData(struct tcsd_comm_data *comm, int parm_count)
{
	/* min packet size should be the size of the header */
	memset(&comm->hdr, 0, sizeof(struct tcsd_packet_hdr));
	comm->hdr.packet_size = sizeof(struct tcsd_packet_hdr);
	if (parm_count > 0) {
		comm->hdr.type_offset = sizeof(struct tcsd_packet_hdr);
		comm->hdr.parm_offset = comm->hdr.type_offset +
			(sizeof(TCSD_PACKET_TYPE) * parm_count);
		comm->hdr.packet_size = comm->hdr.parm_offset;
	}

	memset(comm->buf, 0, comm->buf_size);
}

int
loadData(UINT64 *offset, TCSD_PACKET_TYPE data_type, void *data, int data_size, BYTE *blob)
{
	switch (data_type) {
		case TCSD_PACKET_TYPE_BYTE:
			LoadBlob_BYTE(offset, *((BYTE *) (data)), blob);
			break;
		case TCSD_PACKET_TYPE_BOOL:
			LoadBlob_BOOL(offset, *((TSS_BOOL *) (data)), blob);
			break;
		case TCSD_PACKET_TYPE_UINT16:
			LoadBlob_UINT16(offset, *((UINT16 *) (data)), blob);
			break;
		case TCSD_PACKET_TYPE_UINT32:
			LoadBlob_UINT32(offset, *((UINT32 *) (data)), blob);
			break;
		case TCSD_PACKET_TYPE_PBYTE:
			LoadBlob(offset, data_size, blob, data);
			break;
		case TCSD_PACKET_TYPE_NONCE:
			LoadBlob(offset, sizeof(TCPA_NONCE), blob, ((TCPA_NONCE *)data)->nonce);
			break;
		case TCSD_PACKET_TYPE_DIGEST:
			LoadBlob(offset, sizeof(TCPA_DIGEST), blob, ((TCPA_DIGEST *)data)->digest);
			break;
		case TCSD_PACKET_TYPE_AUTH:
			LoadBlob_Auth_Special(offset, blob, ((TPM_AUTH *)data));
			break;
		case TCSD_PACKET_TYPE_UUID:
			LoadBlob_UUID(offset, blob, *((TSS_UUID *)data));
			break;
		case TCSD_PACKET_TYPE_ENCAUTH:
			LoadBlob(offset, sizeof(TCPA_ENCAUTH), blob,
				 ((TCPA_ENCAUTH *)data)->authdata);
			break;
		case TCSD_PACKET_TYPE_VERSION:
			LoadBlob_VERSION(offset, blob, ((TCPA_VERSION *)data));
			break;
		case TCSD_PACKET_TYPE_KM_KEYINFO:
			LoadBlob_KM_KEYINFO(offset, blob, ((TSS_KM_KEYINFO *)data));
			break;
		case TCSD_PACKET_TYPE_LOADKEY_INFO:
			LoadBlob_LOADKEY_INFO(offset, blob, ((TCS_LOADKEY_INFO *)data));
			break;
		case TCSD_PACKET_TYPE_PCR_EVENT:
			LoadBlob_PCR_EVENT(offset, blob, ((TSS_PCR_EVENT *)data));
			break;
		default:
			LogError("TCSD packet type unknown! (0x%x)", data_type & 0xff);
			return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	return TSS_SUCCESS;
}


#if 0
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
#else
int
setData(TCSD_PACKET_TYPE dataType,
	int index,
	void *theData,
	int theDataSize,
	struct tcsd_comm_data *comm)
{
	UINT64 old_offset, offset;
	TSS_RESULT result;
	TCSD_PACKET_TYPE *type;

	/* Calculate the size of the area needed (use NULL for blob address) */
	offset = 0;
	if ((result = loadData(&offset, dataType, theData, theDataSize, NULL)) != TSS_SUCCESS)
		return result;
	if (((int)comm->hdr.packet_size + (int)offset) < 0) {
		LogError("Too much data to be transmitted!");
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (((int)comm->hdr.packet_size + (int)offset) > comm->buf_size) {
		/* reallocate the buffer */
		BYTE *buffer;
		int buffer_size = comm->hdr.packet_size + offset;
#if 0
		static int realloc_scalar = 1;

		realloc_scalar *= TCSD_COMMBUF_REALLOC_SCALAR;

		if (((int)offset * realloc_scalar) + buffer_size < 0)
			buffer_size = INT_MAX;
		else
			buffer_size += (int)offset * realloc_scalar;

		LogDebug("Increasing communication buffer by %d bytes.",
				(int)offset * realloc_scalar);
#endif
		LogDebug("Increasing communication buffer to %d bytes.", buffer_size);
		buffer = realloc(comm->buf, buffer_size);
		if (buffer == NULL) {
			LogError("realloc of %d bytes failed.", buffer_size);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		comm->buf_size = buffer_size;
		comm->buf = buffer;
	}

	offset = old_offset = comm->hdr.parm_offset + comm->hdr.parm_size;
	if ((result = loadData(&offset, dataType, theData, theDataSize, comm->buf)) != TSS_SUCCESS)
		return result;
	type = (TCSD_PACKET_TYPE *)(comm->buf + comm->hdr.type_offset) + index;
	*type = dataType;
	comm->hdr.type_size += sizeof(TCSD_PACKET_TYPE);
	comm->hdr.parm_size += (offset - old_offset);

	comm->hdr.packet_size = offset;
	comm->hdr.num_parms++;

	return TSS_SUCCESS;
}
#endif

#if 0
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
#else
UINT32
getData(TCSD_PACKET_TYPE dataType,
	int index,
	void *theData,
	int theDataSize,
	struct tcsd_comm_data *comm)
{
	TSS_RESULT result;
	UINT64 old_offset, offset;
	TCSD_PACKET_TYPE *type = (TCSD_PACKET_TYPE *)(comm->buf + comm->hdr.type_offset) + index;

	if ((UINT32)index >= comm->hdr.num_parms || dataType != *type) {
		LogDebug("Data type of TCS packet element %d doesn't match.", index);
		return TSS_TCP_RPC_BAD_PACKET_TYPE;
	}
	old_offset = offset = comm->hdr.parm_offset;
	switch (dataType) {
		case TCSD_PACKET_TYPE_BYTE:
			UnloadBlob_BYTE(&offset, (BYTE *) (theData), comm->buf);
			break;
		case TCSD_PACKET_TYPE_BOOL:
			UnloadBlob_BOOL(&offset, (TSS_BOOL *) (theData), comm->buf);
			break;
		case TCSD_PACKET_TYPE_UINT16:
			UnloadBlob_UINT16(&offset, (UINT16 *) (theData), comm->buf);
			break;
		case TCSD_PACKET_TYPE_UINT32:
			UnloadBlob_UINT32(&offset, (UINT32 *) (theData), comm->buf);
			break;
		case TCSD_PACKET_TYPE_PBYTE:
			UnloadBlob(&offset, theDataSize, comm->buf, theData);
			break;
		case TCSD_PACKET_TYPE_NONCE:
			UnloadBlob(&offset, sizeof(TCPA_NONCE), comm->buf,
					((TCPA_NONCE *) (theData))->nonce);
			break;
		case TCSD_PACKET_TYPE_DIGEST:
			UnloadBlob(&offset, sizeof(TCPA_DIGEST), comm->buf,
					((TCPA_DIGEST *) (theData))->digest);
			break;
		case TCSD_PACKET_TYPE_AUTH:
			UnloadBlob_Auth_Special(&offset, comm->buf, ((TPM_AUTH *) theData));
			break;
		case TCSD_PACKET_TYPE_ENCAUTH:
			UnloadBlob(&offset, sizeof(TCPA_ENCAUTH), comm->buf,
					((TCPA_ENCAUTH *) theData)->authdata);
			break;
		case TCSD_PACKET_TYPE_VERSION:
			UnloadBlob_VERSION(&offset, comm->buf, ((TCPA_VERSION *) theData));
			break;
#ifdef TSS_BUILD_PS
		case TCSD_PACKET_TYPE_KM_KEYINFO:
			UnloadBlob_KM_KEYINFO(&offset, comm->buf, ((TSS_KM_KEYINFO*)theData));
			break;
		case TCSD_PACKET_TYPE_LOADKEY_INFO:
			UnloadBlob_LOADKEY_INFO(&offset, comm->buf, ((TCS_LOADKEY_INFO *)theData));
			break;
		case TCSD_PACKET_TYPE_UUID:
			UnloadBlob_UUID(&offset, comm->buf, (TSS_UUID *) theData);
			break;
#endif
#ifdef TSS_BUILD_PCR_EVENTS
		case TCSD_PACKET_TYPE_PCR_EVENT:
			if ((result = UnloadBlob_PCR_EVENT(&offset, comm->buf,
							   ((TSS_PCR_EVENT *)theData))))
				return result;
			break;
#endif
		default:
			LogError("TCSD packet type unknown! (0x%x)", dataType & 0xff);
			return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	comm->hdr.parm_offset = offset;
	comm->hdr.parm_size -= (offset - old_offset);

	return TSS_SUCCESS;
}
#endif

TSS_RESULT
tcs_wrap_Error(struct tcsd_thread_data *data)
{
	LogError("%s reached.", __FUNCTION__);

	initData(&data->comm, 0);

	data->comm.hdr.u.result = TCSERR(TSS_E_FAIL);

	return TSS_SUCCESS;

}

/* Dispatch */
typedef struct tdDispatchTable {
	TSS_RESULT (*Func) (struct tcsd_thread_data *);
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
	{tcs_wrap_ResetLockValue,"ResetLockValue"},
	{tcs_wrap_PcrReset,"PcrReset"},
	{tcs_wrap_ReadCounter,"ReadCounter"},
	{tcs_wrap_CreateCounter,"CreateCounter"}, /* 80 */
	{tcs_wrap_IncrementCounter,"IncrementCounter"},
	{tcs_wrap_ReleaseCounter,"ReleaseCounter"},
	{tcs_wrap_ReleaseCounterOwner,"ReleaseCounterOwner"}
};

int
access_control(struct tcsd_thread_data *thread_data)
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
			if ((UINT32)tcsd_options.remote_ops[i] == thread_data->comm.hdr.u.ordinal) {
				LogInfo("Accepted %s operation from %s",
					tcs_func_table[thread_data->comm.hdr.u.ordinal].name,
					thread_data->hostname);
				return 0;
			}
			i++;
		}
	}

	return 1;
}

TSS_RESULT
dispatchCommand(struct tcsd_thread_data *data)
{
	UINT64 offset;
	TSS_RESULT result;

	/* First, check the ordinal bounds */
	if (data->comm.hdr.u.ordinal >= TCSD_MAX_NUM_ORDS) {
		LogError("Illegal TCSD Ordinal");
		return TCSERR(TSS_E_FAIL);
	}

	LogDebug("Dispatching ordinal %u", data->comm.hdr.u.ordinal);
	if (access_control(data)) {
		LogWarn("Denied %s operation from %s",
			tcs_func_table[data->comm.hdr.u.ordinal].name, data->hostname);

		/* set platform header */
		memset(&data->comm.hdr, 0, sizeof(data->comm.hdr));
		data->comm.hdr.packet_size = sizeof(struct tcsd_packet_hdr);
		data->comm.hdr.u.result = TCSERR(TSS_E_FAIL);

		/* set the comm buffer */
		memset(data->comm.buf, 0, data->comm.buf_size);
		offset = 0;
		LoadBlob_UINT32(&offset, data->comm.hdr.packet_size, data->comm.buf);
		LoadBlob_UINT32(&offset, data->comm.hdr.u.result, data->comm.buf);

		return TSS_SUCCESS;
	}

	/* Now, dispatch */
	if ((result = tcs_func_table[data->comm.hdr.u.ordinal].Func(data)) == TSS_SUCCESS) {
		/* set the comm buffer */
		offset = 0;
		LoadBlob_UINT32(&offset, data->comm.hdr.packet_size, data->comm.buf);
		LoadBlob_UINT32(&offset, data->comm.hdr.u.result, data->comm.buf);
		LoadBlob_UINT32(&offset, data->comm.hdr.num_parms, data->comm.buf);
		LoadBlob_UINT32(&offset, data->comm.hdr.type_size, data->comm.buf);
		LoadBlob_UINT32(&offset, data->comm.hdr.type_offset, data->comm.buf);
		LoadBlob_UINT32(&offset, data->comm.hdr.parm_size, data->comm.buf);
		LoadBlob_UINT32(&offset, data->comm.hdr.parm_offset, data->comm.buf);
	}

	return result;

}

#if 0
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
#else
TSS_RESULT
getTCSDPacket(struct tcsd_thread_data *data)
{
        /* make sure the all the data is present */
	if (data->comm.hdr.num_parms > 0 &&
	    data->comm.hdr.packet_size !=
		(UINT32)(data->comm.hdr.parm_offset + data->comm.hdr.parm_size))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	/* dispatch the command to the TCS */
	return dispatchCommand(data);
}
#endif
