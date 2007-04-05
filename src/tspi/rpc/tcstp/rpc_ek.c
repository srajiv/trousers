
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
TCSP_CreateEndorsementKeyPair_TP(struct host_table_entry *hte,
					     TCPA_NONCE antiReplay,	/* in */
					     UINT32 endorsementKeyInfoSize,	/* in */
					     BYTE * endorsementKeyInfo,	/* in */
					     UINT32 * endorsementKeySize,	/* out */
					     BYTE ** endorsementKey,	/* out */
					     TCPA_DIGEST * checksum	/* out */
    ) {

	TSS_RESULT result;

	initData(&hte->comm, 4);
	hte->comm.hdr.u.ordinal = TCSD_ORD_CREATEENDORSEMENTKEYPAIR;
	LogDebugFn("TCS Context: 0x%x", hte->tcsContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hte->tcsContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_NONCE, 1, &antiReplay, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &endorsementKeyInfoSize, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, endorsementKeyInfo, endorsementKeyInfoSize, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, endorsementKeySize, 0, &hte->comm)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*endorsementKey = (BYTE *) malloc(*endorsementKeySize);
		if (*endorsementKey == NULL) {
			LogError("malloc of %u bytes failed.", *endorsementKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *endorsementKey, *endorsementKeySize, &hte->comm)) {
			free(*endorsementKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_DIGEST, 2, &(checksum->digest), 0, &hte->comm)) {
			free(*endorsementKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	return result;
}

TSS_RESULT
TCSP_ReadPubek_TP(struct host_table_entry *hte,
			      TCPA_NONCE antiReplay,	/* in */
			      UINT32 * pubEndorsementKeySize,	/* out */
			      BYTE ** pubEndorsementKey,	/* out */
			      TCPA_DIGEST * checksum	/* out */
    ) {
	TSS_RESULT result;

	initData(&hte->comm, 2);
	hte->comm.hdr.u.ordinal = TCSD_ORD_READPUBEK;
	LogDebugFn("TCS Context: 0x%x", hte->tcsContext);
	/*      &hte->comm.numParms = 2; */

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hte->tcsContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_NONCE, 1, &antiReplay, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, pubEndorsementKeySize, 0, &hte->comm)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*pubEndorsementKey = (BYTE *) malloc(*pubEndorsementKeySize);
		if (*pubEndorsementKey == NULL) {
			LogError("malloc of %u bytes failed.", *pubEndorsementKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *pubEndorsementKey, *pubEndorsementKeySize, &hte->comm)) {
			free(*pubEndorsementKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_DIGEST, 2, &(checksum->digest), 0, &hte->comm)) {
			free(*pubEndorsementKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}
done:
	return result;
}

TSS_RESULT
TCSP_DisablePubekRead_TP(struct host_table_entry *hte,
				     TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;

	initData(&hte->comm, 2);
	hte->comm.hdr.u.ordinal = TCSD_ORD_DISABLEPUBEKREAD;
	LogDebugFn("TCS Context: 0x%x", hte->tcsContext);

        if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hte->tcsContext, 0, &hte->comm))
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

TSS_RESULT
TCSP_OwnerReadPubek_TP(struct host_table_entry *hte,
				   TPM_AUTH * ownerAuth,	/* in, out */
				   UINT32 * pubEndorsementKeySize,	/* out */
				   BYTE ** pubEndorsementKey	/* out */
    ) {

        TSS_RESULT result;

	initData(&hte->comm, 2);
        hte->comm.hdr.u.ordinal = TCSD_ORD_OWNERREADPUBEK;
	LogDebugFn("TCS Context: 0x%x", hte->tcsContext);

        if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hte->tcsContext, 0, &hte->comm))
                return TSPERR(TSS_E_INTERNAL_ERROR);
        if (setData(TCSD_PACKET_TYPE_AUTH, 1, ownerAuth, 0, &hte->comm))
                return TSPERR(TSS_E_INTERNAL_ERROR);

        result = sendTCSDPacket(hte);

        if (result == TSS_SUCCESS)
                result = hte->comm.hdr.u.result;

        if (result == TSS_SUCCESS) {
                if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, &hte->comm)){
			free(*pubEndorsementKey);
                        result = TSPERR(TSS_E_INTERNAL_ERROR);
		}

                if (getData(TCSD_PACKET_TYPE_UINT32, 1, pubEndorsementKeySize, 0, &hte->comm)) {
                        result = TSPERR(TSS_E_INTERNAL_ERROR);
                        goto done;
                }

                *pubEndorsementKey = (BYTE *) malloc(*pubEndorsementKeySize);
                if (*pubEndorsementKey == NULL) {
                        LogError("malloc of %u bytes failed.", *pubEndorsementKeySize);
                        result = TSPERR(TSS_E_OUTOFMEMORY);
                        goto done;
                }

                if (getData(TCSD_PACKET_TYPE_PBYTE, 2, *pubEndorsementKey, *pubEndorsementKeySize, &hte->comm)) {
                        free(*pubEndorsementKey);
                        result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
                }
        }

done:
	return result;
}
