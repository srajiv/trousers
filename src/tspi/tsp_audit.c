
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2007
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "obj.h"


TSS_RESULT
audit_set_ordinal_audit_status(TSS_HTPM hTpm,
				TSS_FLAG flag,
				TSS_FLAG subFlag,
				UINT32 ulOrdinal)
{
	TSS_BOOL bAuditState;
	TSS_HCONTEXT tspContext;
	TSS_HPOLICY hPolicy;
	TPM_AUTH ownerAuth;
	Trspi_HashCtx hashCtx;
	TCPA_DIGEST digest;
	TSS_RESULT result = TSS_SUCCESS;

	if (flag != TSS_TSPATTRIB_TPM_ORDINAL_AUDIT_STATUS)
		return TSPERR(TSS_E_BAD_PARAMETER);

	switch (subFlag) {
		case TPM_CAP_PROP_TPM_SET_ORDINAL_AUDIT:
			bAuditState = TRUE;
			break;

		case TPM_CAP_PROP_TPM_CLEAR_ORDINAL_AUDIT:
			bAuditState = FALSE;
			break;

		default:
			return TSPERR(TSS_E_BAD_PARAMETER);
	}

	if ((result = obj_tpm_get_tsp_context(hTpm, &tspContext)))
		return result;

	if ((result = obj_tpm_get_policy(hTpm, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_SetOrdinalAuditStatus);
	result |= Trspi_Hash_UINT32(&hashCtx, ulOrdinal);
	result |= Trspi_Hash_BOOL(&hashCtx, bAuditState);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = secret_PerformAuth_OIAP(hTpm, TPM_ORD_SetOrdinalAuditStatus,
					      hPolicy, FALSE, &digest, &ownerAuth)))
		return result;

	if ((result = TCS_API(tspContext)->SetOrdinalAuditStatus(tspContext, &ownerAuth, ulOrdinal,
								 bAuditState)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, result);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_SetOrdinalAuditStatus);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	return obj_policy_validate_auth_oiap(hPolicy, &digest, &ownerAuth);
}
