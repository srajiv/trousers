
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
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Tspi_TPM_GetCapability(TSS_HTPM hTPM,			/* in */
		       TSS_FLAG capArea,		/* in */
		       UINT32 ulSubCapLength,		/* in */
		       BYTE * rgbSubCap,		/* in */
		       UINT32 * pulRespDataLength,	/* out */
		       BYTE ** prgbRespData)		/* out */
{
	TSS_HCONTEXT tspContext;
	TCPA_CAPABILITY_AREA tcsCapArea;
	UINT32 tcsSubCap = 0;
	UINT32 tcsSubCapContainer;
	TSS_RESULT result;
	UINT32 nonVolFlags, volFlags, respLen, correct_endianess = 0;
	BYTE *respData;
	UINT64 offset;
	TSS_BOOL fOwnerAuth = FALSE; /* flag for caps that need owner auth */

	if (pulRespDataLength == NULL || prgbRespData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	/* Verify the caps and subcaps */
	switch (capArea) {
	case TSS_TPMCAP_ORD:
		if ((ulSubCapLength != sizeof(UINT32)) || !rgbSubCap)
			return TSPERR(TSS_E_BAD_PARAMETER);

		tcsCapArea = TCPA_CAP_ORD;
		tcsSubCap = *(UINT32 *)rgbSubCap;
		break;
	case TSS_TPMCAP_FLAG:
		fOwnerAuth = TRUE;
		break;
	case TSS_TPMCAP_ALG:
		if ((ulSubCapLength != sizeof(UINT32)) || !rgbSubCap)
			return TSPERR(TSS_E_BAD_PARAMETER);

		tcsCapArea = TPM_CAP_ALG;

		switch (*(UINT32 *)rgbSubCap) {
			case TSS_ALG_RSA:
				tcsSubCap = TPM_ALG_RSA;
				break;
			case TSS_ALG_AES128:
				tcsSubCap = TPM_ALG_AES128;
				break;
			case TSS_ALG_AES192:
				tcsSubCap = TPM_ALG_AES192;
				break;
			case TSS_ALG_AES256:
				tcsSubCap = TPM_ALG_AES256;
				break;
			case TSS_ALG_3DES:
				tcsSubCap = TPM_ALG_3DES;
				break;
			case TSS_ALG_DES:
				tcsSubCap = TPM_ALG_DES;
				break;
			default:
				tcsSubCap = *(UINT32 *)rgbSubCap;
				break;
		}
		break;
#ifdef TSS_BUILD_NV
	case TSS_TPMCAP_NV_LIST:
		tcsCapArea = TPM_CAP_NV_LIST;
		break;
	case TSS_TPMCAP_NV_INDEX:
		if ((ulSubCapLength != sizeof(UINT32)) || !rgbSubCap)
			return TSPERR(TSS_E_BAD_PARAMETER);

		tcsCapArea = TPM_CAP_NV_INDEX;
		tcsSubCap = *(UINT32 *)rgbSubCap;
		break;
#endif
	case TSS_TPMCAP_PROPERTY:	/* Determines a physical property of the TPM. */
		if ((ulSubCapLength != sizeof(UINT32)) || !rgbSubCap)
			return TSPERR(TSS_E_BAD_PARAMETER);

		tcsCapArea = TCPA_CAP_PROPERTY;
		tcsSubCapContainer = *(UINT32 *)rgbSubCap;

		if (tcsSubCapContainer == TSS_TPMCAP_PROP_PCR) {
			tcsSubCap = TPM_CAP_PROP_PCR;
			correct_endianess = 1;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_DIR) {
			tcsSubCap = TPM_CAP_PROP_DIR;
			correct_endianess = 1;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_SLOTS) {
			tcsSubCap = TPM_CAP_PROP_SLOTS;
			correct_endianess = 1;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_MANUFACTURER) {
			tcsSubCap = TPM_CAP_PROP_MANUFACTURER;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_COUNTERS) {
			tcsSubCap = TPM_CAP_PROP_COUNTERS;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_MAXCOUNTERS) {
			tcsSubCap = TPM_CAP_PROP_MAX_COUNTERS;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_MIN_COUNTER) {
			tcsSubCap = TPM_CAP_PROP_MIN_COUNTER;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_ACTIVECOUNTER) {
			tcsSubCap = TPM_CAP_PROP_ACTIVE_COUNTER;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_TRANSESSIONS) {
			tcsSubCap = TPM_CAP_PROP_TRANSSESS;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_MAXTRANSESSIONS) {
			tcsSubCap = TPM_CAP_PROP_MAX_TRANSSESS;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_SESSIONS) {
			tcsSubCap = TPM_CAP_PROP_SESSIONS;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_MAXSESSIONS) {
			tcsSubCap = TPM_CAP_PROP_MAX_SESSIONS;
		} else
			return TSPERR(TSS_E_BAD_PARAMETER);
		break;
	case TSS_TPMCAP_VERSION:	/* Queries the current TPM version. */
		tcsCapArea = TCPA_CAP_VERSION;
		break;
	case TSS_TPMCAP_VERSION_VAL:	/* Queries the current TPM version for 1.2 TPM device. */
		tcsCapArea = TPM_CAP_VERSION_VAL;
		break;
	default:
		return TSPERR(TSS_E_BAD_PARAMETER);
		break;
	}

	if (fOwnerAuth) {
		/* do an owner authorized get capability call */
		if ((result = get_tpm_flags(tspContext, hTPM, &volFlags, &nonVolFlags)))
			return result;

		respLen = 2 * sizeof(UINT32);
		respData = calloc_tspi(tspContext, respLen);
		if (respData == NULL) {
			LogError("malloc of %u bytes failed.", respLen);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, nonVolFlags, respData);
		Trspi_LoadBlob_UINT32(&offset, volFlags, respData);

		*pulRespDataLength = respLen;
		*prgbRespData = respData;

		return TSS_SUCCESS;
	}

	tcsSubCap = endian32(tcsSubCap);

	if ((result = TCSP_GetCapability(tspContext, tcsCapArea, ulSubCapLength, (BYTE *)&tcsSubCap,
					 &respLen, &respData)))
		return result;

	*prgbRespData = calloc_tspi(tspContext, respLen);
	if (*prgbRespData == NULL) {
		free(respData);
		LogError("malloc of %u bytes failed.", respLen);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	*pulRespDataLength = respLen;
	memcpy(*prgbRespData, respData, respLen);
	free(respData);

	if (*pulRespDataLength == sizeof(UINT32) && correct_endianess) {
		*((UINT32 *)(*prgbRespData)) = endian32(*((UINT32 *)(*prgbRespData)));
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_GetCapabilitySigned(TSS_HTPM hTPM,			/* in */
			     TSS_HTPM hKey,			/* in */
			     TSS_FLAG capArea,			/* in */
			     UINT32 ulSubCapLength,		/* in */
			     BYTE * rgbSubCap,			/* in */
			     TSS_VALIDATION * pValidationData,	/* in, out */
			     UINT32 * pulRespDataLength,	/* out */
			     BYTE ** prgbRespData)		/* out */
{
	/*
	 * Function was found to have a vulnerability, so implementation is not
	 * required by the TSS 1.1b spec.
	 */
	return TSPERR(TSS_E_NOTIMPL);
}

