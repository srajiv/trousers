
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
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Tspi_TPM_SetStatus(TSS_HTPM hTPM,	/* in */
		   TSS_FLAG statusFlag,	/* in */
		   TSS_BOOL fTpmState)	/* in */
{
	TPM_AUTH auth;
	TSS_RESULT result;
	TCPA_DIGEST hashDigest;
	TSS_HCONTEXT tspContext;
	TSS_HPOLICY hPolicy;
	Trspi_HashCtx hashCtx;

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_tpm_get_policy(hTPM, &hPolicy)))
		return result;

	switch (statusFlag) {
	case TSS_TPMSTATUS_DISABLEOWNERCLEAR:
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_DisableOwnerClear);
		if ((result |= Trspi_HashFinal(&hashCtx, hashDigest.digest)))
			return result;

		if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_DisableOwnerClear, hPolicy,
						      &hashDigest, &auth)))
			return result;

		if ((result = TCSP_DisableOwnerClear(tspContext, &auth)))
			return result;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_DisableOwnerClear);
		if ((result |= Trspi_HashFinal(&hashCtx, hashDigest.digest)))
			return result;

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &hashDigest, &auth)))
			return result;
		break;
	case TSS_TPMSTATUS_DISABLEFORCECLEAR:
		result = TCSP_DisableForceClear(tspContext);
		break;
	case TSS_TPMSTATUS_OWNERSETDISABLE:
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_OwnerSetDisable);
		result |= Trspi_Hash_BOOL(&hashCtx, fTpmState);
		if ((result |= Trspi_HashFinal(&hashCtx, hashDigest.digest)))
			return result;

		if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_OwnerSetDisable, hPolicy,
						      &hashDigest, &auth)))
			return result;

		if ((result = TCSP_OwnerSetDisable(tspContext, fTpmState, &auth)))
			return result;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_OwnerSetDisable);
		if ((result |= Trspi_HashFinal(&hashCtx, hashDigest.digest)))
			return result;

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &hashDigest, &auth)))
			return result;
		break;
	case TSS_TPMSTATUS_PHYSICALDISABLE:
		if (fTpmState)
			result = TCSP_PhysicalDisable(tspContext);
		else
			result = TCSP_PhysicalEnable(tspContext);
		break;
	case TSS_TPMSTATUS_PHYSICALSETDEACTIVATED:
		result = TCSP_PhysicalSetDeactivated(tspContext, fTpmState);
		break;
	case TSS_TPMSTATUS_SETTEMPDEACTIVATED:
		result = TCSP_SetTempDeactivated(tspContext);
		break;
	case TSS_TPMSTATUS_SETOWNERINSTALL:
		result = TCSP_SetOwnerInstall(tspContext, fTpmState);
		break;
	case TSS_TPMSTATUS_DISABLEPUBEKREAD:
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_DisablePubekRead);
		if ((result |= Trspi_HashFinal(&hashCtx, hashDigest.digest)))
			return result;

		if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_DisablePubekRead, hPolicy,
						      &hashDigest, &auth)))
			return result;

		if ((result = TCSP_DisablePubekRead(tspContext, &auth)))
			return result;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_DisablePubekRead);
		if ((result |= Trspi_HashFinal(&hashCtx, hashDigest.digest)))
			return result;

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &hashDigest, &auth)))
			return result;
		break;
#ifdef TSS_BUILD_TSS12
	case TSS_TPMSTATUS_DISABLEPUBSRKREAD:
		/* The logic of setting a 'disable' flag is reversed in the TPM, where setting this
		 * flag to TRUE will enable the SRK read, while FALSE disables it. So we need to
		 * flip the bool here. Sigh... */
		fTpmState = fTpmState ? FALSE : TRUE;

		result = TSP_SetCapability(tspContext, hTPM, hPolicy, TPM_SET_PERM_FLAGS,
					   TPM_PF_READSRKPUB, fTpmState);
		break;
	case TSS_TPMSTATUS_RESETLOCK:
		/* ignoring the bool here */
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_ResetLockValue);
		if ((result |= Trspi_HashFinal(&hashCtx, hashDigest.digest)))
			return result;

		if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_ResetLockValue, hPolicy,
						      &hashDigest, &auth)))
			return result;

		result = TCSP_ResetLockValue(tspContext, &auth);

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_ResetLockValue);
		if ((result |= Trspi_HashFinal(&hashCtx, hashDigest.digest)))
			return result;

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &hashDigest, &auth)))
			return result;
		break;
#endif
#ifndef TSS_SPEC_COMPLIANCE
	case TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK:
		/* set the lifetime lock bit */
		result = TCSP_PhysicalPresence(tspContext, TCPA_PHYSICAL_PRESENCE_LIFETIME_LOCK);
		break;
	case TSS_TPMSTATUS_PHYSPRES_HWENABLE:
		/* set the HW enable bit */
		result = TCSP_PhysicalPresence(tspContext, TCPA_PHYSICAL_PRESENCE_HW_ENABLE);
		break;
	case TSS_TPMSTATUS_PHYSPRES_CMDENABLE:
		/* set the command enable bit */
		result = TCSP_PhysicalPresence(tspContext, TCPA_PHYSICAL_PRESENCE_CMD_ENABLE);
		break;
	case TSS_TPMSTATUS_PHYSPRES_LOCK:
		/* set the physical presence lock bit */
		result = TCSP_PhysicalPresence(tspContext, TCPA_PHYSICAL_PRESENCE_LOCK);
		break;
	case TSS_TPMSTATUS_PHYSPRESENCE:
		/* set the physical presence state */
		result = TCSP_PhysicalPresence(tspContext, (fTpmState ?
							    TCPA_PHYSICAL_PRESENCE_PRESENT :
							    TCPA_PHYSICAL_PRESENCE_NOTPRESENT));
		break;
#endif
	default:
		return TSPERR(TSS_E_BAD_PARAMETER);
		break;
	}

	return result;
}

TSS_RESULT
Tspi_TPM_GetStatus(TSS_HTPM hTPM,		/* in */
		   TSS_FLAG statusFlag,		/* in */
		   TSS_BOOL * pfTpmState)	/* out */
{
	TSS_HCONTEXT tspContext;
	TSS_RESULT result;
	UINT32 nonVolFlags;
	UINT32 volFlags;

	if (pfTpmState == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = get_tpm_flags(tspContext, hTPM, &volFlags, &nonVolFlags)))
		return result;

	switch (statusFlag) {
	case TSS_TPMSTATUS_DISABLEOWNERCLEAR:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_OWNER_CLEARABLE);
		break;
	case TSS_TPMSTATUS_DISABLEFORCECLEAR:
		*pfTpmState = BOOL(volFlags & TPM11_VOL_PRES_CLEARABLE);
		break;
	case TSS_TPMSTATUS_DISABLED:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_DISABLED);
		break;
	case TSS_TPMSTATUS_PHYSICALSETDEACTIVATED:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_DEACTIVATED);
		break;
	case TSS_TPMSTATUS_SETTEMPDEACTIVATED:
		*pfTpmState = BOOL(volFlags & TPM11_VOL_TEMP_DEACTIVATED);
		break;
	case TSS_TPMSTATUS_SETOWNERINSTALL:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_OWNABLE);
		break;
	case TSS_TPMSTATUS_DISABLEPUBEKREAD:
		*pfTpmState = INVBOOL(nonVolFlags & TPM11_NONVOL_READABLE_PUBEK);
		break;
	case TSS_TPMSTATUS_ALLOWMAINTENANCE:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_ALLOW_MAINT);
		break;
	case TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_LIFETIME_LOCK);
		break;
	case TSS_TPMSTATUS_PHYSPRES_HWENABLE:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_HW_PRES);
		break;
	case TSS_TPMSTATUS_PHYSPRES_CMDENABLE:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_CMD_PRES);
		break;
	case TSS_TPMSTATUS_CEKP_USED:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_CEKP_USED);
		break;
	case TSS_TPMSTATUS_PHYSPRESENCE:
		*pfTpmState = BOOL(volFlags & TPM11_VOL_PRES);
		break;
	case TSS_TPMSTATUS_PHYSPRES_LOCK:
		*pfTpmState = BOOL(volFlags & TPM11_VOL_PRES_LOCK);
		break;
#ifdef TSS_BUILD_NV
	case TSS_TPMSTATUS_NV_LOCK:
		*pfTpmState = BOOL(volFlags & TPM_PF_NV_LOCKED);
		break;
#endif
#ifdef TSS_BUILD_TSS12
	case TSS_TPMSTATUS_DISABLEPUBSRKREAD:
		break;
#endif
	default:
		return TSPERR(TSS_E_BAD_PARAMETER);
		break;
	}

	return TSS_SUCCESS;
}
