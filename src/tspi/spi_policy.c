
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#include <stdlib.h>
#include <stdio.h>

#include "trousers/tss.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_RESULT
Tspi_Policy_SetSecret(TSS_HPOLICY hPolicy,	/* in */
		      TSS_FLAG secretMode,	/* in */
		      UINT32 ulSecretLength,	/* in */
		      BYTE * rgbSecret		/* in */
    )
{
	TSS_RESULT result;
	TSS_HCONTEXT tspContext;

	if ((result = obj_policy_get_tsp_context(hPolicy, &tspContext)))
		return result;

	if (obj_context_is_silent(tspContext) && secretMode == TSS_SECRET_MODE_POPUP)
		return TSPERR(TSS_E_SILENT_CONTEXT);

	return obj_policy_set_secret(hPolicy, secretMode, ulSecretLength, rgbSecret);
}

TSS_RESULT
Tspi_Policy_FlushSecret(TSS_HPOLICY hPolicy	/* in */
    )
{
	return obj_policy_flush_secret(hPolicy);
}

TSS_RESULT
Tspi_Policy_AssignToObject(TSS_HPOLICY hPolicy,	/* in */
			   TSS_HOBJECT hObject	/* in */
    )
{
	TSS_RESULT result;
	UINT32 type;

	if ((result = obj_policy_get_type(hPolicy, &type)))
		return result;

	if (obj_is_rsakey(hObject)) {
		result = obj_rsakey_set_policy(hObject, type, hPolicy);
	} else if (obj_is_tpm(hObject)) {
		if (type != TSS_POLICY_USAGE)
			result = TSPERR(TSS_E_BAD_PARAMETER);
		else
			result = obj_tpm_set_policy(hObject, hPolicy);
	} else if (obj_is_encdata(hObject)) {
		result = obj_encdata_set_policy(hObject, type, hPolicy);
	} else {
		result = TSPERR(TSS_E_BAD_PARAMETER);
	}

	return result;
}
