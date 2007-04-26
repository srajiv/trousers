
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
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_RESULT
Tspi_PcrComposite_SetPcrLocality(TSS_HPCRS hPcrComposite,	/* in */
				 UINT32    LocalityValue)	/* in */
{
	switch (LocalityValue) {
		case TPM_LOC_FOUR:
		case TPM_LOC_THREE:
		case TPM_LOC_TWO:
		case TPM_LOC_ONE:
		case TPM_LOC_ZERO:
			break;
		default:
			return TSPERR(TSS_E_BAD_PARAMETER);
	}

	return obj_pcrs_set_locality(hPcrComposite, LocalityValue);
}

TSS_RESULT
Tspi_PcrComposite_GetPcrLocality(TSS_HPCRS hPcrComposite,	/* in */
				 UINT32*   pLocalityValue)	/* out */
{
	if (pLocalityValue == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	return obj_pcrs_get_locality(hPcrComposite, pLocalityValue);

}

TSS_RESULT
Tspi_PcrComposite_GetCompositeHash(TSS_HPCRS hPcrComposite,	/* in */
				   UINT32*   pLen,		/* out */
				   BYTE**    ppbHashData)	/* out */
{
	if (pLen == NULL || ppbHashData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	return obj_pcrs_get_digest_at_release(hPcrComposite, pLen, ppbHashData);

}

TSS_RESULT
Tspi_PcrComposite_SelectPcrIndexEx(TSS_HPCRS hPcrComposite,	/* in */
				   UINT32    ulPcrIndex,	/* in */
				   UINT32    Direction)		/* in */
{
	if (Direction != TSS_PCRS_DIRECTION_CREATION && Direction != TSS_PCRS_DIRECTION_RELEASE)
		return TSPERR(TSS_E_BAD_PARAMETER);

	return obj_pcrs_select_index_ex(hPcrComposite, Direction, ulPcrIndex);
}
