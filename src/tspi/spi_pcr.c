
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
#include <string.h>

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"
#include "tss/trousers.h"

TSS_RESULT
Tspi_PcrComposite_SetPcrValue(TSS_HPCRS hPcrComposite,	/*  in */
			      UINT32 ulPcrIndex,	/*  in */
			      UINT32 ulPcrValueLength,	/*  in */
			      BYTE * rgbPcrValue	/*  in */
    )
{
	AnObject *anObject = NULL;
	TCPA_PCR_OBJECT *pcrObject = NULL;
	TSS_RESULT result;

	if (ulPcrValueLength == 0 || rgbPcrValue == NULL)
		return TSS_E_BAD_PARAMETER;

	if ((result = obj_checkType_1(hPcrComposite, TSS_OBJECT_TYPE_PCRS)))
		return result;

	anObject = getAnObjectByHandle(hPcrComposite);
	if (anObject == NULL)
		return TSS_E_INVALID_HANDLE;

	if (anObject->memPointer == NULL) {
		LogError("internal object pointer for handle 0x%x not found!", hPcrComposite);
		return TSS_E_INTERNAL_ERROR;
	}

	pcrObject = anObject->memPointer;
#if 0
	pcrValue = getPcrFromComposite( pcrObject->pcrComposite, ulPcrIndex );
	if( pcrValue == NULL )
		return TSS_E_INTERNAL_ERROR;

	memcpy( pcrValue->digest, rgbPcrValue, 20 );
#endif

	memcpy(pcrObject->pcrs[ulPcrIndex].digest, rgbPcrValue, ulPcrValueLength);
	calcCompositeHash(pcrObject->select, pcrObject->pcrs, &pcrObject->compositeHash);

	return TSS_SUCCESS;

}

TSS_RESULT
Tspi_PcrComposite_GetPcrValue(TSS_HPCRS hPcrComposite,	/*  in */
			      UINT32 ulPcrIndex,	/*  in */
			      UINT32 * pulPcrValueLength,	/*  out */
			      BYTE ** prgbPcrValue	/*  out */
    )
{
	TCPA_PCR_OBJECT *object;
	AnObject *anObject = NULL;
	TSS_RESULT result;
	TSS_HCONTEXT tspContext;

	if (pulPcrValueLength == NULL || prgbPcrValue == NULL)
		return TSS_E_BAD_PARAMETER;

	if ((result = obj_checkType_1(hPcrComposite, TSS_OBJECT_TYPE_PCRS)))
		return result;

	if ((tspContext = obj_getTspContext(hPcrComposite)) == NULL_HCONTEXT)
		return TSS_E_INTERNAL_ERROR;

	/* ===  Get the PCRObject */
	anObject = getAnObjectByHandle(hPcrComposite);
	if (anObject == NULL)
		return TSS_E_INVALID_HANDLE;
	if (anObject->memPointer == NULL) {
		LogError("internal object pointer for handle 0x%x not found!", hPcrComposite);
		return TSS_E_INTERNAL_ERROR;
	}

	object = anObject->memPointer;

	/* ===  Make sure the ulPcrIndex is valid */
	if (object->select.sizeOfSelect <= (ulPcrIndex >> 8))
/* 	if( object->pcrComposite.select.sizeOfSelect <= ( ulPcrIndex >> 3 )) */
		return TSS_E_BAD_PARAMETER;

	*prgbPcrValue = NULL;

/* 	val = getPcrFromComposite( object->pcrComposite, ulPcrIndex ); */

/* 	if( val == NULL ) */
/* 		return TSS_E_BAD_PARAMETER; */
	*prgbPcrValue = calloc_tspi(tspContext, 20);
	if (*prgbPcrValue == NULL) {
		LogError("malloc of %d bytes failed.", 20);
		return TSS_E_OUTOFMEMORY;
	}
/* 	*prgbPcrValue = malloc( 20 ); */
/* 	memcpy( *prgbPcrValue, val->digest, 20 ); */
	memcpy(*prgbPcrValue, object->pcrs[ulPcrIndex].digest, 20);
	*pulPcrValueLength = 20;
	return TSS_SUCCESS;

}

TSS_RESULT
Tspi_PcrComposite_SelectPcrIndex(TSS_HPCRS hPcrComposite,	/*  in */
				 UINT32 ulPcrIndex	/*  in */
    )
{
	TCPA_PCR_OBJECT *object;
	AnObject *anObject = NULL;
	BYTE mask;
	//TCS_CONTEXT_HANDLE hContext;
	//UINT32 numPCRs;
	TSS_RESULT result;
#if 0
//      UINT32 valueOffset;
//      UINT32 bufferOffset;
//      UINT32 i, j;
//      BYTE buffer[1024];
#endif
	if ((result = obj_checkType_1(hPcrComposite, TSS_OBJECT_TYPE_PCRS)))
		return result;

	/* ===  Get the PCRObject */
	anObject = getAnObjectByHandle(hPcrComposite);
	if (anObject == NULL)
		return TSS_E_INVALID_HANDLE;
	if (anObject->memPointer == NULL) {
		LogError("internal object pointer for handle 0x%x not found!", hPcrComposite);
		return TSS_E_INTERNAL_ERROR;
	}

	/* ---  Here is the actual object */
	object = anObject->memPointer;

	/* ===  Make sure the ulPcrIndex is valid against what the object says */
	if (object->select.sizeOfSelect <= (ulPcrIndex >> 3))
/* 	if( object->pcrComposite.select.sizeOfSelect <= ( ulPcrIndex >> 3 )) */
		return TSS_E_BAD_PARAMETER;

	/* ===  Set the bit */
	mask = 1 << (ulPcrIndex & 0x07);
	if (object->select.pcrSelect[ulPcrIndex >> 3] & mask)
/* 	if( object->pcrComposite.select.pcrSelect[ ulPcrIndex >> 3 ] & mask ) */
		return TSS_SUCCESS;
	object->select.pcrSelect[ulPcrIndex >> 3] |= mask;
/* 	object->pcrComposite.select.pcrSelect[ ulPcrIndex >> 3 ] |= mask; */

#if 0
	/* ===  Setup 20 bytes of 0 in the composite */
	valueOffset = 0;
	bufferOffset = 0;
	for (j = 0; j < object->pcrComposite.select.sizeOfSelect; j++)
		for (i = 0; i < 8; i++) {
			if (object->pcrComposite.select.pcrSelect[j] & (1 << i)) {
				if (j == (ulPcrIndex >> 3) && ((1 << i) == mask)) {	/*  && !alreadyExists ) */
					memset(&buffer[bufferOffset], 0x00, 20);	/* stick some 0's in there */
				} else {
					memcpy(&buffer[bufferOffset],
					       &object->pcrComposite.
					       pcrValue[valueOffset].digest, 20);
					valueOffset++;	/*  += 20; */
				}
				bufferOffset += 20;
			}

		}
#endif
	memset(object->pcrs[ulPcrIndex].digest, 0, 20);
#if 0
//      if( object->pcrComposite.pcrValue != NULL )
//              try_FreeMemory( object->pcrComposite.pcrValue );
//              free( object->pcrComposite.pcrValue );
//      object->pcrComposite.pcrValue = malloc( bufferOffset );
//      object->pcrComposite.valueSize = bufferOffset;// / 20;

//      bufferOffset = 0;
//      for( i = 0 ; i < object->pcrComposite.valueSize / 20 ; i++, bufferOffset += 20 )
//      {
//              memcpy( object->pcrComposite.pcrValue[i].digest, &buffer[bufferOffset], 20 );
//      }
//              Trspi_Hash( TSS_SHA1, object->pcrComposite.valueSize, object->pcrComposite.pcrValue, object->compositeHash.digest );
//      calculateCompositeHash( object->pcrComposite, &object->compositeHash );
#endif
	calcCompositeHash(object->select, object->pcrs, &object->compositeHash);

	return TSS_SUCCESS;
}
