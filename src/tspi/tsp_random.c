
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004, 2007
 *
 */


#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "tsplog.h"
#include "obj.h"


#ifdef TSS_BUILD_TRANSPORT
TSS_RESULT
Transport_GetRandom(TSS_HCONTEXT tspContext,	/* in */
		    UINT32 bytesRequested,	/* in */
		    BYTE ** randomBytes)	/* out */
{
	TSS_RESULT result;
        UINT32 decLen = 0;
        BYTE *dec = NULL;
        UINT64 offset;
	TCS_HANDLE handlesLen = 0;
        BYTE data[sizeof(UINT32)];

	if ((result = obj_context_transport_init(tspContext)))
		return result;

        LogDebugFn("Executing in a transport session");

        offset = 0;
        Trspi_LoadBlob_UINT32(&offset, bytesRequested, data);

        if ((result = obj_context_transport_execute(tspContext, TPM_ORD_GetRandom, sizeof(data),
                                                    data, NULL, &handlesLen, NULL, NULL, NULL,
						    &decLen, &dec)))
                return result;

        if ((*randomBytes = malloc(bytesRequested)) == NULL) {
                free(dec);
                LogError("malloc of %u bytes failed", bytesRequested);
                return TSPERR(TSS_E_OUTOFMEMORY);
        }

        offset = 0;
        Trspi_UnloadBlob(&offset, bytesRequested, dec, *randomBytes);

        free(dec);

        return result;

}

TSS_RESULT
Transport_StirRandom(TSS_HCONTEXT tspContext,	/* in */
		     UINT32 inDataSize,	/* in */
		     BYTE * inData)	/* in */
{
	TSS_RESULT result;
        UINT64 offset;
	TCS_HANDLE handlesLen = 0;
        BYTE data[sizeof(UINT32) + 256]; /* 256 is the max entropy size allowed */

	if ((result = obj_context_transport_init(tspContext)))
		return result;

        LogDebugFn("Executing in a transport session");

        offset = 0;
        Trspi_LoadBlob_UINT32(&offset, inDataSize, data);
        Trspi_LoadBlob(&offset, inDataSize, data, inData);

	return obj_context_transport_execute(tspContext, TPM_ORD_StirRandom, sizeof(data), data,
					     NULL, &handlesLen, NULL, NULL, NULL, NULL, NULL);
}
#endif

