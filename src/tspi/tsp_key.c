
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */


#include <stdlib.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


void
free_key_refs(TCPA_KEY *key)
{
	free(key->algorithmParms.parms);
	key->algorithmParms.parms = NULL;
	key->algorithmParms.parmSize = 0;

	free(key->pubKey.key);
	key->pubKey.key = NULL;
	key->pubKey.keyLength = 0;

	free(key->encData);
	key->encData = NULL;
	key->encSize = 0;

	free(key->PCRInfo);
	key->PCRInfo = NULL;
	key->PCRInfoSize = 0;
}
