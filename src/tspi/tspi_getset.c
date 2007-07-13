
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
#include <time.h>
#include <errno.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Tspi_SetAttribUint32(TSS_HOBJECT hObject,	/* in */
		     TSS_FLAG attribFlag,	/* in */
		     TSS_FLAG subFlag,		/* in */
		     UINT32 ulAttrib)		/* in */
{
	TSS_RESULT result;

	if (obj_is_rsakey(hObject)) {
#ifdef TSS_BUILD_RSAKEY_LIST
		if (attribFlag == TSS_TSPATTRIB_KEY_REGISTER) {
			if (subFlag)
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

			if (ulAttrib == TSS_TSPATTRIB_KEYREGISTER_USER)
				result = obj_rsakey_set_pstype(hObject, TSS_PS_TYPE_USER);
			else if (ulAttrib == TSS_TSPATTRIB_KEYREGISTER_SYSTEM)
				result = obj_rsakey_set_pstype(hObject, TSS_PS_TYPE_SYSTEM);
			else if (ulAttrib == TSS_TSPATTRIB_KEYREGISTER_NO)
				result = obj_rsakey_set_pstype(hObject, TSS_PS_TYPE_NO);
			else
				return TSPERR(TSS_E_INVALID_ATTRIB_DATA);
		} else if (attribFlag == TSS_TSPATTRIB_KEY_INFO) {
			switch (subFlag) {
				case TSS_TSPATTRIB_KEYINFO_USAGE:
					result = obj_rsakey_set_usage(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_MIGRATABLE:
					if (ulAttrib != TRUE && ulAttrib != FALSE)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_migratable(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_REDIRECTED:
					if (ulAttrib != TRUE && ulAttrib != FALSE)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_redirected(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_VOLATILE:
					if (ulAttrib != TRUE && ulAttrib != FALSE)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_volatile(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_AUTHUSAGE:
					/* fall through */
				case TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE:
					if (ulAttrib != TRUE && ulAttrib != FALSE)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_authdata_usage(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_ALGORITHM:
					result = obj_rsakey_set_alg(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_ENCSCHEME:
					if (ulAttrib != TSS_ES_NONE &&
					    ulAttrib != TSS_ES_RSAESPKCSV15 &&
					    ulAttrib != TSS_ES_RSAESOAEP_SHA1_MGF1)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_es(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_SIGSCHEME:
					if (ulAttrib != TSS_SS_NONE &&
					    ulAttrib != TSS_SS_RSASSAPKCS1V15_SHA1 &&
					    ulAttrib != TSS_SS_RSASSAPKCS1V15_DER)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_ss(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_KEYFLAGS:
					result = obj_rsakey_set_flags(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_SIZE:
					result = obj_rsakey_set_size(hObject, ulAttrib);
					break;
				default:
					return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else if (attribFlag == TSS_TSPATTRIB_RSAKEY_INFO) {
			if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_PRIMES) {
				result = obj_rsakey_set_num_primes(hObject, ulAttrib);
			} else
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
		} else
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
#endif
#ifdef TSS_BUILD_NV
	} else if (obj_is_nvstore(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_NV_INDEX:
				if ((result = obj_nvstore_set_index(hObject, ulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_NV_DATASIZE:
				if ((result = obj_nvstore_set_datasize(hObject, ulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_NV_PERMISSIONS:
				if ((result = obj_nvstore_set_permission(hObject, ulAttrib)))
					return result;
				break;
			default:
				return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
				break;
		}
#endif
	} else if (obj_is_policy(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_POLICY_CALLBACK_HMAC:
			case TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC:
			case TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP:
			case TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM:
				result = obj_policy_set_cb11(hObject, attribFlag,
							     subFlag, ulAttrib);
				break;
			case TSS_TSPATTRIB_POLICY_SECRET_LIFETIME:
				if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS) {
					result = obj_policy_set_lifetime(hObject);
				} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
					result = obj_policy_set_counter(hObject, ulAttrib);
				} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER) {
					result = obj_policy_set_timer(hObject, ulAttrib);
				} else {
					result = TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
				}
				break;
			case TSS_TSPATTRIB_SECRET_HASH_MODE:
				result = obj_policy_set_hash_mode(hObject, ulAttrib);
				break;
			default:
				return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
				break;
		}
	} else if (obj_is_context(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_CONTEXT_SILENT_MODE:
				if (ulAttrib == TSS_TSPATTRIB_CONTEXT_NOT_SILENT)
					result = obj_context_set_mode(hObject, ulAttrib);
				else if (ulAttrib == TSS_TSPATTRIB_CONTEXT_SILENT) {
					if (obj_context_has_popups(hObject))
						return TSPERR(TSS_E_SILENT_CONTEXT);
					result = obj_context_set_mode(hObject, ulAttrib);
				} else
					return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
				break;
			case TSS_TSPATTRIB_CONTEXT_TRANSPORT:
				if (subFlag == TSS_TSPATTRIB_CONTEXTTRANS_CONTROL) {
					if (ulAttrib != TSS_TSPATTRIB_DISABLE_TRANSPORT &&
					    ulAttrib != TSS_TSPATTRIB_ENABLE_TRANSPORT)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_context_transport_set_control(hObject,
										   ulAttrib);
				} else if (subFlag == TSS_TSPATTRIB_CONTEXTTRANS_MODE) {
					switch (ulAttrib) {
						case TSS_TSPATTRIB_TRANSPORT_NO_DEFAULT_ENCRYPTION:
						case TSS_TSPATTRIB_TRANSPORT_DEFAULT_ENCRYPTION:
						case TSS_TSPATTRIB_TRANSPORT_AUTHENTIC_CHANNEL:
						case TSS_TSPATTRIB_TRANSPORT_EXCLUSIVE:
						case TSS_TSPATTRIB_TRANSPORT_STATIC_AUTH:
							break;
						default:
							return TSPERR(TSS_E_INVALID_ATTRIB_DATA);
					}

					result = obj_context_transport_set_mode(hObject, ulAttrib);
				} else
					return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

				break;
			case TSS_TSPATTRIB_SECRET_HASH_MODE:
				result = obj_context_set_hash_mode(hObject, ulAttrib);
				break;
			default:
				return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
				break;
		}
	} else if (obj_is_tpm(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY:
			case TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY:
				if ((result = obj_tpm_set_cb11(hObject, attribFlag, subFlag,
							       ulAttrib)))
					return result;
				break;
			default:
				result = TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
				break;
		}
	} else {
		if (obj_is_hash(hObject) || obj_is_pcrs(hObject) || obj_is_encdata(hObject))
			result = TSPERR(TSS_E_BAD_PARAMETER);
		else
			result = TSPERR(TSS_E_INVALID_HANDLE);
	}

	return result;
}

TSS_RESULT
Tspi_GetAttribUint32(TSS_HOBJECT hObject,	/* in */
		     TSS_FLAG attribFlag,	/* in */
		     TSS_FLAG subFlag,		/* in */
		     UINT32 * pulAttrib)	/* out */
{
	UINT32 attrib;
	TSS_RESULT result = TSS_SUCCESS;

	if (pulAttrib == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (obj_is_rsakey(hObject)) {
#ifdef TSS_BUILD_RSAKEY_LIST
		if (attribFlag == TSS_TSPATTRIB_KEY_REGISTER) {
			if (subFlag != 0)
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

			if ((result = obj_rsakey_get_pstype(hObject, &attrib)))
				return result;

			if (attrib == TSS_PS_TYPE_USER)
				*pulAttrib = TSS_TSPATTRIB_KEYREGISTER_USER;
			else if (attrib == TSS_PS_TYPE_SYSTEM)
				*pulAttrib = TSS_TSPATTRIB_KEYREGISTER_SYSTEM;
			else
				*pulAttrib = TSS_TSPATTRIB_KEYREGISTER_NO;
		} else if (attribFlag == TSS_TSPATTRIB_KEY_INFO) {
			switch (subFlag) {
			case TSS_TSPATTRIB_KEYINFO_USAGE:
				if ((result = obj_rsakey_get_usage(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_MIGRATABLE:
				*pulAttrib = obj_rsakey_is_migratable(hObject);
				break;
			case TSS_TSPATTRIB_KEYINFO_REDIRECTED:
				*pulAttrib = obj_rsakey_is_redirected(hObject);
				break;
			case TSS_TSPATTRIB_KEYINFO_VOLATILE:
				*pulAttrib = obj_rsakey_is_volatile(hObject);
				break;
			case TSS_TSPATTRIB_KEYINFO_AUTHUSAGE:
				/* fall through */
			case TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE:
				if ((result = obj_rsakey_get_authdata_usage(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_ALGORITHM:
				if ((result = obj_rsakey_get_alg(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_ENCSCHEME:
				if ((result = obj_rsakey_get_es(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_SIGSCHEME:
				if ((result = obj_rsakey_get_ss(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_KEYFLAGS:
				if ((result = obj_rsakey_get_flags(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_SIZE:
				if ((result = obj_rsakey_get_size(hObject, pulAttrib)))
					return result;
				break;
			default:
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else if (attribFlag == TSS_TSPATTRIB_RSAKEY_INFO) {
			if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE) {
				if ((result = obj_rsakey_get_size(hObject, pulAttrib)))
					return result;
			} else if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_PRIMES) {
				if ((result = obj_rsakey_get_num_primes(hObject, pulAttrib)))
					return result;
			} else {
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
#endif
#ifdef TSS_BUILD_NV
	} else if (obj_is_nvstore(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_NV_INDEX:
				if ((result = obj_nvstore_get_index(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_NV_DATASIZE:
				if ((result = obj_nvstore_get_datasize(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_NV_PERMISSIONS:
				if ((result = obj_nvstore_get_permission(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_NV_STATE:
				switch (subFlag) {
					case TSS_TSPATTRIB_NVSTATE_READSTCLEAR:
						if ((result =
						     obj_nvstore_get_state_readstclear(hObject,
										       pulAttrib)))
							return result;
						break;
					case TSS_TSPATTRIB_NVSTATE_WRITEDEFINE:
						if ((result =
						     obj_nvstore_get_state_writedefine(hObject,
										       pulAttrib)))
							return result;
						break;
					case TSS_TSPATTRIB_NVSTATE_WRITESTCLEAR:
						if ((result =
						     obj_nvstore_get_state_writestclear(hObject,
											pulAttrib)))
							return result;
						break;
					default:
						return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
					}
				break;
			case TSS_TSPATTRIB_NV_PCR:
				switch (subFlag) {
					case TSS_TSPATTRIB_NVPCR_READLOCALITYATRELEASE:
						if ((result =
						     obj_nvstore_get_readlocalityatrelease(hObject,
											   pulAttrib)))
							return result;
						break;
					case TSS_TSPATTRIB_NVPCR_WRITELOCALITYATRELEASE:
						if ((result =
						     obj_nvstore_get_writelocalityatrelease(hObject,
											    pulAttrib)))
							return result;
						break;
					default:
						return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
					}
				break;
			default:
				return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
		}
#endif
	} else if (obj_is_policy(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_POLICY_CALLBACK_HMAC:
			case TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC:
			case TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP:
			case TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM:
				if ((result = obj_policy_get_cb11(hObject, attribFlag, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_POLICY_SECRET_LIFETIME:
				if ((result = obj_policy_get_lifetime(hObject, &attrib)))
					return result;

				if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS) {
					if (attrib == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS)
						*pulAttrib = TRUE;
					else
						*pulAttrib = FALSE;
				} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
					if (attrib != TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER)
						return TSPERR(TSS_E_BAD_PARAMETER);
					if ((result = obj_policy_get_counter(hObject, pulAttrib)))
						return result;
				} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER) {
					if ((result =
					    obj_policy_get_secs_until_expired(hObject, pulAttrib)))
						return result;
				} else
					return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
				break;
			case TSS_TSPATTRIB_SECRET_HASH_MODE:
				if (subFlag == TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP)
					result = obj_policy_get_hash_mode(hObject, pulAttrib);
				else
					return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
				break;
			default:
				return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
				break;
		}
	} else if (obj_is_context(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_CONTEXT_SILENT_MODE:
				if ((result = obj_context_get_mode(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_SECRET_HASH_MODE:
				if (subFlag == TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP)
					result = obj_context_get_hash_mode(hObject, pulAttrib);
				else
					return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
				break;
			case TSS_TSPATTRIB_CONTEXT_TRANSPORT:
				if (subFlag == TSS_TSPATTRIB_DISABLE_TRANSPORT ||
				    subFlag == TSS_TSPATTRIB_ENABLE_TRANSPORT) {
					result = obj_context_transport_get_control(hObject, subFlag,
										   pulAttrib);
				} else if (
					subFlag == TSS_TSPATTRIB_TRANSPORT_NO_DEFAULT_ENCRYPTION ||
					subFlag == TSS_TSPATTRIB_TRANSPORT_DEFAULT_ENCRYPTION ||
					subFlag == TSS_TSPATTRIB_TRANSPORT_AUTHENTIC_CHANNEL ||
					subFlag == TSS_TSPATTRIB_TRANSPORT_EXCLUSIVE ||
					subFlag == TSS_TSPATTRIB_TRANSPORT_STATIC_AUTH) {
					result = obj_context_transport_get_mode(hObject, subFlag,
										pulAttrib);
				} else
					return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
				break;
			default:
				return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
				break;
		}
	} else if (obj_is_tpm(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY:
			case TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY:
				if ((result = obj_tpm_get_cb11(hObject, attribFlag, pulAttrib)))
					return result;
				break;
			default:
				result = TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
				break;
		}
	} else {
		if (obj_is_hash(hObject) || obj_is_pcrs(hObject) || obj_is_encdata(hObject))
			result = TSPERR(TSS_E_BAD_PARAMETER);
		else
			result = TSPERR(TSS_E_INVALID_HANDLE);
	}

	return result;
}

TSS_RESULT
Tspi_SetAttribData(TSS_HOBJECT hObject,		/* in */
		   TSS_FLAG attribFlag,		/* in */
		   TSS_FLAG subFlag,		/* in */
		   UINT32 ulAttribDataSize,	/* in */
		   BYTE * rgbAttribData)	/* in */
{
	TSS_RESULT result;
	BYTE *string = NULL;

	if (obj_is_rsakey(hObject)) {
#ifdef TSS_BUILD_RSAKEY_LIST
		if (attribFlag == TSS_TSPATTRIB_KEY_BLOB) {
			if (subFlag == TSS_TSPATTRIB_KEYBLOB_BLOB) {
				/* A TCPA_KEY structure, in blob form */
				result = obj_rsakey_set_tcpakey(hObject, ulAttribDataSize,
								rgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY) {
				/* A TCPA_PUBKEY structure, in blob form */
				result = obj_rsakey_set_pubkey(hObject, FALSE, rgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY) {
				/* A blob, either encrypted or unencrypted */
				result = obj_rsakey_set_privkey(hObject, FALSE, ulAttribDataSize,
								rgbAttribData);
			} else {
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else if (attribFlag == TSS_TSPATTRIB_RSAKEY_INFO) {
			if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT) {
				result = obj_rsakey_set_exponent(hObject, ulAttribDataSize,
								 rgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_MODULUS) {
				result = obj_rsakey_set_modulus(hObject, ulAttribDataSize,
								rgbAttribData);
			} else {
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else {
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
		}
#endif
	} else if (obj_is_encdata(hObject)) {
#ifdef TSS_BUILD_ENCDATA_LIST
		if (attribFlag != TSS_TSPATTRIB_ENCDATA_BLOB)
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
		if (subFlag != TSS_TSPATTRIB_ENCDATABLOB_BLOB)
			return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

		result = obj_encdata_set_data(hObject, ulAttribDataSize, rgbAttribData);
#endif
	} else if (obj_is_policy(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_POLICY_POPUPSTRING:
				if ((string = Trspi_UNICODE_To_Native(rgbAttribData,
								      NULL)) == NULL)
					return TSPERR(TSS_E_INTERNAL_ERROR);

				result = obj_policy_set_string(hObject,
							       ulAttribDataSize,
							       string);
				break;
			case TSS_TSPATTRIB_POLICY_CALLBACK_HMAC:
			case TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC:
			case TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP:
			case TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM:
				result = obj_policy_set_cb12(hObject, attribFlag,
							     rgbAttribData);
				break;
			default:
				return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
				break;
		}
	} else if (obj_is_hash(hObject)) {
#ifdef TSS_BUILD_HASH_LIST
		if (attribFlag != TSS_TSPATTRIB_HASH_IDENTIFIER)
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);

		if (subFlag != 0)
			return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

		result = obj_hash_set_value(hObject, ulAttribDataSize, rgbAttribData);
#endif
	} else if (obj_is_tpm(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY:
			case TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY:
				result = obj_tpm_set_cb12(hObject, attribFlag,
							  rgbAttribData);
				break;
			default:
				return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
				break;
		}
	} else {
		if (obj_is_pcrs(hObject) || obj_is_context(hObject))
			result = TSPERR(TSS_E_BAD_PARAMETER);
#ifdef TSS_BUILD_NV
		else if (obj_is_nvstore(hObject))
			result = TSPERR(TSS_E_BAD_PARAMETER);
#endif
		else
			result = TSPERR(TSS_E_INVALID_HANDLE);
	}

	return result;
}

TSS_RESULT
Tspi_GetAttribData(TSS_HOBJECT hObject,		/* in */
		   TSS_FLAG attribFlag,		/* in */
		   TSS_FLAG subFlag,		/* in */
		   UINT32 * pulAttribDataSize,	/* out */
		   BYTE ** prgbAttribData)	/* out */
{
	TSS_RESULT result;

	if (pulAttribDataSize == NULL || prgbAttribData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (obj_is_rsakey(hObject)) {
#ifdef TSS_BUILD_RSAKEY_LIST
		if (attribFlag == TSS_TSPATTRIB_KEY_BLOB) {
			if (subFlag == TSS_TSPATTRIB_KEYBLOB_BLOB) {
				/* A TCPA_KEY structure, in blob form */
				result = obj_rsakey_get_blob(hObject, pulAttribDataSize,
							     prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY) {
				/* A blob, either encrypted or unencrypted */
				result = obj_rsakey_get_priv_blob(hObject, pulAttribDataSize,
								  prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY) {
				/* A TCPA_PUBKEY structure, in blob form */
				result = obj_rsakey_get_pub_blob(hObject, pulAttribDataSize,
								 prgbAttribData);
			} else {
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else if (attribFlag == TSS_TSPATTRIB_KEY_INFO) {
			if (subFlag != TSS_TSPATTRIB_KEYINFO_VERSION)
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

			result = obj_rsakey_get_version(hObject, pulAttribDataSize,
							prgbAttribData);
		} else if (attribFlag == TSS_TSPATTRIB_RSAKEY_INFO) {
			if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT) {
				result = obj_rsakey_get_exponent(hObject, pulAttribDataSize,
								 prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_MODULUS) {
				result = obj_rsakey_get_modulus(hObject, pulAttribDataSize,
								prgbAttribData);
			} else
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
		} else if (attribFlag == TSS_TSPATTRIB_KEY_UUID) {
			if (subFlag)
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

			result = obj_rsakey_get_uuid(hObject,
					pulAttribDataSize,
					prgbAttribData);
		} else if (attribFlag == TSS_TSPATTRIB_KEY_PCR) {
			if (subFlag == TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION) {
				result = obj_rsakey_get_pcr_atcreation(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE) {
				result = obj_rsakey_get_pcr_atrelease(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYPCR_SELECTION) {
				result = obj_rsakey_get_pcr_selection(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
		} else
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
#endif
#ifdef TSS_BUILD_NV
		} else if (obj_is_nvstore(hObject)) {
			if (attribFlag == TSS_TSPATTRIB_NV_PCR){
				switch (subFlag) {
					case TSS_TSPATTRIB_NVPCR_READDIGESTATRELEASE:
						if ((result =
						     obj_nvstore_get_readdigestatrelease(hObject,
								pulAttribDataSize, prgbAttribData)))
							return result;
						break;
					case TSS_TSPATTRIB_NVPCR_READPCRSELECTION:
						if ((result =
						     obj_nvstore_get_readpcrselection(hObject,
								pulAttribDataSize, prgbAttribData)))
							return result;
						break;
					case TSS_TSPATTRIB_NVPCR_WRITEDIGESTATRELEASE:
						if ((result =
						     obj_nvstore_get_writedigestatrelease(hObject,
								pulAttribDataSize, prgbAttribData)))
							return result;
						break;
					case TSS_TSPATTRIB_NVPCR_WRITEPCRSELECTION:
						if ((result =
						     obj_nvstore_get_writepcrselection(hObject,
								pulAttribDataSize, prgbAttribData)))
							return result;
						break;
					default:
						return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
					}
			} else
				return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
#endif
	} else if (obj_is_encdata(hObject)) {
#ifdef TSS_BUILD_ENCDATA_LIST
		if (attribFlag == TSS_TSPATTRIB_ENCDATA_BLOB) {
			if (subFlag != TSS_TSPATTRIB_ENCDATABLOB_BLOB)
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

			result = obj_encdata_get_data(hObject,
					pulAttribDataSize,
					prgbAttribData);
		} else if (attribFlag == TSS_TSPATTRIB_ENCDATA_PCR) {
			if (subFlag == TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION) {
				result = obj_encdata_get_pcr_atcreation(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_ENCDATAPCR_DIGEST_RELEASE) {
				result = obj_encdata_get_pcr_atrelease(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_ENCDATAPCR_SELECTION) {
				result = obj_encdata_get_pcr_selection(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else {
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else {
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
		}
#endif
	} else if (obj_is_context(hObject)) {
		if (attribFlag != TSS_TSPATTRIB_CONTEXT_MACHINE_NAME)
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);

		if ((result = obj_context_get_machine_name_attrib(hObject,
								  pulAttribDataSize,
								  prgbAttribData)))
			return result;
	} else if (obj_is_policy(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_POLICY_CALLBACK_HMAC:
			case TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC:
			case TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP:
			case TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM:
				result = obj_policy_get_cb12(hObject, attribFlag,
							     pulAttribDataSize, prgbAttribData);
				break;
			case TSS_TSPATTRIB_POLICY_POPUPSTRING:
				if ((result = obj_policy_get_string(hObject, pulAttribDataSize,
								    prgbAttribData)))
					return result;
				break;
			default:
				result = TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
				break;
		}
	} else if (obj_is_tpm(hObject)) {
		switch (attribFlag) {
			case TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY:
			case TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY:
				result = obj_tpm_get_cb12(hObject, attribFlag,
							  pulAttribDataSize, prgbAttribData);
				break;
			default:
				return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
				break;
		}
	} else {
		if (obj_is_hash(hObject) || obj_is_pcrs(hObject))
			result = TSPERR(TSS_E_BAD_PARAMETER);
		else
			result = TSPERR(TSS_E_INVALID_HANDLE);
	}

	return result;
}

