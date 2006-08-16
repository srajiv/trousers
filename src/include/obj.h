
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */

#ifndef _OBJ_H_
#define _OBJ_H_

/* definitions */

/* When TRUE, the object has PCRs associated with it */
#define TSS_OBJ_FLAG_PCRS	0x00000001
/* When TRUE, the object has a usage auth secret associated with it */
#define TSS_OBJ_FLAG_USAGEAUTH	0x00000002
/* When TRUE, the object has a migration auth secret associated with it */
#define TSS_OBJ_FLAG_MIGAUTH	0x00000004
/* When TRUE, the object has previously been registered in USER PS */
#define TSS_OBJ_FLAG_USER_PS	0x00000008
/* When TRUE, the object has previously been registered in SYSTEM PS */
#define TSS_OBJ_FLAG_SYSTEM_PS	0x00000010

/* structures */

struct tsp_object {
	UINT32 handle;
	UINT32 tspContext;
	UINT32 tcsContext;
	TSS_FLAG flags;
	void *data;
	struct tsp_object *next;
};

struct obj_list {
	struct tsp_object *head;
	pthread_mutex_t lock;
};

struct tr_pcrs_obj {
	TCPA_PCR_SELECTION select;
	TCPA_PCRVALUE *pcrs;
	TCPA_PCRVALUE compositeHash;
};

struct tr_hash_obj {
	UINT32 type;
	BYTE *hashData;
	UINT32 hashSize;
	UINT32 hashUpdateSize;
	BYTE *hashUpdateBuffer;
};

struct tr_encdata_obj {
	TSS_HPOLICY usagePolicy;
	TSS_HPOLICY migPolicy;
	UINT32 encryptedDataLength;
	BYTE encryptedData[512];
	TCPA_PCR_INFO pcrInfo;
	UINT32 type;
};

struct tr_tpm_obj {
	TSS_HPOLICY policy;
#ifndef TSS_SPEC_COMPLIANCE
	TSS_ALGORITHM_ID collateAlg;
	TSS_ALGORITHM_ID activateAlg;
#endif
	PVOID collateAppData;
	PVOID activateAppData;
	TSS_RESULT (*Tspicb_CollateIdentity)(
			PVOID lpAppData,
			UINT32 ulTCPAPlainIdentityProofLength,
			BYTE *rgbTCPAPlainIdentityProof,
			TSS_ALGORITHM_ID algID,
			UINT32 ulSessionKeyLength,
			BYTE *rgbSessionKey,
			UINT32 *pulTCPAIdentityProofLength,
			BYTE *rgbTCPAIdentityProof);
	TSS_RESULT (*Tspicb_ActivateIdentity)(
			PVOID lpAppData,
			UINT32 ulSessionKeyLength,
			BYTE *rgbSessionKey,
			UINT32 ulSymCAAttestationBlobLength,
			BYTE *rgbSymCAAttestationBlob,
			UINT32 *pulCredentialLength,
			BYTE *rgbCredential);
};

struct tr_context_obj {
	TSS_FLAG silentMode;
#ifndef TSS_SPEC_COMPLIANCE
	UINT32 hashMode;
#endif
	TSS_HPOLICY policy;
	TCS_CONTEXT_HANDLE tcsHandle;
	BYTE *machineName;
	UINT32 machineNameLength;
};

struct tr_rsakey_obj {
	TCPA_KEY tcpaKey;
	TSS_HPOLICY usagePolicy;
	TSS_HPOLICY migPolicy;
	TSS_UUID uuid;
	TCS_KEY_HANDLE tcsHandle;
};

struct tr_policy_obj {
	BYTE SecretLifetime;    /* 0->Always, 1->Use Counter 2-> Use Timer */
	TSS_BOOL SecretSet;
	UINT32 SecretMode;
	UINT32 SecretCounter;
	UINT32 SecretTimer;     /* in seconds */
	UINT32 SecretSize;
	BYTE Secret[20];
	UINT32 type;
	BYTE *popupString;
	UINT32 popupStringLength;
#ifndef TSS_SPEC_COMPLIANCE
	UINT32 hashMode;
	TSS_ALGORITHM_ID hmacAlg;
	TSS_ALGORITHM_ID xorAlg;
	TSS_ALGORITHM_ID takeownerAlg;
	TSS_ALGORITHM_ID changeauthAlg;
#endif
	PVOID hmacAppData;
	PVOID xorAppData;
	PVOID takeownerAppData;
	PVOID changeauthAppData;
	TSS_RESULT (*Tspicb_CallbackHMACAuth)(
			PVOID lpAppData,
			TSS_HOBJECT hAuthorizedObject,
			TSS_BOOL ReturnOrVerify,
			UINT32 ulPendingFunction,
			TSS_BOOL ContinueUse,
			UINT32 ulSizeNonces,
			BYTE *rgbNonceEven,
			BYTE *rgbNonceOdd,
			BYTE *rgbNonceEvenOSAP,
			BYTE *rgbNonceOddOSAP,
			UINT32 ulSizeDigestHmac,
			BYTE *rgbParamDigest,
			BYTE *rgbHmacData);
	TSS_RESULT (*Tspicb_CallbackXorEnc)(
			PVOID lpAppData,
			TSS_HOBJECT hOSAPObject,
			TSS_HOBJECT hObject,
			TSS_FLAG PurposeSecret,
			UINT32 ulSizeNonces,
			BYTE *rgbNonceEven,
			BYTE *rgbNonceOdd,
			BYTE *rgbNonceEvenOSAP,
			BYTE *rgbNonceOddOSAP,
			UINT32 ulSizeEncAuth,
			BYTE *rgbEncAuthUsage,
			BYTE *rgbEncAuthMigration);
	TSS_RESULT (*Tspicb_CallbackTakeOwnership)(
			PVOID lpAppData,
			TSS_HOBJECT hObject,
			TSS_HKEY hObjectPubKey,
			UINT32 ulSizeEncAuth,
			BYTE *rgbEncAuth);
	TSS_RESULT (*Tspicb_CallbackChangeAuthAsym)(
			PVOID lpAppData,
			TSS_HOBJECT hObject,
			TSS_HKEY hObjectPubKey,
			UINT32 ulSizeEncAuth,
			UINT32 ulSizeAithLink,
			BYTE *rgbEncAuth,
			BYTE *rgbAuthLink);
};

extern struct obj_list tpm_list;
extern struct obj_list context_list;
extern struct obj_list hash_list;
extern struct obj_list pcrs_list;
extern struct obj_list policy_list;
extern struct obj_list rsakey_list;
extern struct obj_list encdata_list;

/* prototypes */
TSS_RESULT	   obj_getTpmObject(UINT32, TSS_HOBJECT *);
TSS_HOBJECT	   obj_GetPolicyOfObject(UINT32, UINT32);
void		   obj_close_context(TSS_HCONTEXT);

void		   obj_list_init();
TSS_HOBJECT	   obj_get_next_handle();
void		   obj_close_context(TSS_HCONTEXT);
TSS_RESULT	   obj_getTpmObject(TSS_HCONTEXT, TSS_HOBJECT *);
TSS_RESULT	   obj_list_add(struct obj_list *, UINT32, TSS_FLAG, void *, TSS_HOBJECT *);
TSS_RESULT	   obj_list_remove(struct obj_list *, TSS_HOBJECT, TSS_HCONTEXT);
void		   obj_list_put(struct obj_list *);
struct tsp_object *obj_list_get_obj(struct obj_list *, UINT32);

TSS_HCONTEXT       obj_lookupTspContext(TCS_CONTEXT_HANDLE);
struct tsp_object *obj_list_get_tspcontext(struct obj_list *, UINT32);
void		   obj_connectContext(TSS_HCONTEXT, TCS_CONTEXT_HANDLE);

/* obj_pcrs.c */
TSS_BOOL   obj_is_pcrs(TSS_HOBJECT);
TSS_RESULT obj_pcrs_get_tsp_context(TSS_HPCRS, TSS_HCONTEXT *);
TSS_RESULT obj_pcrs_add(TSS_HCONTEXT, TSS_HOBJECT *);
TSS_RESULT obj_pcrs_remove(TSS_HOBJECT, TSS_HCONTEXT);
TSS_RESULT obj_pcrs_select_index(TSS_HPCRS, UINT32);
TSS_RESULT obj_pcrs_get_value(TSS_HPCRS, UINT32, UINT32 *, BYTE **);
TSS_RESULT obj_pcrs_set_value(TSS_HPCRS, UINT32, UINT32, BYTE *);
TSS_RESULT obj_pcrs_set_values(TSS_HPCRS hPcrs, TCPA_PCR_COMPOSITE *);
TSS_RESULT obj_pcrs_get_selection(TSS_HPCRS, TCPA_PCR_SELECTION *);
TSS_RESULT obj_pcrs_get_composite(TSS_HPCRS, TCPA_PCRVALUE *);

/* obj_hash.c */
void       obj_list_hash_close(struct obj_list *, TSS_HCONTEXT);
TSS_RESULT obj_hash_add(TSS_HCONTEXT, UINT32, TSS_HOBJECT *);
TSS_BOOL   obj_is_hash(TSS_HOBJECT);
TSS_RESULT obj_hash_remove(TSS_HOBJECT, TSS_HCONTEXT);
TSS_RESULT obj_hash_get_tsp_context(TSS_HHASH, TSS_HCONTEXT *);
TSS_RESULT obj_hash_set_value(TSS_HHASH, UINT32, BYTE *);
TSS_RESULT obj_hash_get_value(TSS_HHASH, UINT32 *, BYTE **);
TSS_RESULT obj_hash_update_value(TSS_HHASH, UINT32, BYTE *);

/* obj_rsakey.c */
void       obj_list_rsakey_close(struct obj_list *, TSS_HCONTEXT);
TSS_BOOL   obj_is_rsakey(TSS_HOBJECT);
TSS_RESULT obj_rsakey_add(TSS_HCONTEXT, TSS_FLAG, TSS_HOBJECT *);
TSS_RESULT obj_rsakey_add_by_key(TSS_HCONTEXT, TSS_UUID *, BYTE *, TSS_FLAG, TSS_HKEY *);
TSS_RESULT obj_rsakey_set_policy(TSS_HKEY, UINT32, TSS_HPOLICY);
TSS_RESULT obj_rsakey_remove(TSS_HOBJECT, TSS_HCONTEXT);
TSS_RESULT obj_rsakey_get_tsp_context(TSS_HKEY, TSS_HCONTEXT *);
TSS_RESULT obj_rsakey_set_pstype(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_get_pstype(TSS_HKEY, UINT32 *);
TSS_RESULT obj_rsakey_get_usage(TSS_HKEY, UINT32 *);
TSS_RESULT obj_rsakey_set_usage(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_set_migratable(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_set_redirected(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_set_volatile(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_get_authdata_usage(TSS_HKEY, UINT32 *);
TSS_RESULT obj_rsakey_set_authdata_usage(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_get_alg(TSS_HKEY, UINT32 *);
TSS_RESULT obj_rsakey_set_alg(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_get_es(TSS_HKEY, UINT32 *);
TSS_RESULT obj_rsakey_set_es(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_get_ss(TSS_HKEY, UINT32 *);
TSS_RESULT obj_rsakey_set_ss(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_set_num_primes(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_get_num_primes(TSS_HKEY, UINT32 *);
TSS_RESULT obj_rsakey_set_flags(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_get_flags(TSS_HKEY, UINT32 *);
TSS_RESULT obj_rsakey_set_size(TSS_HKEY, UINT32);
TSS_RESULT obj_rsakey_get_size(TSS_HKEY, UINT32 *);
TSS_BOOL   obj_rsakey_is_migratable(TSS_HKEY);
TSS_BOOL   obj_rsakey_is_redirected(TSS_HKEY);
TSS_BOOL   obj_rsakey_is_volatile(TSS_HKEY);
TSS_RESULT obj_rsakey_get_policy(TSS_HKEY, TSS_FLAG, TSS_HPOLICY *, TSS_BOOL *);
TSS_RESULT obj_rsakey_get_blob(TSS_HKEY, UINT32 *, BYTE **);
TSS_RESULT obj_rsakey_get_priv_blob(TSS_HKEY, UINT32 *, BYTE **);
TSS_RESULT obj_rsakey_get_pub_blob(TSS_HKEY, UINT32 *, BYTE **);
TSS_RESULT obj_rsakey_get_version(TSS_HKEY, UINT32 *, BYTE **);
TSS_RESULT obj_rsakey_get_exponent(TSS_HKEY, UINT32 *, BYTE **);
TSS_RESULT obj_rsakey_get_modulus(TSS_HKEY, UINT32 *, BYTE **);
TSS_RESULT obj_rsakey_get_uuid(TSS_HKEY, UINT32 *, BYTE **);
TSS_RESULT obj_rsakey_get_parent_uuid(TSS_HKEY, TSS_FLAG *, TSS_UUID *);
TSS_RESULT obj_rsakey_set_uuids(TSS_HKEY, TSS_FLAG, TSS_UUID *, TSS_FLAG, TSS_UUID *);
TSS_RESULT obj_rsakey_set_uuid(TSS_HKEY, TSS_FLAG, TSS_UUID *);
TSS_RESULT obj_rsakey_set_tcpakey(TSS_HKEY, UINT32 , BYTE *);
TSS_RESULT obj_rsakey_get_pcr_atcreation(TSS_HKEY, UINT32 *, BYTE **);
TSS_RESULT obj_rsakey_get_pcr_atrelease(TSS_HKEY, UINT32 *, BYTE **);
TSS_RESULT obj_rsakey_get_pcr_selection(TSS_HKEY, UINT32 *, BYTE **);
TSS_RESULT obj_rsakey_set_pubkey(TSS_HKEY, BYTE *);
TSS_RESULT obj_rsakey_set_privkey(TSS_HKEY, UINT32 , BYTE *);
TSS_RESULT obj_rsakey_set_pcr_data(TSS_HKEY, TSS_HPOLICY);
TSS_RESULT obj_rsakey_set_key_parms(TSS_HKEY, TCPA_KEY_PARMS *);
TSS_RESULT obj_rsakey_is_connected(TSS_HKEY, TCS_CONTEXT_HANDLE *);
TSS_RESULT obj_rsakey_get_by_uuid(TSS_UUID *, TSS_HKEY *);
TSS_RESULT obj_rsakey_get_by_pub(UINT32, BYTE *, TSS_HKEY *);
TSS_RESULT obj_rsakey_get_tcs_handle(TSS_HKEY, TCS_KEY_HANDLE *);
TSS_RESULT obj_rsakey_set_tcs_handle(TSS_HKEY, TCS_KEY_HANDLE);

/* obj_tpm.c */
TSS_BOOL   obj_is_tpm(TSS_HOBJECT);
TSS_RESULT obj_tpm_get_tsp_context(TSS_HTPM, TSS_HCONTEXT *);
TSS_RESULT obj_tpm_get(TSS_HCONTEXT, TSS_HTPM *);
TSS_RESULT obj_tpm_get_tcs_context(TSS_HTPM, TCS_CONTEXT_HANDLE *);
TSS_RESULT obj_tpm_set_policy(TSS_HTPM, TSS_HPOLICY);
TSS_RESULT obj_tpm_add(TSS_HCONTEXT, TSS_HOBJECT *);
TSS_RESULT obj_tpm_get_policy(TSS_HTPM, TSS_HPOLICY *);
TSS_RESULT obj_tpm_is_connected(TSS_HTPM, TCS_CONTEXT_HANDLE *);
TSS_RESULT obj_tpm_set_cb12(TSS_HTPM, TSS_FLAG, BYTE *);
TSS_RESULT obj_tpm_get_cb12(TSS_HTPM, TSS_FLAG, UINT32 *, BYTE **);
TSS_RESULT obj_tpm_set_cb11(TSS_HTPM, TSS_FLAG, TSS_FLAG, UINT32);
TSS_RESULT obj_tpm_get_cb11(TSS_HTPM, TSS_FLAG, UINT32 *);

/* obj_encdata.c */
TSS_BOOL   obj_is_encdata(TSS_HOBJECT);
TSS_RESULT obj_encdata_set_policy(TSS_HKEY, UINT32, TSS_HPOLICY);
TSS_RESULT obj_encdata_set_data(TSS_HENCDATA, UINT32, BYTE *);
TSS_RESULT obj_encdata_remove(TSS_HOBJECT, TSS_HCONTEXT);
TSS_RESULT obj_encdata_get_tsp_context(TSS_HENCDATA, TSS_HCONTEXT *);
TSS_RESULT obj_encdata_add(TSS_HCONTEXT, UINT32, TSS_HOBJECT *);
void       obj_list_encdata_close(struct obj_list *, TSS_HCONTEXT);
TSS_RESULT obj_encdata_get_data(TSS_HENCDATA, UINT32 *, BYTE **);
TSS_RESULT obj_encdata_get_pcr_atcreation(TSS_HENCDATA, UINT32 *, BYTE **);
TSS_RESULT obj_encdata_get_pcr_atrelease(TSS_HENCDATA, UINT32 *, BYTE **);
TSS_RESULT obj_encdata_get_pcr_selection(TSS_HENCDATA, UINT32 *, BYTE **);
TSS_RESULT obj_encdata_get_policy(TSS_HENCDATA, UINT32, TSS_HPOLICY *);
TSS_RESULT obj_encdata_set_pcr_info(TSS_HENCDATA, BYTE *);
TSS_RESULT obj_encdata_is_connected(TSS_HENCDATA, TCS_CONTEXT_HANDLE *);

/* obj_context.c */
TSS_BOOL   obj_is_context(TSS_HOBJECT);
TSS_RESULT obj_context_get_policy(TSS_HCONTEXT, TSS_HPOLICY *);
TSS_BOOL   obj_context_is_silent(TSS_HCONTEXT);
TSS_RESULT obj_context_is_connected(TSS_HCONTEXT, TCS_CONTEXT_HANDLE *);
TSS_RESULT obj_context_set_policy(TSS_HCONTEXT, TSS_HPOLICY);
TSS_RESULT obj_context_get_machine_name(TSS_HCONTEXT, UINT32 *, BYTE **);
TSS_RESULT obj_context_get_machine_name_attrib(TSS_HCONTEXT, UINT32 *, BYTE **);
TSS_RESULT obj_context_set_machine_name(TSS_HCONTEXT, BYTE *, UINT32);
TSS_RESULT obj_context_add(TSS_HOBJECT *);
TSS_RESULT obj_context_get_tcs_context(TSS_HCONTEXT, TCS_CONTEXT_HANDLE *);
TSS_RESULT obj_context_set_mode(TSS_HCONTEXT, UINT32);
TSS_RESULT obj_context_get_mode(TSS_HCONTEXT, UINT32 *);
TSS_BOOL   obj_context_has_popups(TSS_HCONTEXT);
TSS_RESULT obj_context_get_hash_mode(TSS_HCONTEXT, UINT32 *);
TSS_RESULT obj_context_set_hash_mode(TSS_HCONTEXT, UINT32);

/* obj_policy.c */
TSS_BOOL   anyPopupPolicies(TSS_HCONTEXT);
TSS_BOOL   obj_is_policy(TSS_HOBJECT);
TSS_RESULT obj_policy_get_tsp_context(TSS_HPOLICY, TSS_HCONTEXT *);
TSS_RESULT obj_policy_get_secret(TSS_HPOLICY, TCPA_SECRET *);
TSS_RESULT obj_policy_flush_secret(TSS_HPOLICY);
TSS_RESULT obj_policy_set_secret_object(TSS_HPOLICY, TSS_FLAG, UINT32,
					TCPA_DIGEST *, TSS_BOOL);
TSS_RESULT obj_policy_copy_secret(TSS_HPOLICY, TSS_HPOLICY);
TSS_RESULT obj_policy_set_secret(TSS_HPOLICY, TSS_FLAG, UINT32, BYTE *);
TSS_RESULT obj_policy_get_type(TSS_HPOLICY, UINT32 *);
TSS_RESULT obj_policy_remove(TSS_HOBJECT, TSS_HCONTEXT);
TSS_RESULT obj_policy_add(TSS_HCONTEXT, UINT32, TSS_HOBJECT *);
TSS_RESULT obj_policy_get_secret(TSS_HPOLICY, TCPA_SECRET *);
TSS_RESULT obj_policy_set_type(TSS_HPOLICY, UINT32);
TSS_RESULT obj_policy_get_tcs_context(TSS_HPOLICY, TCS_CONTEXT_HANDLE *);
TSS_RESULT obj_policy_set_cb12(TSS_HPOLICY, TSS_FLAG, BYTE *);
TSS_RESULT obj_policy_get_cb12(TSS_HPOLICY, TSS_FLAG, UINT32 *, BYTE **);
TSS_RESULT obj_policy_set_cb11(TSS_HPOLICY, TSS_FLAG, TSS_FLAG, UINT32);
TSS_RESULT obj_policy_get_cb11(TSS_HPOLICY, TSS_FLAG, UINT32 *);
TSS_RESULT obj_policy_get_lifetime(TSS_HPOLICY, UINT32 *);
TSS_RESULT obj_policy_set_lifetime(TSS_HPOLICY);
TSS_RESULT obj_policy_get_counter(TSS_HPOLICY, UINT32 *);
TSS_RESULT obj_policy_set_counter(TSS_HPOLICY, UINT32);
TSS_RESULT obj_policy_set_timer(TSS_HPOLICY, UINT32);
TSS_RESULT obj_policy_get_string(TSS_HPOLICY, UINT32 *size, BYTE **);
TSS_RESULT obj_policy_set_string(TSS_HPOLICY, UINT32 size, BYTE *);
TSS_RESULT obj_policy_get_secs_until_expired(TSS_HPOLICY, UINT32 *);
TSS_RESULT obj_policy_has_expired(TSS_HPOLICY, TSS_BOOL *);
TSS_RESULT obj_policy_get_mode(TSS_HPOLICY, UINT32 *);
TSS_RESULT obj_policy_dec_counter(TSS_HPOLICY);
TSS_RESULT obj_policy_do_hmac(TSS_HPOLICY, TSS_HOBJECT, TSS_BOOL, UINT32,
			      TSS_BOOL, UINT32, BYTE *, BYTE *, BYTE *, BYTE *,
			      UINT32, BYTE *, BYTE *);
TSS_RESULT obj_policy_do_xor(TSS_HPOLICY, TSS_HOBJECT, TSS_HOBJECT, TSS_FLAG,
		UINT32, BYTE *, BYTE *, BYTE *, BYTE *, UINT32, BYTE *, BYTE *);
TSS_RESULT obj_policy_do_takeowner(TSS_HPOLICY, TSS_HOBJECT, TSS_HKEY, UINT32, BYTE *);
TSS_RESULT obj_policy_validate_auth_oiap(TSS_HPOLICY, TCPA_DIGEST *, TPM_AUTH *);
TSS_RESULT obj_policy_get_hash_mode(TSS_HCONTEXT, UINT32 *);
TSS_RESULT obj_policy_set_hash_mode(TSS_HCONTEXT, UINT32);

#endif
