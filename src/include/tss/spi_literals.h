
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _SPI_LITERALS_H_
#define _SPI_LITERALS_H_

#ifndef _TCPA_LITERALS_H_
#error tcpa_literals.h should be inluded before this file
#endif

#define TSS_TSPATTRIB_POLICY_POPUPSTRING	(0x000000281)

#define FIXED_SRK_KEY_HANDLE		0x40000000

#define	TSS_OBJECT_TYPE_POLICY		(0x01)	/* Policy object */
#define	TSS_OBJECT_TYPE_RSAKEY		(0x02)	/* RSA-Key object */
#define	TSS_OBJECT_TYPE_ENCDATA		(0x03)	/* Encrypted data object */
#define	TSS_OBJECT_TYPE_PCRS		(0x04)	/* PCR composite object */
#define	TSS_OBJECT_TYPE_HASH		(0x05)	/* Hash object */

/*---	May not call via createObject, IBM internal flags */
#define TSS_OBJECT_TYPE_TPM		(0x80000006)
#define TSS_OBJECT_TYPE_CONTEXT		(0x80000007)

/* Flags passable to Tspi_Context_CreateObect */
#define	TSS_KEY_DEFAULT			(0x00000001)

#define	TSS_KEY_NO_AUTHORIZATION	(0x00000002)	/* no authorization for this key */
#define	TSS_KEY_AUTHORIZATION		(0x00000004)	/* key needs authorization */

#define	TSS_KEY_NOT_MIGRATABLE		(0x00000008)	/* key is not migratable */
#define	TSS_KEY_MIGRATABLE		(0x00000010)	/* key is migratable */

#define	TSS_KEY_TYPE_SIGNING		(0x00000020)	/* indicate a signing key */
#define	TSS_KEY_TYPE_STORAGE		(0x00000040)	/* used as storage key */
#define	TSS_KEY_TYPE_IDENTITY		(0x00000080)	/* indicate an idendity key */
#define	TSS_KEY_TYPE_AUTHCHANGE		(0x00000100)	/* indicate an ephemeral key */
#define	TSS_KEY_TYPE_BIND		(0x00000200)	/* indicate a key for TPM_Bind */
#define	TSS_KEY_TYPE_LEGACY		(0x00000400)	/* indicate a key that can perfom signing and binding */

#define	TSS_KEY_SIZE_512		(0x00000800)	/* indicate a key with 512 bits */
#define	TSS_KEY_SIZE_1024		(0x00001000)	/* indicate a key with 1024 bits */
#define	TSS_KEY_SIZE_2048		(0x00002000)	/* indicate a key with 2048 bits */
#define	TSS_KEY_SIZE_4096		(0x00004000)	/* indicate a key with 4096 bits */
#define	TSS_KEY_SIZE_8192		(0x00008000)	/* indicate a key with 8192 bits */
#define	TSS_KEY_SIZE_16384		(0x00010000)	/* indicate a key with 16384 bits */

#define	TSS_KEY_EMPTY_KEY		(0x00020000)	/* no TCPA key template (empty TSP key object) */
#define	TSS_KEY_TSP_SRK			(0x00040000)	/* use a TCPA SRK template (TSP key object for SRK) */
/* XXX Where did this symbol come from? */
#define TSS_KEY_SRK_HANDLE		TSS_KEY_TSP_SRK

#define TSS_KEY_VOLATILE		(0x00080000)
#define TSS_KEY_NON_VOLATILE		(0x00100000)

#define	TSS_ENCDATA_SEAL		(0x00200000)	/* data for seal operation */
#define	TSS_ENCDATA_BIND		(0x00400000)	/* data for bind operation */
#define	TSS_ENCDATA_LEGACY		(0x00800000)	/* data for legacy bind operation */

#define	TSS_POLICY_USAGE		(0x01000000)	/* usage policy object */
#define	TSS_POLICY_MIGRATION		(0x02000000)	/* migration policy object */

#define	TSS_HASH_DEFAULT		(0x04000000)	/* Default hash algorithm */
#define	TSS_HASH_SHA1			(0x08000000)	/* Sha1 with 20 bytes */
#define	TSS_HASH_OTHER			(0x10000000)	/* Not specified hash algorithm */

/* attribute definitions for a context object */
#define TSS_TSPATTRIB_CONTEXT_SILENT_MODE		(0x00000001)	/* TSP dialog display control */
#define TSS_TSPATTRIB_CONTEXT_MACHINE_NAME		(0x00000002)

/* attribute definitions for a TPM object */
#define TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY	(0x00000001)
#define TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY	(0x00000002)

/* attribute definitions for a policy object */
#define TSS_TSPATTRIB_POLICY_CALLBACK_HMAC		(0x00000080)	/* enable/disable callback function  */
#define TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC		(0x00000100)	/* enable/disable callback function */
#define TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP	(0x00000180)	/* enable/disable callback function */
#define TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM	(0x00000200)	/* enable/disable callback function */
#define TSS_TSPATTRIB_POLICY_SECRET_LIFETIME		(0x00000280)	/* set lifetime mode for policy secret */

/* attribute definitions for a key object */
#define TSS_TSPATTRIB_KEY_BLOB		(0x00000040)	/* key info as blob data */
#define TSS_TSPATTRIB_KEY_INFO		(0x00000080)	/* key param info as blob data */
#define TSS_TSPATTRIB_KEY_UUID		(0x000000C0)	/* key GUID info as blob data */
#define TSS_TSPATTRIB_KEY_PCR		(0x00000100)	/* composite digest value for the key */
#define TSS_TSPATTRIB_RSAKEY_INFO	(0x00000140)	/* public exponent of the key */
#define TSS_TSPATTRIB_KEY_REGISTER	(0x00000180)	/* register location for the key data */

/* attribute definitions for a data object */
#define TSS_TSPATTRIB_ENCDATA_BLOB	(0x00000008)	/* data blob for seal or bind */
#define TSS_TSPATTRIB_ENCDATA_PCR	(0x00000010)

/* policy definitions for secret mode */
#define TSS_SECRET_MODE_NONE		(0x00000800)	/* No authorization will be processed */
#define TSS_SECRET_MODE_SHA1		(0x00001000)	/* Secret string will not be touched by the TSP */
#define TSS_SECRET_MODE_PLAIN		(0x00001800)	/* Secret string will be hashed using SHA1 */
#define TSS_SECRET_MODE_POPUP		(0x00002000)	/* TSP will ask for a secret */
#define TSS_SECRET_MODE_CALLBACK	(0x00002800)	/* Application has to provide a call back function */

/* policy definitions for secret lifetime */
#define TSS_SECRET_LIFETIME_ALWAYS	(0x00000001)	/* secret will not be invalidated */
#define TSS_SECRET_LIFETIME_COUNTER	(0x00000002)	/* secret lifetime controled be counter */
#define TSS_SECRET_LIFETIME_TIMER	(0x00000003)	/* secret lifetime controled be time */

/* sub-attribute flags for a policy object */
#define	TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS	(TSS_SECRET_LIFETIME_ALWAYS)
#define	TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER	(TSS_SECRET_LIFETIME_COUNTER)
#define	TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER	(TSS_SECRET_LIFETIME_TIMER)
/* these cover for a type-o in the TSS 1.1 spec */
#define	TSS_TSPATTRIB_POLSECRET_LIFETIME_ALWAYS		(TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS)
#define	TSS_TSPATTRIB_POLSECRET_LIFETIME_COUNTER	(TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER)
#define	TSS_TSPATTRIB_POLSECRET_LIFETIME_TIMER		(TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER)

/* attribute values for a context object */
#define	TSS_TSPATTRIB_CONTEXT_NOT_SILENT	(0x00000000)	/* TSP dialogs enabled */
#define	TSS_TSPATTRIB_CONTEXT_SILENT		(0x00000001)	/* TSP dialogs disabled */

/* sub-attribute flags for a data object */
#define TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION	(0x80000000)
#define TSS_TSPATTRIB_ENCDATABLOB_BLOB			(0x00000001)	/* encrypted data blob */

#define TSS_TSPATTRIB_HASH_IDENTIFIER	(0x00001000)	/* Hash algorithm identifier */

/* attribute values for a key object */
#define TSS_TSPATTRIB_KEYBLOB_BLOB		(0x00000008)	/* key info using the key blob */
#define TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY	(0x00000010)	/* public key info using the blob */
#define TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY	(0x00000040)	/* private key info as blob */

#define TSS_TSPATTRIB_KEYINFO_SIZE		(0x00000080)	/* key size in bits */
#define TSS_TSPATTRIB_KEYINFO_USAGE		(0x00000100)	/* key usage info */
#define TSS_TSPATTRIB_KEYINFO_KEYFLAGS		(0x00000180)	/* key flags */
#define TSS_TSPATTRIB_KEYINFO_AUTHUSAGE		(0x00000200)	/* key auth usage info */
#define TSS_TSPATTRIB_KEYINFO_ALGORITHM		(0x00000280)	/* key algorithm ID */
#define TSS_TSPATTRIB_KEYINFO_SIGSCHEME		(0x00000300)	/* key sig scheme */
#define TSS_TSPATTRIB_KEYINFO_ENCSCHEME		(0x00000380)	/* key enc scheme        */
#define TSS_TSPATTRIB_KEYINFO_MIGRATABLE	(0x00000400)	/* if true then key is migratable */
#define TSS_TSPATTRIB_KEYINFO_REDIRECTED	(0x00000480)	/* key is redirected */
#define TSS_TSPATTRIB_KEYINFO_VOLATILE		(0x00000500)	/* if true key is volatile */
#define TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE	(0x00000580)	/* if true authorization is required */
#define TSS_TSPATTRIB_KEYINFO_VERSION		(0x00000600)	/* version info as TSS version struct */

#define TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT	(0x00001000)
#define TSS_TSPATTRIB_KEYINFO_RSA_MODULUS	(0x00002000)
#define TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE	(0x00003000)
#define TSS_TSPATTRIB_KEYINFO_RSA_PRIMES	(0x00004000)

#define TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION	(0x00008000)
#define TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE	(0x00010000)
#define TSS_TSPATTRIB_KEYPCR_SELECTION		(0x00018000)

#define TSS_TSPATTRIB_KEYREGISTER_USER		(0x02000000)
#define TSS_TSPATTRIB_KEYREGISTER_SYSTEM	(0x04000000)
#define TSS_TSPATTRIB_KEYREGISTER_NO		(0x06000000)

/* TPM status flags */
#define TSS_TPMSTATUS_DISABLEOWNERCLEAR		(0x00000001)	/* persistent flag */
#define TSS_TPMSTATUS_DISABLEFORCECLEAR		(0x00000002)	/* volatile flag */
#define TSS_TPMSTATUS_DISABLED			(0x00000003)	/* persistent flag */
#define TSS_TPMSTATUS_DEACTIVATED		(0x00000004)	/* persistent flag,  volatile flag */
#define TSS_TPMSTATUS_OWNERSETDISABLE		(0x00000005)	/* persistent flag for SetStatus (disable flag) */
#define TSS_TPMSTATUS_SETOWNERINSTALL		(0x00000006)	/* persistent flag (ownership flag) */
#define TSS_TPMSTATUS_DISABLEPUBEKREAD		(0x00000007)	/* persistent flag */
#define TSS_TPMSTATUS_ALLOWMAINTENANCE		(0x00000008)	/* persistent flag */
#define TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK	(0x00000009)	/* persistent flag */
#define TSS_TPMSTATUS_PHYSPRES_HWENABLE		(0x0000000A)	/* persistent flag */
#define TSS_TPMSTATUS_PHYSPRES_CMDENABLE	(0x0000000B)	/* persistent flag */
#define TSS_TPMSTATUS_PHYSPRES_LOCK		(0x0000000C)	/* volatile flag */
#define TSS_TPMSTATUS_PHYSPRESENCE		(0x0000000D)	/* volatile flag */
#define TSS_TPMSTATUS_PHYSICALDISABLE		(0x0000000E)	/* persistent flag (SetStatus-Fkt disable flag) */
#define TSS_TPMSTATUS_CEKP_USED			(0x0000000F)	/* persistent flag */
#define TSS_TPMSTATUS_PHYSICALSETDEACTIVATED	(0x00000010)	/* persistent flag (deactivated flag) */
#define TSS_TPMSTATUS_SETTEMPDEACTIVATED	(0x00000011)	/* volatile flag (deactivated flag) */
#define TSS_TPMSTATUS_POSTINITIALISE		(0x00000012)	/* volatile flag */
#define TSS_TPMSTATUS_TPMPOST			(0x00000013)	/* persistent flag */
#define TSS_TPMSTATUS_TPMPOSTLOCK		(0x00000014)	/* persistent flag */

/* algorithm ID definitions */
#define	TSS_ALG_RSA				(TCPA_ALG_RSA)
#define	TSS_ALG_DES				(TCPA_ALG_DES)
#define	TSS_ALG_3DES				(TCPA_ALG_3DES)
#define	TSS_ALG_SHA				(TCPA_ALG_SHA)
#define	TSS_ALG_HMAC				(TCPA_ALG_HMAC)
#define	TSS_ALG_AES				(TCPA_ALG_AES)

/* TPM capability flag definitions */
#define TSS_TPMCAP_ORD				(0x10)
#define TSS_TPMCAP_ALG				(0x11)
#define TSS_TPMCAP_FLAG				(0x12)
#define TSS_TPMCAP_PROPERTY			(0x13)
#define TSS_TPMCAP_VERSION			(0x14)

/* TCS capability flag definitions */
#define TSS_TCSCAP_ALG				(0x10000001)
#define TSS_TCSCAP_VERSION			(0x10000002)
#define TSS_TCSCAP_PERSSTORAGE			(0x10000004)
#define TSS_TCSCAP_CACHING			(0x10000008)
#define TSS_TCSCAP_MANUFACTURER			(0x10000010)

/* TCS sub-capability flag definitions */
#define TSS_TCSCAP_PROP_KEYCACHE		(0x10000020)
#define TSS_TCSCAP_PROP_AUTHCACHE		(0x10000040)
#define TSS_TCSCAP_PROP_MANUFACTURER_STR	(0x10000080)
#define TSS_TCSCAP_PROP_MANUFACTURER_ID		(0x10000100)

/* TSP capability flag definitions */
#define TSS_TSPCAP_ALG				(0x20000001)
#define TSS_TSPCAP_VERSION			(0x20000002)
#define TSS_TSPCAP_PERSSTORAGE			(0x20000004)
#define TSS_TSPCAP_COLLATE_ALG			(0x20000008)

/* TPM sub-capability flag definitions */
#define TSS_TPMCAP_PROP_PCR			(TCPA_CAP_PROP_PCR)
#define TSS_TPMCAP_PROP_DIR			(TCPA_CAP_PROP_DIR)
#define TSS_TPMCAP_PROP_MANUFACTURER		(TCPA_CAP_PROP_MANUFACTURER)
#define TSS_TPMCAP_PROP_SLOTS			(TCPA_CAP_PROP_SLOTS)

/* persistent storage type definitions */
#define TSS_PS_TYPE_NO			(0) /* IBM SPECIFIC */
#define TSS_PS_TYPE_USER		(1) /* Key is registered persistantly in the user storage database. */
#define TSS_PS_TYPE_SYSTEM		(2) /* Key is registered persistantly in the system storage database. */

/* migration scheme definitions */
#define TSS_MS_MIGRATE			(TCPA_MS_MIGRATE)
#define TSS_MS_REWRAP			(TCPA_MS_REWRAP)
#define TSS_MS_MAINT			(TCPA_MS_MAINT)

/* key usage definitions */
#define TSS_KEYUSAGE_BIND		(TPM_KEY_BIND)
#define TSS_KEYUSAGE_IDENTITY		(TPM_KEY_IDENTITY)
#define TSS_KEYUSAGE_LEGACY		(TPM_KEY_LEGACY)
#define TSS_KEYUSAGE_SIGN		(TPM_KEY_SIGNING)
#define TSS_KEYUSAGE_STORAGE		(TPM_KEY_STORAGE)
#define TSS_KEYUSAGE_AUTHCHANGE		(TPM_KEY_AUTHCHANGE)

/* key type flags (as returned by GetAttribUint32) */
#define TSS_KEYFLAG_REDIRECTION		(0x00000001)
#define TSS_KEYFLAG_MIGRATABLE		(0x00000002)
#define TSS_KEYFLAG_VOLATILEKEY		(0x00000004)

/* key authorization flags (as returned by GetAttribUint32) */
#define TSS_KEYAUTH_AUTH_NEVER		(0x00000001)
#define TSS_KEYAUTH_AUTH_ALWAYS		(0x00000002)

/* key encryption scheme definitions */
#define TSS_ES_NONE			(TCPA_ES_NONE)
#define TSS_ES_RSAESPKCSV15		(TCPA_ES_RSAESPKCSv15)
#define TSS_ES_RSAESOAEP_SHA1_MGF1	(TCPA_ES_RSAESOAEP_SHA1_MGF1)

/* key signature scheme definitions */
#define TSS_SS_NONE			(TCPA_SS_NONE)
#define TSS_SS_RSASSAPKCS1V15_SHA1	(TCPA_SS_RSASSAPKCS1v15_SHA1)
#define TSS_SS_RSASSAPKCS1V15_DER	(TCPA_SS_RSASSAPKCS1v15_DER)

/* event type definitions */
#define TSS_EV_CODE_CERT		(1)
#define TSS_EV_CODE_NOCERT		(2)
#define TSS_EV_XML_CONFIG		(3)
#define TSS_EV_NO_ACTION		(4)
#define TSS_EV_SEPARATOR		(5)
#define TSS_EV_ACTION			(6)
#define TSS_EV_PLATFORM_SPECIFIC	(7)

/* well known secret, a hash of all 0's */
#define TSS_WELL_KNOWN_SECRET	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"

/* IBM SPECIFIC */
#define TPM_NONCE_SIZE		20
#define TPM_DIGEST_SIZE		20
#define TPM_AUTHDATA_SIZE	20
#define TPM_ENCAUTH_SIZE	20
#define TPM_DIRVALUE_SIZE	20

#endif
