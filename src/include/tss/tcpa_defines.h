/*++

  TMP defines basically extracted from TCPA Main Specification V1.1

  --*/

#ifndef __TCPA_DEFINES_H__
#define __TCPA_DEFINES_H__


//////////////////////////////////////////////////////////////////////
// Parameter List Tag Identifiers
// A command with no authentication
#define TPM_TAG_RQU_COMMAND        (UINT16)(0x00C1)

// An authenticated command with one authentication handle
#define TPM_TAG_RQU_AUTH1_COMMAND  (UINT16)(0x00C2)

//An authenticated command with two authentication handles
#define TPM_TAG_RQU_AUTH2_COMMAND  (UINT16)(0x00C3)

// A response from a command with no authentication
#define TPM_TAG_RSP_COMMAND        (UINT16)(0x00C4)

// An authenticated response with one authentication handle
#define TPM_TAG_RSP_AUTH1_COMMAND  (UINT16)(0x00C5)

// An authenticated response with two authentication handles
#define TPM_TAG_RSP_AUTH2_COMMAND  (UINT16)(0x00C6)

//////////////////////////////////////////////////////////////////////
// vendor specific
//
#define TCPA_Vendor_Specific32  0x00000400
#define TCPA_Vendor_Specific8   0x80

//////////////////////////////////////////////////////////////////////
// section 4.10 - key usage values - TPM_KEY_USAGE
#define TPM_KEY_SIGNING    (UINT16)(0x0010)
#define TPM_KEY_STORAGE    (UINT16)(0x0011)
#define TPM_KEY_IDENTITY   (UINT16)(0x0012)
#define TPM_KEY_AUTHCHANGE (UINT16)(0x0013)
#define TPM_KEY_BIND       (UINT16)(0x0014)
#define TPM_KEY_LEGACY     (UINT16)(0x0015)

//////////////////////////////////////////////////////////////////////
// section 4.11 - auth data usage values - TPM_AUTH_DATA_USAGE
#define TPM_AUTH_NEVER   (BYTE)(0x00)
#define TPM_AUTH_ALWAYS  (BYTE)(0x01)

//////////////////////////////////////////////////////////////////////
// section 4.14 - payload type values - TPM_PAYLOAD_TYPE
#define TCPA_PT_ASYM      0x01
#define TCPA_PT_BIND      0x02
#define TCPA_PT_MIGRATE   0x03
#define TCPA_PT_MAINT     0x04
#define TCPA_PT_SEAL      0x05

//////////////////////////////////////////////////////////////////////
// section 4.15 - TPM_ENTITY_TYPE values
#define TCPA_ET_KEYHANDLE (UINT16)(0x0001)
#define TCPA_ET_OWNER     (UINT16)(0x0002)
#define TCPA_ET_DATA      (UINT16)(0x0003)
#define TCPA_ET_SRK       (UINT16)(0x0004)
#define TCPA_ET_KEY       (UINT16)(0x0005)

// The entity type TPM_ET_OWNER and TPM_ET_SRK are associated with
// specific key handles
// Errata: Not in spec
#define TPM_KEYHND_OWNER (0x40000001)
#define TPM_KEYHND_SRK   (0x40000000)

//////////////////////////////////////////////////////////////////////
// section 4.17 - TPM_PROTOCOL_ID values
#define TCPA_PID_OIAP  (UINT16)(0x0001)
#define TCPA_PID_OSAP  (UINT16)(0x0002)
#define TCPA_PID_ADIP  (UINT16)(0x0003)
#define TCPA_PID_ADCP  (UINT16)(0x0004)
#define TCPA_PID_OWNER (UINT16)(0x0005)

//////////////////////////////////////////////////////////////////////
// section 4.18 - algorithm identifiers
#define TCPA_ALG_RSA   (UINT32)(0x00000001)
#define TCPA_ALG_DES   (UINT32)(0x00000002)
#define TCPA_ALG_3DES  (UINT32)(0x00000003)
#define TCPA_ALG_SHA   (UINT32)(0x00000004)
#define TCPA_ALG_HMAC  (UINT32)(0x00000005)
#define TCPA_ALG_AES   (UINT32)(0x00000006)

//////////////////////////////////////////////////////////////////////
// section 4.19 - TPM_PHYSICAL_PRESENCE values
#define TCPA_PHYSICAL_PRESENCE_LIFETIME_LOCK  0x0080
#define TCPA_PHYSICAL_PRESENCE_HW_ENABLE      0x0040
#define TCPA_PHYSICAL_PRESENCE_CMD_ENABLE     0x0020
#define TCPA_PHYSICAL_PRESENCE_NOTPRESENT     0x0010
#define TCPA_PHYSICAL_PRESENCE_PRESENT        0x0008
#define TCPA_PHYSICAL_PRESENCE_LOCK           0x0004

//////////////////////////////////////////////////////////////////////
// section 4.31 - capability identifiers
#define TCPA_CAP_ORD           (UINT32)(0x00000001)
#define TCPA_CAP_ALG           (UINT32)(0x00000002)
#define TCPA_CAP_PID           (UINT32)(0x00000003)
#define TCPA_CAP_FLAG          (UINT32)(0x00000004)
#define TCPA_CAP_PROPERTY      (UINT32)(0x00000005)
#define TCPA_CAP_VERSION       (UINT32)(0x00000006)
#define TCPA_CAP_KEY_HANDLE    (UINT32)(0x00000007)
#define TCPA_CAP_CHECK_LOADED  (UINT32)(0x00000008)

//////////////////////////////////////////////////////////////////////
// section 8.11.1 - IDL Definitions of subCap
#define TPM_CAP_PROP_PCR           (UINT32)(0x00000101)
#define TPM_CAP_PROP_DIR           (UINT32)(0x00000102)
#define TPM_CAP_PROP_MANUFACTURER  (UINT32)(0x00000103)
#define TPM_CAP_PROP_SLOTS         (UINT32)(0x00000104)

//////////////////////////////////////////////////////////////////////
// section 4.33 - command ordinals
#define TCPA_PROTECTED_COMMAND    (UINT32)(0x00000000)
#define TCPA_UNPROTECTED_COMMAND  (UINT32)(0x80000000)
#define TCPA_CONNECTION_COMMAND   (UINT32)(0x40000000)
#define TCPA_VENDOR_COMMAND       (UINT32)(0x20000000)

#define TCPA_MAIN       (UINT16)(0x0000) // Command is from the main specification
#define TCPA_PC         (UINT16)(0x0001) // Command is specific to the PC
#define TCPA_PDA        (UINT16)(0x0002) // Command is specific to a PDA
#define TCPA_CELL_PHONE (UINT16)(0x0003) // Command is specific to a cell phone

#define TCPA_PROTECTED_ORDINAL    (TCPA_PROTECTED_COMMAND | TCPA_MAIN)
#define TCPA_UNPROTECTED_ORDINAL  (TCPA_UNPROTECTED_COMMAND | TCPA_MAIN)
#define TCPA_CONNECTION_ORDINAL   (TCPA_CONNECTION_COMMAND | TCPA_MAIN)

//////////////////////////////////////////////////////////////////////
// section 8.5 - TPM_SIG_SCHEME values
// For TCPA_ALG_RSA
#define TCPA_SS_NONE                 (UINT16)(0x0001)
#define TCPA_SS_RSASSAPKCS1v15_SHA1  (UINT16)(0x0002)
#define TCPA_SS_RSASSAPKCS1v15_DER   (UINT16)(0x0003)

//////////////////////////////////////////////////////////////////////
// section 8.4 - TPM_ENC_SCHEME values
#define TCPA_ES_NONE                 (UINT16)(0x0001)
#define TCPA_ES_RSAESPKCSv15         (UINT16)(0x0002)
#define TCPA_ES_RSAESOAEP_SHA1_MGF1  (UINT16)(0x0003)

//////////////////////////////////////////////////////////////////////
// section 4.22 - TPM_MIGRATE_SCHEME values
#define TCPA_MS_MIGRATE  (UINT16)(0x0001)
#define TCPA_MS_REWRAP   (UINT16)(0x0002)
#define TCPA_MS_MAINT    (UINT16)(0x0003)

// without any TPM_ like in Main Spec, strange
#define redirection    (UINT32)(0x00000001)
#define migratable     (UINT32)(0x00000002)
#define volatileKey    (UINT32)(0x00000004)

// empty defines Errata: What are these for?
#define AUTH  // paramDigest of HMAC1/HMAC2
#define HMAC1
#define HMAC2

// byte size definition for 160Bit SHA1 hash value
// Errata: Add these to Main Spec
#define TCPA_SHA1_160_HASH_LEN    0x14
#define TCPA_SHA1BASED_NONCE_LEN  TCPA_SHA1_160_HASH_LEN

#endif // __TCPA_DEFINES_H__

