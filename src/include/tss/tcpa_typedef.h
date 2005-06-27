/*++
  TCPA typedefs basically extracted from TCPA Main Specification V1.1b
  and TCPA Software Stack (TSS) Specification.

  Before including this file it is necessary that the platform-specific
  typedef’s are defined. Be advised that these definitions can depend on
  both the platform and the compiler used. The defines used in this and
  some other TCPA include file are derived from 4 Basic-Types:
  --*/

#ifndef __TCPA_TYPEDEF_H__
#define __TCPA_TYPEDEF_H__

#define TRUE  0x01
#define FALSE 0x00

//--------------------------------------------------------------------
// 4.2.3   Helper redefinitions
typedef UINT32   TCPA_PCRINDEX;     // Index to a PCR register
typedef UINT32   TCPA_DIRINDEX;     // Index to a DIR register
typedef UINT32   TCPA_AUTHHANDLE;   // Handle to an authorization session
typedef UINT32   TSS_HASHHANDLE;    // Handle to a hash session
typedef UINT32   TSS_HMACHHANDLE;   // Handle to a HMAC session
typedef UINT32   TCPA_ENCHANDLE;    // Handle to a encryption/decryption session
typedef UINT32   TCPA_KEY_HANDLE;   // The area where a key is held assigned by the TPM.
typedef UINT32   TCPA_RESULT;       // The return code from a function


// 4.2.4   Enumerated Helper redefinitions

typedef UINT32   TCPA_COMMAND_CODE;       // The command ordinal. See 4.33
typedef UINT16   TCPA_PROTOCOL_ID;        // The protocol in use. See 4.17
typedef UINT32   TCPA_EVENTTYPE;          // Type of PCR event. See 4.25.2
typedef BYTE     TCPA_AUTH_DATA_USAGE;    // Indicates the conditions where it is required that authorization
//    be presented. See 4.11
typedef UINT16   TCPA_ENTITY_TYPE;        // Indicates the types of entity that are supported by the TPM. See 4.15
typedef UINT32   TCPA_ALGORITHM_ID;       // Indicates the type of algorithm. See 4.18
typedef UINT16   TCPA_KEY_USAGE;          // Indicates the permitted usage of the key. See 4.10
typedef UINT16   TCPA_STARTUP_TYPE;       // Indicates the start state. See 4.16
typedef UINT32   TCPA_CAPABILITY_AREA;    // Identifies a TPM capability area.  See 4.31
typedef UINT16   TCPA_ENC_SCHEME;         // The definition of the encryption scheme. See 8.4
typedef UINT16   TCPA_SIG_SCHEME;         // The definition of the signature scheme. See 8.5
typedef UINT16   TCPA_MIGRATE_SCHEME;     // The definition of the migration scheme 4.22
typedef UINT16   TCPA_PHYSICAL_PRESENCE;  // Sets the state of the physical presence mechanism. See section 4.19
typedef UINT32   TCPA_KEY_FLAGS;          // Indicates information regarding a key. See 4.12

typedef UINT16   TCPA_TAG;              // command tag identifier Errata: missing in Main spec
typedef BYTE     TCPA_PAYLOAD_TYPE;     // Errata: should be relocated to here in Main spec


#endif // __TCPA_TYPEDEF_H__

