/*++

  Global defines for TSS.

  --*/

#ifndef __TSS_DEFINES_H__
#define __TSS_DEFINES_H__

typedef UINT32  TSS_HMACHANDLE;        // handle to a HMAC session

//
// definition of the object types that can be created via CreateObject
//
#define   TSS_OBJECT_TYPE_POLICY      (0x01)      // Policy object
#define   TSS_OBJECT_TYPE_RSAKEY      (0x02)      // RSA-Key object
#define   TSS_OBJECT_TYPE_ENCDATA      (0x03)      // Encrypted data object
#define   TSS_OBJECT_TYPE_PCRS      (0x04)      // PCR composite object
#define   TSS_OBJECT_TYPE_HASH      (0x05)      // Hash object
//
//////////////////////////////////////////////////////////////////////////
// CreateObject: Flags
//////////////////////////////////////////////////////////////////////////
//
// for RSAKEY object:
//
// Authorization:
//
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
// Authorization:
//   Never                               |0 0|
//   Always                            |0 1|
//
#define   TSS_KEY_NO_AUTHORIZATION   (0x00000000)   // no authorization for this key
#define   TSS_KEY_AUTHORIZATION      (0x00000001)   // key needs authorization
//
// Volatility
//
//   Non Volatile                                            |0|
//   Volatile                                                |1|
//
#define    TSS_KEY_NON_VOLATILE           (0x00000000)    // Key is non-volatile
#define    TSS_KEY_VOLATILE               (0x00000004)    // Key is volatile
//
// Migration:
//
//   Non Migratable                                        |0|
//   Migratable                                            |1|
//
#define   TSS_KEY_NOT_MIGRATABLE      (0x00000000)   // key is not migratable
#define   TSS_KEY_MIGRATABLE      (0x00000008)   // key is migratable
//
// Usage:
//
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
// Usage:
//    Default (Legacy)                              |0 0 0 0|
//   Signing                                       |0 0 0 1|
//   Storage                                       |0 0 1 0|
//   Identity                                      |0 0 1 0|
//   AuthChange                                    |0 1 0 0|
//   Bind                                          |0 1 0 1|
//   Legacy                                        |0 1 1 0|
//
//
#define   TSS_KEY_TYPE_DEFAULT	(0x00000000)   // indicate a default key (Legacy-Key)
#define   TSS_KEY_TYPE_SIGNING      (0x00000010)   // indicate a signing key
#define   TSS_KEY_TYPE_STORAGE      (0x00000020)   // used as storage key
#define   TSS_KEY_TYPE_IDENTITY      (0x00000030)   // indicate an idendity key
#define   TSS_KEY_TYPE_AUTHCHANGE      (0x00000040)   // indicate an ephemeral key
#define   TSS_KEY_TYPE_BIND         (0x00000050)   // indicate a key for TPM_Bind
#define   TSS_KEY_TYPE_LEGACY      (0x00000060)   // indicate a key that can perfom signing
//                                                                         and binding
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
// Size:
//   512                                    |0 0 0 1|
//  1024                                    |0 0 1 0|
//  2048                                    |0 0 1 1|
//  4096                                    |0 1 0 0|
//  8192                                    |0 1 0 1|
// 16286                                    |0 1 1 0|
//
#define TSS_KEY_SIZE_512    ((UINT32)( 0x00000100 )) // indicate a key with 512 bit
#define TSS_KEY_SIZE_1024   ((UINT32)( 0x00000200 )) // indicate a key with 1024 bit
#define TSS_KEY_SIZE_2048   ((UINT32)( 0x00000300 )) // indicate a key with 2048 bit
#define TSS_KEY_SIZE_4096   ((UINT32)( 0x00000400 )) // indicate a key with 4096 bit
#define TSS_KEY_SIZE_8192   ((UINT32)( 0x00000500 )) // indicate a key with 8192 bit
#define TSS_KEY_SIZE_16384  ((UINT32)( 0x00000600 )) // indicate a key with 16286 bit
//
// fixed KeyTypes (templates)
//
//
//                      3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//                      1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ----------------------------------------------------------------------------------
//    Reserved:                    |0 0 0 0 0 0 0 0 0 0 0 0 0 0|
//   Empty Key        |0 0 0 0 0 0|
//   Storage root key |0 0 0 0 0 1|
//
#define   TSS_KEY_EMPTY_KEY         (0x00000000)   // no TCPA key template (empty TSP key
//                                                                         object)
#define   TSS_KEY_TSP_SRK         (0x04000000)   // use a TCPA SRK template (TSP key object
//                                                                         for SRK)
//
// Flags for ENCDATA:
//
// Type:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
// Type:
//   Seal                             |0 0 1|
//   Bind                             |0 1 0|
//   Legacy                          |0 1 1|
//
// ENCDATA Reserved:
//  |x x x x x x x x x x x x x x x x x x x x x x x x x x x x x|
//
#define   TSS_ENCDATA_SEAL         (0x00000001)   // data for seal operation
#define   TSS_ENCDATA_BIND         (0x00000002)   // data for bind operation
#define   TSS_ENCDATA_LEGACY      (0x00000003)   // data for legacy bind operation
//
//
// Flags for POLICY:
//
// Type:
//
//
// Flags for POLICY:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
// Type:
//   Usage                                                       |0 1|
//   Migration                                                   |1 0|
//
// POLICY Reserved:
//  |x x x x x x x x x x x x x x x x x x x x x x x x x x x x x x|

#define   TSS_POLICY_USAGE         (0x00000001)   // usage policy object
#define   TSS_POLICY_MIGRATION      (0x00000002)   // migration policy object
//
//
// Flags for HASH:
//
//
// Flags for HASH:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
// Algorithm:
//   DEFAULT
//  |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0|
//   SHA1
//  |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1|
//   OTHER
//  |1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1|
//
#define   TSS_HASH_DEFAULT         (0x00000000)   // Default hash algorithm
#define   TSS_HASH_SHA1         (0x00000001)   // Sha1 with 20 bytes
#define   TSS_HASH_OTHER         (0xFFFFFFFF)   // Not specified hash algorithm
//
//////////////////////////////////////////////////////////////////////////
// SetAttribField and GetAttribField: Flags
//////////////////////////////////////////////////////////////////////////
//
// Object Context:
//
//        3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//        1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//        ---------------------------------------------------------------
//   TSS_TSPATTRIB_CONTEXT_SILENT_MODE                             |0 0 1|
//   TSS_TSPATTRIB_CONTEXT_MACHINE_NAME                            |0 1 0|
//
#define TSS_TSPATTRIB_CONTEXT_SILENT_MODE      (0x00000001)   // TSP dialog display control
#define TSS_TSPATTRIB_CONTEXT_MACHINE_NAME   (0x00000002)
// TSS 1.2 backport
#define TSS_TSPATTRIB_SECRET_HASH_MODE           (0x00000006)
							// flag indicating whether
							// NUL is included in the
							// hash of the password
//
// Subflags of TSS_TSPATTRIB_SECRET_HASH_MODE
//
#define TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP     (0x00000001)
//

//
// Values for TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP subflag
//
#define TSS_TSPATTRIB_HASH_MODE_NOT_NULL         (0x00000000)
#define TSS_TSPATTRIB_HASH_MODE_NULL             (0x00000001)
// end TSS 1.2 backport

//
// Object Policy:
//
//                  3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//                  1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//                  ---------------------------------------------------------------
//   TSS_TSPATTRIB_POLICY_CALLBACK_HMAC                        |0 0 1|
//   TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC                     |0 1 0|
//   TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP               |0 1 1|
//   TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM              |1 0 0|
//   TSS_TSPATTRIB_POLICY_SECRET_LIFETIME                      |1 0 1|
//   TSS_TSPATTRIB_POLICY_POPUPSTRING                          |1 1 0|
//
#define TSS_TSPATTRIB_POLICY_CALLBACK_HMAC         (0x00000080)   // enable/disable callback
//                                                                                     function
#define TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC         (0x00000100)   // enable/disable callback
//                                                                                     function
#define TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP      (0x00000180)   // enable/disable callback
//                                                                                     function
#define TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM      (0x00000200)   // enable/disable callback
//                                                                                     function
#define TSS_TSPATTRIB_POLICY_SECRET_LIFETIME         (0x00000280)   // set lifetime mode for
//                                                                                     policy secret
#define TSS_TSPATTRIB_POLICY_POPUPSTRING            (0x00000300)   // set a NULL terminated
//                                                                                UNICODE string which is displayed
//                                                                                in the TSP policy popup dialog
//
//   Definition of policy mode flags that can be used with the method Tspi_Policy_SetSecret( )
//
//   TSS_SECRET_MODE_NONE                              |0 0 0 1|
//   TSS_SECRET_MODE_SHA1                              |0 0 1 0|
//   TSS_SECRET_MODE_PLAIN                             |0 0 1 1|
//   TSS_SECRET_MODE_POPUP                             |0 1 0 0|
//   TSS_SECRET_MODE_CALLBACK                          |0 1 0 1|
//
#define TSS_SECRET_MODE_NONE      (0x00000800)      // No authorization will be processed
#define TSS_SECRET_MODE_SHA1      (0x00001000)      // Secret string will not be touched by TSP
#define TSS_SECRET_MODE_PLAIN      (0x00001800)      // Secret string will be hashed using SHA1
#define TSS_SECRET_MODE_POPUP      (0x00002000)      // TSS SP will ask for a secret
#define TSS_SECRET_MODE_CALLBACK   (0x00002800)      // Application has to provide a call back
//                                                                         function
//
//////////////////////////////////////////////////////////////////////////
// SetAttribField and GetAttribField: SubFlags
//////////////////////////////////////////////////////////////////////////
//
// SubFlags for Flag TSS_TSPATTRIB_POLICY_SECRET_LIFETIME
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
// SubFlags for Flag TSS_TSPATTRIB_POLICY_SECRET_LIFETIME
//
//   TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS            |0 0 0 1|
//   TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER           |0 0 1 0|
//   TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER             |0 0 1 1|
//
#define   TSS_SECRET_LIFETIME_ALWAYS   (0x00000001)   // secret will not be invalidated
#define   TSS_SECRET_LIFETIME_COUNTER   (0x00000002)   // secret lifetime controled be counter
#define   TSS_SECRET_LIFETIME_TIMER   (0x00000003)   // secret lifetime controled be time

#define TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS	TSS_SECRET_LIFETIME_ALWAYS
#define TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER	TSS_SECRET_LIFETIME_COUNTER
#define TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER	TSS_SECRET_LIFETIME_TIMER
//
//////////////////////////////////////////////////////////////////////////
// SetAttribField and GetAttribField: Attrib
//////////////////////////////////////////////////////////////////////////
//
// for Flag TSS_TSPATTRIB_CONTEXT_SILENT_MODE
//
#define   TSS_TSPATTRIB_CONTEXT_NOT_SILENT   (0x00000000)   // TSP dialogs enabled
#define   TSS_TSPATTRIB_CONTEXT_SILENT      (0x00000001)   // TSP dialogs disabled
//
// Object EncData:
//
#define TSS_TSPATTRIB_ENCDATA_BLOB         (0x00000008)   // data blob for seal or bind
#define TSS_TSPATTRIB_ENCDATA_PCR              (0x00000010)
//
// Object Key:
//
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
// Object Key:
//   TSS_TSPATTRIB_KEY_BLOB                     |0 0 0 1|
//   TSS_TSPATTRIB_KEY_PARAM                    |0 0 1 0|
//   TSS_TSPATTRIB_KEY_GUID                     |0 0 1 1|
//   TSS_TSPATTRIB_KEY_PCR                      |0 1 0 0|
//   TSS_TSPATTRIB_RSAKEY_INFO                  |0 1 0 1|
//   TSS_TSPATTRIB_KEY_REGISTER                 |0 1 1 0|
//
#define TSS_TSPATTRIB_KEY_BLOB      (0x00000040)   // key info as blob data
#define TSS_TSPATTRIB_KEY_INFO      (0x00000080)   // key param info as blob data
#define TSS_TSPATTRIB_KEY_UUID      (0x000000C0)   // key GUID info as blob data
#define TSS_TSPATTRIB_KEY_PCR         (0x00000100)   // composite digest value for the key
#define TSS_TSPATTRIB_RSAKEY_INFO      (0x00000140)   // public exponent of the key
#define TSS_TSPATTRIB_KEY_REGISTER      (0x00000180)   // register location for the key data
//
// Object Hash:
//
#define TSS_TSPATTRIB_HASH_IDENTIFIER   (0x00001000)   // Hash algorithm identifier
//
// SubFlags for Flag TSS_TSPATTRIB_ENCDATA_BLOB
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
// SubFlags for Flag TSS_TSPATTRIB_ENCDATA_BLOB
//
//   TSS_TSPATTRIB_ENCDATABLOB_BLOB                           |0 0 1|
//   TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION               |0 1 0|
//
#define TSS_TSPATTRIB_ENCDATABLOB_BLOB         (0x00000001)   // encrypted data blob
#define TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION    (0x00000002)   // PCR digest at creation
#define TSS_TSPATTRIB_ENCDATAPCR_DIGEST_RELEASE      (0x00000003)
#define TSS_TSPATTRIB_ENCDATAPCR_SELECTION      (0x00000004)
//
// SubFlags for Flag TSS_TSPATTRIB_KEY_BLOB
//
//
//     TSS_TSPATTRIB_KEYBLOB_BLOB                     |0 0 0 1|
//    TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY               |0 0 1 0|
//    TSS_TSPATTRIB_KEYBLOB_PLAIN                    |0 0 1 1|
//    TSS_TSPATTRIB_KEYBLOB_GUID                     |0 1 0 0|
//    TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY              |0 1 0 1|
//
#define TSS_TSPATTRIB_KEYBLOB_BLOB         (0x00000008)   // key info using the key blob
#define TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY      (0x00000010)   // public key info using the blob
#define TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY      (0x00000028)   // encrypted private key blob
//
// SubFlags for Flag TSS_TSPATTRIB_KEY_INFO
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//   ---------------------------------------------------------------
//
//    TSS_TSPATTRIB_KEYINFO_SIZE           |0 0 0 0 1|
//    TSS_TSPATTRIB_KEYINFO_USAGE          |0 0 0 1 0|
//    TSS_TSPATTRIB_KEYINFO_KEYFLAGS       |0 0 0 1 1|
//    TSS_TSPATTRIB_KEYINFO_AUTHUSAGE      |0 0 1 0 0|
//    TSS_TSPATTRIB_KEYINFO_ALGORITHM      |0 0 1 0 1|
//    TSS_TSPATTRIB_KEYINFO_SIGSCHEME      |0 0 1 1 0|
//    TSS_TSPATTRIB_KEYINFO_ENCSCHEME      |0 0 1 1 1|
//    TSS_TSPATTRIB_KEYINFO_MIGRATABLE     |0 1 0 0 0|
//    TSS_TSPATTRIB_KEYINFO_REDIRECTED     |0 1 0 0 1|
//    TSS_TSPATTRIB_KEYINFO_VOLATILE       |0 1 0 1 0|
//    TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE  |0 1 0 1 1|
//    TSS_TSPATTRIB_KEYINFO_VERSION        |0 1 0 100|
//
#define TSS_TSPATTRIB_KEYINFO_SIZE         (0x00000080)   // key size in bits
#define TSS_TSPATTRIB_KEYINFO_USAGE         (0x00000100)   // key usage info
#define TSS_TSPATTRIB_KEYINFO_KEYFLAGS      (0x00000180)   // key flags
#define TSS_TSPATTRIB_KEYINFO_AUTHUSAGE      (0x00000200)   // key auth usage info
#define TSS_TSPATTRIB_KEYINFO_ALGORITHM          (0x00000280)   // key algorithm ID
#define TSS_TSPATTRIB_KEYINFO_SIGSCHEME          (0x00000300)   // key sig scheme
#define TSS_TSPATTRIB_KEYINFO_ENCSCHEME          (0x00000380)   // key enc scheme
#define TSS_TSPATTRIB_KEYINFO_MIGRATABLE      (0x00000400)   // if true then key is migratable
#define TSS_TSPATTRIB_KEYINFO_REDIRECTED      (0x00000480)   // key is redirected
#define TSS_TSPATTRIB_KEYINFO_VOLATILE      (0x00000500)   // if true key is volatile
#define TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE   (0x00000580)   // if true authorization is required
#define TSS_TSPATTRIB_KEYINFO_VERSION      (0x00000600)   // version info as TSS version struct
//
//////////////////////////////////////////////////////////////////////////
//      3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//      1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//      ---------------------------------------------------------------
//
// SubFlags for Flag TSS_TSPATTRIB_RSAKEY_INFO
//
//  TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT   |0 0 1|
//  TSS_TSPATTRIB_KEYINFO_RSA_MODULUS    |0 1 0|
//  TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE    |0 1 1|
//  TSS_TSPATTRIB_KEYINFO_RSA_PRIMES     |1 0 0|
//
#define TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT   (0x00001000)
#define TSS_TSPATTRIB_KEYINFO_RSA_MODULUS      (0x00002000)
#define TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE      (0x00003000)
#define TSS_TSPATTRIB_KEYINFO_RSA_PRIMES      (0x00004000)
//
// SubFlags for Flag TSS_TSPATTRIB_KEY_PCR
//
////////////////////////////////////////////////////////////////////////////////////
//               3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//               1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//               ---------------------------------------------------------------
//
// SubFlags for Flag TSS_TSPATTRIB_KEY_PCR
//  TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION  |0 0 1|
//  TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE   |0 1 0|
//  TSS_TSPATTRIB_KEYPCR_SELECTION          |0 1 1|
//
#define TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION   (0x00008000)
#define TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE   (0x00010000)
#define TSS_TSPATTRIB_KEYPCR_SELECTION      (0x00018000)
//
// SubFlags for TSS_TSPATTRIB_KEY_REGISTER
//
// SubFlags for TSS_TSPATTRIB_KEY_REGISTER
///////////////////////////////////////////////////////////////////////////////////////////////////
//                            3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//                            1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//                            ---------------------------------------------------------------
//
// TSS_TSPATTRIB_KEYREGISTER_USER    |0 0 1|
// TSS_TSPATTRIB_KEYREGISTER_SYSTEM  |0 1 0|
// TSS_TSPATTRIB_KEYREGISTER_NO      |0 1 1|
//
#define TSS_TSPATTRIB_KEYREGISTER_USER      (0x02000000)
#define TSS_TSPATTRIB_KEYREGISTER_SYSTEM      (0x04000000)
#define TSS_TSPATTRIB_KEYREGISTER_NO      (0x06000000)
//
//   Attribute definition for the tsp key object
//
//  Algorithm ID Definitions
//

//
// key size definitions
//
#define TSS_KEY_SIZEVAL_512BIT      (0x0200)
#define TSS_KEY_SIZEVAL_1024BIT     (0x0400)
#define TSS_KEY_SIZEVAL_2048BIT     (0x0800)
#define TSS_KEY_SIZEVAL_4096BIT     (0x1000)
#define TSS_KEY_SIZEVAL_8192BIT     (0x2000)
#define TSS_KEY_SIZEVAL_16384BIT    (0x4000)

//
//   This table defines the algo id's
//      Values intentional moved away from corresponding TPM values to avoid possible misuse
//
#define   TSS_ALG_RSA            (0x20)
#define   TSS_ALG_DES            (0x21)
#define   TSS_ALG_3DES         (0x22)
#define   TSS_ALG_SHA            (0x23)
#define   TSS_ALG_HMAC         (0x24)
#define   TSS_ALG_AES            (0x25)
//
//
// persisten storage registration definitions
//
#define TSS_PS_TYPE_USER             (1)         // Key is registered persistantly in the user
//                                                                       storage database.

#define TSS_PS_TYPE_SYSTEM           (2)         // Key is registered persistantly in the
//                                                                       system storage database.
// migration scheme definitions
//      Values intentional moved away from corresponding TPM values to avoid possible misuse
//
#define TSS_MS_MIGRATE            (0x20)
#define TSS_MS_REWRAP            (0x21)
#define TSS_MS_MAINT            (0x22)
//
//
//   TCPA key authorization
//      Values intentional moved away from corresponding TPM values to avoid possible misuse
//
#define TSS_KEYAUTH_AUTH_NEVER      (0x10)
#define TSS_KEYAUTH_AUTH_ALWAYS      (0x11)
//
// key usage definitions
//      Values intentional moved away from corresponding TPM values to avoid possible misuse
//
#define TSS_KEYUSAGE_BIND         (0x00)
#define TSS_KEYUSAGE_IDENTITY         (0x01)
#define TSS_KEYUSAGE_LEGACY         (0x02)
#define TSS_KEYUSAGE_SIGN         (0x03)
#define TSS_KEYUSAGE_STORAGE         (0x04)
#define TSS_KEYUSAGE_AUTHCHANGE      (0x07)
//
// key encrypten and signature scheme definitions
//
#define TSS_ES_NONE            (0x10)
#define TSS_ES_RSAESPKCSV15         (0x11)
#define TSS_ES_RSAESOAEP_SHA1_MGF1      (0x12)
//
#define TSS_SS_NONE            (0x10)
#define TSS_SS_RSASSAPKCS1V15_SHA1      (0x11)
#define TSS_SS_RSASSAPKCS1V15_DER      (0x12)
//
// Flags for TPM status information (Get- and SetStatus)
//
#define TSS_TPMSTATUS_DISABLEOWNERCLEAR      (0x00000001)   // persistent flag
#define TSS_TPMSTATUS_DISABLEFORCECLEAR      (0x00000002)   // volatile flag
#define TSS_TPMSTATUS_DISABLED         (0x00000003)   // persistent flag
#define TSS_TPMSTATUS_DEACTIVATED         (0x00000004)   // volatile flag
#define TSS_TPMSTATUS_OWNERSETDISABLE      (0x00000005)   // persistent flag for SetStatus
//                                                                               (disable flag)
#define TSS_TPMSTATUS_SETOWNERINSTALL      (0x00000006)   // persistent flag (ownership flag)
#define TSS_TPMSTATUS_DISABLEPUBEKREAD      (0x00000007)   // persistent flag
#define TSS_TPMSTATUS_ALLOWMAINTENANCE      (0x00000008)   // persistent flag
#define TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK   (0x00000009)   // persistent flag
#define TSS_TPMSTATUS_PHYSPRES_HWENABLE      (0x0000000A)   // persistent flag
#define TSS_TPMSTATUS_PHYSPRES_CMDENABLE      (0x0000000B)   // persistent flag
#define TSS_TPMSTATUS_PHYSPRES_LOCK         (0x0000000C)   // volatile flag
#define TSS_TPMSTATUS_PHYSPRESENCE         (0x0000000D)   // volatile flag
#define TSS_TPMSTATUS_PHYSICALDISABLE      (0x0000000E)   // persistent flag (SetStatus-Fkt
//                                                                               disable flag)
#define TSS_TPMSTATUS_CEKP_USED         (0x0000000F)   // persistent flag
#define TSS_TPMSTATUS_PHYSICALSETDEACTIVATED   (0x00000010)   // persistent flag (deactivated flag)
#define TSS_TPMSTATUS_SETTEMPDEACTIVATED      (0x00000011)   // volatile flag (deactivated flag)
#define TSS_TPMSTATUS_POSTINITIALISE      (0x00000012)   // volatile flag
#define TSS_TPMSTATUS_TPMPOST            (0x00000013)   // persistent flag
#define TSS_TPMSTATUS_TPMPOSTLOCK         (0x00000014)   // persistent flag
//
// Capability flag definitions
//
// TPM capabilities
#define TSS_TPMCAP_ORD               (0x10)
#define TSS_TPMCAP_ALG               (0x11)
#define TSS_TPMCAP_FLAG               (0x12)
#define TSS_TPMCAP_PROPERTY            (0x13)
#define TSS_TPMCAP_VERSION            (0x14)
//
// Sub-Capability Flags TPM-Capabilities
#define TSS_TPMCAP_PROP_PCR            (0x10)
#define TSS_TPMCAP_PROP_DIR            (0x11)
#define TSS_TPMCAP_PROP_MANUFACTURER      (0x12)
#define TSS_TPMCAP_PROP_SLOTS            (0x13)
//
// TSS Core Service Capabilities
#define TSS_TCSCAP_ALG               (0x00000001)
#define TSS_TCSCAP_VERSION            (0x00000002)
#define TSS_TCSCAP_CACHING            (0x00000003)
#define TSS_TCSCAP_PERSSTORAGE         (0x00000004)
#define TSS_TCSCAP_MANUFACTURER         (0x00000005)
//
// Sub-Capability Flags TSS-CoreService-Capabilities
#define TSS_TCSCAP_PROP_KEYCACHE         (0x00000100)
#define TSS_TCSCAP_PROP_AUTHCACHE         (0x00000101)
#define TSS_TCSCAP_PROP_MANUFACTURER_STR      (0x00000102)
#define TSS_TCSCAP_PROP_MANUFACTURER_ID      (0x00000103)
//
// TSS Service Provider Capabilities
#define TSS_TSPCAP_ALG               (0x00000010)
#define TSS_TSPCAP_VERSION            (0x00000011)
#define TSS_TSPCAP_PERSSTORAGE         (0x00000012)
//
// Event type definitions
#define TSS_EV_CODE_CERT            (0x00000001)
#define TSS_EV_CODE_NOCERT            (0x00000002)
#define TSS_EV_XML_CONFIG            (0x00000003)
#define TSS_EV_NO_ACTION            (0x00000004)
#define TSS_EV_SEPARATOR            (0x00000005)
#define TSS_EV_ACTION               (0x00000006)
#define TSS_EV_PLATFORM_SPECIFIC         (0x00000007)
//
//
// TSS random number limits
//
#define TSS_TSPCAP_RANDOMLIMIT         (0x00001000)   / Errata: Missing from spec
//
// UUIDs
//
// Errata: This are not in the spec
#ifdef __GNUC__
#define TSS_UUID_SRK	{0x00000000,0x0000,0x0000,0x00,0x00,{0x00,0x00,0x00,0x00,0x00,0x01}}	// Storage root key
#define TSS_UUID_SK	{0x00000000,0x0000,0x0000,0x00,0x00,{0x00,0x00,0x00,0x00,0x00,0x02}}	// System key
#define TSS_UUID_RK	{0x00000000,0x0000,0x0000,0x00,0x00,{0x00,0x00,0x00,0x00,0x00,0x03}}	// roaming key
#define TSS_UUID_USK1	{0x00000000,0x0000,0x0000,0x00,0x00,{0x00,0x00,0x00,0x00,0x00,0x04}}	// user storage key 1
#define TSS_UUID_USK2	{0x00000000,0x0000,0x0000,0x00,0x00,{0x00,0x00,0x00,0x00,0x00,0x05}}	// user storage key 2
#define TSS_UUID_USK3	{0x00000000,0x0000,0x0000,0x00,0x00,{0x00,0x00,0x00,0x00,0x00,0x06}}	// user storage key 3
#define TSS_UUID_USK4	{0x00000000,0x0000,0x0000,0x00,0x00,{0x00,0x00,0x00,0x00,0x00,0x07}}	// user storage key 4
#else
#define TSS_UUID_SRK   L"00000000-0000-0000-0000-000000000001"      // Storage root key
#define TSS_UUID_SK   L"00000000-0000-0000-0000-000000000002"      // System key
#define TSS_UUID_RK   L"00000000-0000-0000-0000-000000000003"      // roaming key
#define TSS_UUID_USK1   L"00000000-0000-0000-0000-000000000004"      // user storage key 1
#define TSS_UUID_USK2   L"00000000-0000-0000-0000-000000000005"      // user storage key 2
#define TSS_UUID_USK3   L"00000000-0000-0000-0000-000000000006"      // user storage key 3
#define TSS_UUID_USK4   L"00000000-0000-0000-0000-000000000007"      // user storage key 4
#endif

//
// TCPA well known secret
//
#define TSS_WELL_KNOWN_SECRET {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

/* Imported from the TSS 1.2 header files for use in 1.2 style callbacks */
// *************
// TPM object: *
// *************

//
// Attributes:
//
#define TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY  0x00000001
#define TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY 0x00000002


#endif // __TSS_DEFINES_H__
