/*++

  TPM error return codes basically extracted from TCPA Main Specification V1.1b

  --*/

#ifndef __TCPA_ERROR_H__
#define __TCPA_ERROR_H__


//////////////////////////////////////////////////////////////////////
// error codes

#ifndef TCPA_E_BASE
#define TCPA_E_BASE    0x00000000L
#endif

#ifndef TCPA_E_NON_FATAL
#define TCPA_E_NON_FATAL   0x00000800L
#endif


// Successful completion of the TCPA operation.
#define TCPA_SUCCESS    TCPA_E_BASE

//
// MessageId: TCPA_E_AUTHFAIL
//
// MessageText:
//
// Authentication failed.
//
#define TCPA_E_AUTHFAIL    (UINT32)(TCPA_E_BASE + 0x1)

//
// MessageId: TCPA_E_BADINDEX
//
// MessageText:
//
// The index to a PCR, DIR or other register is incorrect.
//
#define TCPA_E_BADINDEX    (UINT32)(TCPA_E_BASE + 0x2)

//
// MessageId: TCPA_E_BAD_PARAMETER
//
// MessageText:
//
// One or more TCPA command parameter is bad.
//
#define TCPA_E_BAD_PARAMETER   (UINT32)(TCPA_E_BASE + 0x3)

//
// MessageId: TCPA_E_AUDITFAILURE
//
// MessageText:
//
// An operation completed successfully but the auditing of that operation failed.
// 
#define TCPA_E_AUDITFAILURE   (UINT32)(TCPA_E_BASE + 0x4)

//
// MessageId: TCPA_E_CLEAR_DISABLED
//
// MessageText:
//
// The clear disable flag is set and all clear operations now require physical access.
//
#define TCPA_E_CLEAR_DISABLED   (UINT32)(TCPA_E_BASE + 0x5)

//
// MessageId: TCPA_E_DEACTIVATED
//
// MessageText:
//
// The TCPA is deactivated.
//
#define TCPA_E_DEACTIVATED   (UINT32)(TCPA_E_BASE + 0x6)

//
// MessageId: TCPA_E_DISABLED
//
// MessageText:
//
// The TCPA is disabled.
//
#define TCPA_E_DISABLED    (UINT32)(TCPA_E_BASE + 0x7)

//
// MessageId: TCPA_E_DISABLED_CMD
//
// MessageText:
//
// The target TCPA command has been disabled.
//
#define TCPA_E_DISABLED_CMD   (UINT32)(TCPA_E_BASE + 0x8)

//
// MessageId: TCPA_E_FAIL
//
// MessageText:
//
// The TCPA operation failed.
//
#define TCPA_E_FAIL    (UINT32)(TCPA_E_BASE + 0x9)

//
// MessageId: TCPA_E_INACTIVE 
//
// MessageText:
//
// The TCPA is inactive.
//
#define TCPA_E_INACTIVE    (UINT32)(TCPA_E_BASE + 0xA)

//
// MessageId: TCPA_E_INSTALL_DISABLED
//
// MessageText:
//
// The ability to install an owner is disabled.
//
#define TCPA_E_INSTALL_DISABLED  (UINT32)(TCPA_E_BASE + 0xB)

//
// MessageId: TCPA_E_INVALID_HANDLE
//
// MessageText:
//
// The TCPA key handle presented was invalid.
//
#define TCPA_E_INVALID_KEYHANDLE  (UINT32)(TCPA_E_BASE + 0xC)

//
// MessageId: TCPA_E_KEYNOTFOUND
//
// MessageText:
//
// The target key was not found in the TCPA.
//
#define TCPA_E_KEYNOTFOUND   (UINT32)(TCPA_E_BASE + 0xD)

//
// MessageId: TCPA_E_NEED_SELFTEST
//
// MessageText:
//
// The capability requires an untested function,
// additional self-test is required before the capability may execute.
//
#define TCPA_E_NEED_SELFTEST   (UINT32)(TCPA_E_BASE + 0xE)

//
// MessageId: TCPA_E_MIGRATEFAIL
//
// MessageText:
//
// Migration authorization failed.
//
#define TCPA_E_MIGRATEFAIL   (UINT32)(TCPA_E_BASE + 0xF)

//
// MessageId: TCPA_E_NO_PCR_INFO
//
// MessageText:
//
// A list of PCR values was not supplied.
//
#define TCPA_E_NO_PCR_INFO   (UINT32)(TCPA_E_BASE + 0x10)

//
// MessageId: TCPA_E_NOSPACE
//
// MessageText:
//
// No room in the TCPA to load a key.
//
#define TCPA_E_NOSPACE    (UINT32)(TCPA_E_BASE + 0x11)

//
// MessageId: TCPA_E_NOSRK
//
// MessageText:
//
// There is no SRK set.
//
#define TCPA_E_NOSRK    (UINT32)(TCPA_E_BASE + 0x12)

//
// MessageId: TCPA_E_NOTSEALED_BLOB
//
// MessageText:
//
// An encrypted blob is invalid or was not created by this TCPA.
//
#define TCPA_E_NOTSEALED_BLOB   (UINT32)(TCPA_E_BASE + 0x13)

//
// MessageId: TCPA_E_OWNER_SET
//
// MessageText:
//
// An Owner is already set in the TCPA.
//
#define TCPA_E_OWNER_SET   (UINT32)(TCPA_E_BASE + 0x14)

//
// MessageId: TCPA_E_RESOURCES
//
// MessageText:
//
// The TPM has insufficient internal resources to perform the requested action.
//
#define TCPA_E_RESOURCES   (UINT32)(TCPA_E_BASE + 0x15)

//
// MessageId: TCPA_E_SHORTRANDOM
//
// MessageText:
//
// A random string supplied to the TPM was too short.
//
#define TCPA_E_SHORTRANDOM   (UINT32)(TCPA_E_BASE + 0x16)

//
// MessageId: TCPA_E_SIZE
//
// MessageText:
//
// The TPM does not have the space to perform the operation.
//
#define TCPA_E_SIZE    (UINT32)(TCPA_E_BASE + 0x17)

//
// MessageId: TCPA_E_WRONGPCRVAL
//
// MessageText:
//
// The named PCR value does not match the current PCR value.
//
#define TCPA_E_WRONGPCRVAL   (UINT32)(TCPA_E_BASE + 0x18)

//
// MessageId: TCPA_E_BUSY
//
// MessageText:
//
// The TPM is too busy to respond to the command.
//
//#define TCPA_E_BUSY    (UINT32)(TCPA_E_BASE + 0x19)

//
// MessageId: TCPA_E_BAD_PARAM_SIZE
//
// MessageText:
//
// The paramSize argument to the command has the incorrect value
//
#define TCPA_E_BAD_PARAM_SIZE   (UINT32)(TCPA_E_BASE + 0x19)

//
// MessageId: TCPA_E_SHA_THREAD
//
// MessageText:
//
// There is no existing SHA-1 thread in the TPM.
//
#define TCPA_E_SHA_THREAD   (UINT32)(TCPA_E_BASE + 0x1A)

//
// MessageId: TCPA_E_SHA_ERROR
//
// MessageText:
//
// The calculation is unable to proceed because the existing SHA-1
// thread has already encountered an error.
//
#define TCPA_E_SHA_ERROR   (UINT32)(TCPA_E_BASE + 0x1B)

//
// MessageId: TCPA_E_FAILEDSELFTEST
//
// MessageText:
//
// Self-test has failed and the TPM has shutdown.
//
#define TCPA_E_FAILEDSELFTEST   (UINT32)(TCPA_E_BASE + 0x1C)

//
// MessageId: TCPA_E_AUTH2FAIL
//
// MessageText:
//
// The authorization for the second key in a 2 key function failed authorization.
//
#define TCPA_E_AUTH2FAIL   (UINT32)(TCPA_E_BASE + 0x1D)

//
// MessageId: TCPA_E_BADTAG
//
// MessageText:
//
// The tag value sent to the TPM for a command is invalid.
//
#define TCPA_E_BADTAG    (UINT32)(TCPA_E_BASE + 0x1E)

//
// MessageId: TCPA_E_IOERROR
//
// MessageText:
//
//  An IO error occurred transmitting information to the TPM.
//
#define TCPA_E_IOERROR    (UINT32)(TCPA_E_BASE + 0x1F)

//
// MessageId: TCPA_E_ENCRYPT_ERROR
//
// MessageText:
//
// The TPM encryption process had a problem.
//
#define TCPA_E_ENCRYPT_ERROR   (UINT32)(TCPA_E_BASE + 0x20)

//
// MessageId: TCPA_E_DECRYPT_ERROR
//
// MessageText:
//
// The TPM decryption process did not complete.
//
#define TCPA_E_DECRYPT_ERROR   (UINT32)(TCPA_E_BASE + 0x21)

//
// MessageId: TCPA_E_INVALID_AUTHHANDLE
//
// MessageText:
//
// The TPM auth handle was invalid.
//
#define TCPA_E_INVALID_AUTHHANDLE  (UINT32)(TCPA_E_BASE + 0x22)

//
// MessageId: TCPA_E_NO_ENDORSEMENT
//
// MessageText:
//
// The TPM does not have an Endorsement Key installed.
//
#define TCPA_E_NO_ENDORSEMENT   (UINT32)(TCPA_E_BASE + 0x23)

//
// MessageId: TCPA_E_INVALID_KEYUSAGE
//
// MessageText:
//
// The usage of a key is not allowed.
//
#define TCPA_E_INVALID_KEYUSAGE  (UINT32)(TCPA_E_BASE + 0x24)

//
// MessageId: TCPA_E_WRONG_ENTITYTYPE
//
// MessageText:
//
//  The submitted entity type is not allowed.
//
#define TCPA_E_WRONG_ENTITYTYPE  (UINT32)(TCPA_E_BASE + 0x25)

//
// MessageId: TCPA_INVALID_POSTINIT
//
// MessageText:
//
// The command was received in the wrong sequence relative to TPM_Init and a subsequent TPM_Startup.
//
#define TCPA_E_INVALID_POSTINIT  (UINT32)(TCPA_E_BASE + 0x26)

//
// MessageId: TCPA_E_INAPPROPRIATE_SIG
//
// MessageText:
//
// Signed data cannot include additional DER information.
//
#define TCPA_E_INAPPROPRIATE_SIG  (UINT32)(TCPA_E_BASE + 0x27)

//
// MessageId: TCPA_E_BAD_KEY_PROPERTY
//
// MessageText:
//
//  The key properties in TCPA_KEY_PARMs are not supported by this TPM.
//
#define TCPA_E_BAD_KEY_PROPERTY  (UINT32)(TCPA_E_BASE + 0x28)

//
// MessageId: TCPA_E_BAD_MIGRATION
//
// MessageText:
//
//  The migration properties of this key are incorrect.
//
#define TCPA_E_BAD_MIGRATION   (UINT32)(TCPA_E_BASE + 0x29)

//
// MessageId: TCPA_E_BAD_SCHEME
//
// MessageText:
//
// The signature or encryption scheme for this key is incorrect or not permitted in this situation.
//
#define TCPA_E_BAD_SCHEME   (UINT32)(TCPA_E_BASE + 0x2A)

//
// MessageId: TCPA_E_BAD_DATASIZE
//
// MessageText:
//
//  The size of the data (or blob) parameter is bad or inconsistent with the referenced key.
//
#define TCPA_E_BAD_DATASIZE   (UINT32)(TCPA_E_BASE + 0x2B)

//
// MessageId: TCPA_E_BAD_MODE
//
// MessageText:
//
// A mode parameter is bad, such as capArea or subCapArea for TPM_GetCapability,
// phsicalPresence parameter for TPM_PhysicalPresence,
// or migrationType for TPM_CreateMigrationBlob.
//
#define TCPA_E_BAD_MODE    (UINT32)(TCPA_E_BASE + 0x2C)

//
// MessageId: TCPA_E_BAD_PRESENCE
//
// MessageText:
//
// Either the physicalPresence or physicalPresenceLock bits have the wrong value.
//
#define TCPA_E_BAD_PRESENCE   (UINT32)(TCPA_E_BASE + 0x2D)

//
// MessageId: TCPA_E_BAD_VERSION
//
// MessageText:
//
// The TPM cannot perform this version of the capability.
//
#define TCPA_E_BAD_VERSION   (UINT32)(TCPA_E_BASE + 0x2E)


//////////////////////////////////////////////////////////////////////
// non fatal errors

//
// MessageId: TCPA_E_RETRY
//
// MessageText:
//
// The TPM is too busy to respond to the command immediately,
// but the command could be resubmitted at a later time.
//
#define TCPA_E_RETRY  (UINT32)(TCPA_E_BASE + TCPA_E_NON_FATAL)

#endif // __TCPA_ERROR_H__
