/*++

  Global typedefs for TSS

*/

#ifndef __TSS_TYPEDEF_H__
#define __TSS_TYPEDEF_H__


//--------------------------------------------------------------------
// definitions for TSS Service Provider (TSP)
//
typedef  UINT32  TSS_HANDLE;

typedef  UINT32  TSS_FLAG;  // object attributes
typedef  UINT32  TSS_RESULT;  // the return code from a TSS function

typedef  UINT32      TSS_HOBJECT; // basic object handle
typedef  TSS_HOBJECT     TSS_HCONTEXT; // context object handle
typedef  TSS_HOBJECT     TSS_HPOLICY; // policy object handle
typedef  TSS_HOBJECT     TSS_HTPM;  // TPM object handle
typedef  TSS_HOBJECT     TSS_HKEY;  // key object handle
typedef  TSS_HOBJECT     TSS_HENCDATA; // encrypted data object handle
typedef  TSS_HOBJECT     TSS_HPCRS;  // PCR composite object handle
typedef  TSS_HOBJECT     TSS_HHASH;  // hash object handle
typedef  TSS_HOBJECT     TSS_HPS;  // persistent storage object handle


typedef UINT32  TSS_EVENTTYPE;
typedef UINT16  TSS_MIGRATE_SCHEME;
typedef UINT32  TSS_ALGORITHM_ID;
typedef UINT32  TSS_KEY_USAGE_ID;
typedef UINT16  TSS_KEY_ENC_SCHEME;
typedef UINT16  TSS_KEY_SIG_SCHEME;

#endif // __TSS_TYPEDEF_H__

