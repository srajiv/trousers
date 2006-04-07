/*++

  TPM Device Driver Library interface

  --*/

#ifndef __TDDLI_H__
#define __TDDLI_H__

#ifdef _WINDOWS_

// --- This should be used on Windows platforms
#ifdef TDDLI_EXPORTS
#define TDDLI __declspec(dllexport)
#else
#define TDDLI __declspec(dllimport)
#endif
#else
#define TDDLI
#endif


// Errata: Change spec from TCPA_CAP_PROP_MANUFACTURER to TPM_CAP_PROP_MANUFACTURER
#define TDDL_CAP_VERSION   0x0100
#define TDDL_CAP_VER_DRV   0x0101
#define TDDL_CAP_VER_FW    0x0102
#define TDDL_CAP_VER_FW_DATE   0x0103

#define TDDL_CAP_PROPERTY   0x0200
#define TDDL_CAP_PROP_MANUFACTURER  0x0201
#define TDDL_CAP_PROP_MODULE_TYPE  0x0202
#define TDDL_CAP_PROP_GLOBAL_STATE  0x0203

//--------------------------------------------------------------------
// TDDL specific helper redefinitions

#ifdef __cplusplus
extern "C" {

	//establish a connection to the TPM device driver
	TDDLI TSS_RESULT Tddli_Open();

	//close a open connection to the TPM device driver
	TDDLI TSS_RESULT Tddli_Close();

	//cancels the last outstanding TPM command
	TDDLI TSS_RESULT Tddli_Cancel();

	// read the attributes returned by the TPM HW/FW
	TDDLI TSS_RESULT Tddli_GetCapability(
			UINT32        CapArea,
			UINT32        SubCap,
			BYTE*         pCapBuf,
			UINT32*       puntCapBufLen
			);

	// set parameters to the TPM HW/FW
	TDDLI TSS_RESULT Tddli_SetCapability(
			UINT32        CapArea,
			UINT32        SubCap,
			BYTE*         pCapBuf,
			UINT32       puntCapBufLen
			);

	// get status of the TPM driver and device
	TDDLI TSS_RESULT Tddli_GetStatus(
			UINT32        ReqStatusType,
			UINT32*       puntStatus
			);

	// send any data to the TPM module
	TDDLI TSS_RESULT Tddli_TransmitData(
			BYTE*         pTransmitBuf,
			UINT32        TransmitBufLen,
			BYTE*         pReceiveBuf,
			UINT32*       puntReceiveBufLen
			);
}
#else

//establish a connection to the TPM device driver
extern TDDLI TSS_RESULT Tddli_Open();

//close a open connection to the TPM device driver
extern TDDLI TSS_RESULT Tddli_Close();

//cancels the last outstanding TPM command
extern TDDLI TSS_RESULT Tddli_Cancel();

// read the attributes returned by the TPM HW/FW
extern TDDLI TSS_RESULT Tddli_GetCapability(
		UINT32       CapArea,
		UINT32       SubCap,
		BYTE*        pCapBuf,
		UINT32*      puntCapBufLen
		);

// set parameters to the TPM HW/FW
extern TDDLI TSS_RESULT Tddli_SetCapability(
		UINT32       CapArea,
		UINT32       SubCap,
		BYTE*        pCapBuf,
		UINT32      puntCapBufLen
		);

// get status of the TPM driver and device
extern TDDLI TSS_RESULT Tddli_GetStatus(
		UINT32       ReqStatusType,
		UINT32*      puntStatus
		);

// send any data to the TPM module
extern TDDLI TSS_RESULT Tddli_TransmitData(
		BYTE*        pTransmitBuf,
		UINT32       TransmitBufLen,
		BYTE*        pReceiveBuf,
		UINT32*      puntReceiveBufLen
		);
#endif

#endif // __TDDLI_H__

