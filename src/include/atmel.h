
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _ATMEL_H_
#define _ATMEL_H_

/*typedef		BYTE	TCPA_STATE_ID; */
#define TCPA_STATE_ID BYTE

typedef struct tdTCPA_IO_CONFIG {
	unsigned configA:1;
	unsigned configB:1;
	unsigned configC:1;
	unsigned configLock:1;
	unsigned stateA:1;
	unsigned stateB:1;
	unsigned stateC:1;
	unsigned batteryClear:1;
	unsigned unused:24;
} TCPA_IO_CONFIG;

/*Name	Value	Description */
#define TCPA_ATMEL_BASE			0x00000400	/*The start of Atmel-specific TCPA return codes */
#define TCPA_BAD_STATEID		TCPA_ATMEL_BASE + 1	/*These state ID name is undefined. */
#define TCPA_BADWRITE			TCPA_ATMEL_BASE + 2	/*Writes are not permitted to the location specified. */
#define TCPA_BADREAD			TCPA_ATMEL_BASE + 3	/*Reads are not permitted from the location specified. */
#define TCPA_TAMPER_DETECT		TCPA_ATMEL_BASE + 4	/*      A tamper event has occurred and the TPM has been reset. */
#define TCPA_LOCKED_OUT			TCPA_ATMEL_BASE + 5	/*Sufficient authorization attempts have failed such that the chip is temporarily locked out against further operation. */
#define TCPA_BAD_ID				TCPA_ATMEL_BASE + 6	/*There was a problem with the ID value on the chip. */
#define TCPA_NO_ID				TCPA_ATMEL_BASE + 7	/*No ID has been installed on the chip. */
#define TCPA_INT_ERROR			TCPA_ATMEL_BASE + 8	/*      The TPM encountered an internal error. */
#define TCPA_VERIF_FAIL			TCPA_ATMEL_BASE + 9	/*The signature verification failed */

#ifndef TCPA_VENDOR_COMMAND
#define TCPA_VENDOR_COMMAND	0x20000000	/*Command that is vendor specific for a given TPM or TSS. */
#endif
#define TPM_ORD_SetState			1 + TCPA_VENDOR_COMMAND
#define TPM_ORD_OwnerSetState		2 + TCPA_VENDOR_COMMAND
#define TPM_ORD_GetState			3 + TCPA_VENDOR_COMMAND
#define TPM_ORD_Identify			4 + TCPA_VENDOR_COMMAND
#define TPM_ORD_VerifySignature		5 + TCPA_VENDOR_COMMAND
#define TPM_ORD_BindV20				6 + TCPA_VENDOR_COMMAND

/*CONDITIONAL_EXPORT TCPA_RESULT Atmel_TPM_SetState( TCPA_STATE_ID stateID, UINT32 sizeState, BYTE* stateValue ); */
/*CONDITIONAL_EXPORT TCPA_RESULT Atmel_TPM_OwnerSetState( TCPA_STATE_ID stateID, UINT32 sizeState, BYTE* stateValue, TCS_AUTH* ownerAuth ); */
/*CONDITIONAL_EXPORT TCPA_RESULT Atmel_TPM_GetState( TCS_CONTEXT_HANDLE hContext, TCPA_STATE_ID stateID, UINT32* sizeState, BYTE** stateValue ); */

/*
#ifdef __cplusplus
extern "C"{
#endif 

#ifndef _TCSDLL_
TCPA_RESULT Atmel_TPM_SetState_Internal( TCS_CONTEXT_HANDLE hContext, BYTE stateID, UINT32 sizeState, BYTE* stateValue );
TCPA_RESULT Atmel_TPM_OwnerSetState_Internal( TCS_CONTEXT_HANDLE hContext, BYTE stateID, UINT32 sizeState, BYTE* stateValue, TCS_AUTH* ownerAuth );
TCPA_RESULT Atmel_TPM_GetState_Internal( TCS_CONTEXT_HANDLE hContext, BYTE stateID, UINT32* sizeState, BYTE** stateValue );
#endif

#ifdef __cplusplus
}
#endif 
*/

TCPA_RESULT TPM_Identify(TCS_CONTEXT_HANDLE hContext, BYTE mode, UINT32 inputSize, BYTE * inputValue,
			 UINT32 * outputSize, BYTE ** outData);
TCPA_RESULT TPM_VerifySignature(UINT32 digestSize, BYTE * digest, UINT32 sigSize, BYTE * sig,
				TCPA_PUBKEY pubSigningKey);
TCPA_RESULT TPM_BindV20(TCS_CONTEXT_HANDLE hContext, TCPA_STORE_PUBKEY pubBindingKey, UINT32 dataSize,
			BYTE * inData, UINT32 * encDataSize, BYTE ** encData);
/*DllExport TCPA_RESULT TSC_PhysicalPresence( UINT16 physPres ); */

/*------------------	 */
/*TSP Literals */

enum ATMEL_STATE_ID {
	ATMEL_STATE_ID_TPM_IO_A = 0,
	ATMEL_STATE_ID_TPM_IO_B,
	ATMEL_STATE_ID_TPM_IO_C,
	ATMEL_STATE_ID_BATTERY,
	ATMEL_STATE_ID_EXTAMPER,
	ATMEL_STATE_ID_INTAMPER,
	ATMEL_STATE_ID_EN_SETSTATE,
	ATMEL_STATE_ID_TPM_CONFIG,
	ATMEL_STATE_ID_FAILCOUNT,
	ATMEL_STATE_ID_FAILMOD,
	ATMEL_STATE_ID_CODEREV,
	ATMEL_STATE_ID_FIPS
};

#endif
