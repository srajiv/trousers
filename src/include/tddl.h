
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#ifndef _TDDL_H_
#define _TDDL_H_

#undef TPM_IOCTL

#ifdef TPM_IOCTL
#define TPM_DEVICE_PATH		"/dev/tpm"
#else
#define TPM_DEVICE_PATH		"/dev/tpm0"
#endif

#define TDDL_TXBUF_SIZE		2048
#define TDDL_UNINITIALIZED	-1


TSS_RESULT Tddli_Open(void);

TSS_RESULT Tddli_TransmitData(BYTE *pTransmitBuf,
			UINT32 TransmitBufLen,
			BYTE *pReceiveBuf,
			UINT32 *pReceiveBufLen);

TSS_RESULT Tddli_Close(void);

#endif
