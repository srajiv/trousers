
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>

#include "tss/tss.h"
#include "linux/tpm.h"
#include "log.h"
#include "tddl.h"

int tpm_fd = TDDL_UNINITIALIZED;

BYTE txBuffer[TDDL_TXBUF_SIZE];

#undef	TPM_IOCTL

TSS_RESULT
Tddli_Open()
{
	if (tpm_fd != TDDL_UNINITIALIZED) {
		LogDebug1("attempted to re-open the TPM driver!");
		return TDDL_E_ALREADY_OPENED;
	}

	tpm_fd = open(TPM_DEVICE_PATH, O_RDWR);
	if (tpm_fd < 0) {
		if (errno == ENOENT) {
			tpm_fd = TDDL_UNINITIALIZED;
			LogError("device file %s does not exist!", TPM_DEVICE_PATH);
			/* File DNE */
			return TDDL_E_COMPONENT_NOT_FOUND;
		}
		LogError("Open of %s failed: (errno: %d) %s", TPM_DEVICE_PATH, errno, strerror(errno));
		return TDDL_E_FAIL;
	}
	LogDebug("Leaving %s", __FUNCTION__);
	return TDDL_SUCCESS;
}

TSS_RESULT
Tddli_Close()
{
	if (tpm_fd == TDDL_UNINITIALIZED) {
		LogDebug1("attempted to re-close the TPM driver!");
		return TDDL_E_ALREADY_CLOSED;
	}
	close(tpm_fd);
	tpm_fd = TDDL_UNINITIALIZED;
	LogDebug("Leaving %s", __FUNCTION__);
	return TDDL_SUCCESS;
}

TSS_RESULT
Tddli_TransmitData(BYTE * pTransmitBuf, UINT32 TransmitBufLen, BYTE * pReceiveBuf,
		  UINT32 * pReceiveBufLen)
{
	int sizeResult;

	if (TransmitBufLen > TDDL_TXBUF_SIZE)
		return TDDL_E_FAIL;

	memcpy(txBuffer, pTransmitBuf, TransmitBufLen);
	LogDebug1("Calling write to driver ");
#ifdef TPM_IOCTL
	if ((sizeResult = ioctl(tpm_fd, TPMIOC_TRANSMIT, txBuffer)) == -1) {
		LogError("ioctl: (%d) %s", errno, strerror(errno));
		return TDDL_E_FAIL;
	}
#else
	if (write(tpm_fd, txBuffer, TransmitBufLen) == 0)
		return TDDL_E_IOERROR;
#if 0
	LogDebug1("Passed Write");

	LogDebug1("Calling Read");
#endif
	sizeResult = read(tpm_fd, txBuffer, TDDL_TXBUF_SIZE);
#endif
	if (sizeResult <= 0)
		return TDDL_E_IOERROR;
	if ((unsigned)sizeResult > *pReceiveBufLen)
		return TDDL_E_INSUFFICIENT_BUFFER;

	*pReceiveBufLen = sizeResult;

	memcpy(pReceiveBuf, txBuffer, *pReceiveBufLen);
	LogDebug("Leaving %s ", __FUNCTION__);
	return TDDL_SUCCESS;
}

TSS_RESULT
Tddli_GetStatus(UINT32 ReqStatusType)
{
	return TSS_E_NOTIMPL;
}

TSS_RESULT
Tddli_SetCapability(UINT32 CapArea, UINT32 SubCap,
		    BYTE *pSetCapBuf, UINT32 SetCapBufLen)
{
	return TSS_E_NOTIMPL;
}

TSS_RESULT
Tddli_GetCapability(UINT32 CapArea, UINT32 SubCap,
		    BYTE *pCapBuf, UINT32 *pCapBufLen)
{
	return TSS_E_NOTIMPL;
}

TSS_RESULT Tddli_Cancel(void)
{
#ifdef TPM_IOCTL
	int rc;

	if ((rc = ioctl(tpm_fd, TPMIOC_CANCEL, NULL)) == -1) {
		LogError("ioctl: (%d) %s", errno, strerror(errno));
		return TDDL_E_FAIL;
	} else if (rc == -EIO) {
		/* The driver timed out while trying to tell the chip to cancel */
		return TDDL_COMMAND_COMPLETED;
	}

	return TDDL_SUCCESS;
#else
	return TSS_E_NOTIMPL;
#endif
}
