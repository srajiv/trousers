
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004, 2005
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
#include "tcslog.h"
#include "tddl.h"

struct tpm_device_node tpm_device_nodes[] = {
	{"/dev/tpm0", 0, TDDL_UNINITIALIZED},
	{"/udev/tpm0", 0, TDDL_UNINITIALIZED},
	{"/dev/tpm", 1, TDDL_UNINITIALIZED},
	{NULL, 0, TDDL_UNINITIALIZED}
};

struct tpm_device_node *opened_device = NULL;

BYTE txBuffer[TDDL_TXBUF_SIZE];

int
open_device(void)
{
	int i;

	/* tpm_device_paths is filled out in tddl.h */
	for (i = 0; tpm_device_nodes[i].path != NULL; i++) {
		if ((tpm_device_nodes[i].fd = open(tpm_device_nodes[i].path, O_RDWR)) < 0) {
			continue;
		}

		opened_device = &(tpm_device_nodes[i]);
		return opened_device->fd;
	}

	return -1;
}

TSS_RESULT
Tddli_Open()
{
	int rc;

	if (opened_device != NULL) {
		LogDebug1("attempted to re-open the TPM driver!");
		return TDDL_E_ALREADY_OPENED;
	}

	rc = open_device();
	if (rc < 0) {
		LogError("Could not find a device to open!");
		if (errno == ENOENT) {
			/* File DNE */
			return TDDL_E_COMPONENT_NOT_FOUND;
		}

		return TDDL_E_FAIL;
	}

	return TDDL_SUCCESS;
}

TSS_RESULT
Tddli_Close()
{
	if (opened_device == NULL) {
		LogDebug1("attempted to re-close the TPM driver!");
		return TDDL_E_ALREADY_CLOSED;
	}

	close(opened_device->fd);
	opened_device->fd = TDDL_UNINITIALIZED;
	opened_device = NULL;

	return TDDL_SUCCESS;
}

TSS_RESULT
Tddli_TransmitData(BYTE * pTransmitBuf, UINT32 TransmitBufLen, BYTE * pReceiveBuf,
		  UINT32 * pReceiveBufLen)
{
	int sizeResult;

	if (TransmitBufLen > TDDL_TXBUF_SIZE) {
		LogError("buffer size handed to TDDL is too large! (%u bytes)", TransmitBufLen);
		return TDDL_E_FAIL;
	}

	memcpy(txBuffer, pTransmitBuf, TransmitBufLen);
	LogDebug1("Calling write to driver");

	if (opened_device->ioctl) {
		if ((sizeResult = ioctl(opened_device->fd, TPMIOC_TRANSMIT, txBuffer)) == -1) {
			LogError("ioctl: (%d) %s", errno, strerror(errno));
			return TDDL_E_FAIL;
		}
	} else {
		if ((sizeResult = write(opened_device->fd, txBuffer, TransmitBufLen)) < 0) {
			LogError("write to device %s failed: %s", opened_device->path, strerror(errno));
			return TDDL_E_IOERROR;
		} else if (sizeResult < TransmitBufLen) {
			LogError("wrote %d bytes to %s (tried to write %d)", sizeResult,
					opened_device->path, TransmitBufLen);
			return TDDL_E_IOERROR;
		}

		sizeResult = read(opened_device->fd, txBuffer, TDDL_TXBUF_SIZE);
	}

	if (sizeResult < 0) {
		LogError("read from device %s failed: %s", opened_device->path, strerror(errno));
		return TDDL_E_IOERROR;
	} else if (sizeResult == 0) {
		LogError("Zero bytes read from device %s", opened_device->path);
		return TDDL_E_IOERROR;
	}

	if ((unsigned)sizeResult > *pReceiveBufLen) {
		LogError("read %d bytes from device %s, (only room for %d)", sizeResult,
				opened_device->path, *pReceiveBufLen);
		return TDDL_E_INSUFFICIENT_BUFFER;
	}

	*pReceiveBufLen = sizeResult;

	memcpy(pReceiveBuf, txBuffer, *pReceiveBufLen);
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
	int rc;

	if (opened_device->ioctl) {
		if ((rc = ioctl(opened_device->fd, TPMIOC_CANCEL, NULL)) == -1) {
			LogError("ioctl: (%d) %s", errno, strerror(errno));
			return TDDL_E_FAIL;
		} else if (rc == -EIO) {
			/* The driver timed out while trying to tell the chip to cancel */
			return TDDL_COMMAND_COMPLETED;
		}

		return TDDL_SUCCESS;
	} else {
		return TSS_E_NOTIMPL;
	}
}
