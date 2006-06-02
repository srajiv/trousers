
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _SPI_INTERNAL_TYPES_H_
#define _SPI_INTERNAL_TYPES_H_

/* XXX */
#include "trousers_types.h"

// operate on the TPMs non-volatile flags
#define TPM11_NONVOL_DISABLED		0x00000001
#define TPM11_NONVOL_OWNABLE		0x00000002
#define TPM11_NONVOL_DEACTIVATED	0x00000004
#define TPM11_NONVOL_READABLE_PUBEK	0x00000008
#define TPM11_NONVOL_OWNER_CLEARABLE	0x00000010
#define TPM11_NONVOL_ALLOW_MAINT	0x00000020
#define TPM11_NONVOL_LIFETIME_LOCK	0x00000040
#define TPM11_NONVOL_HW_PRES		0x00000080
#define TPM11_NONVOL_CMD_PRES		0x00000100
#define TPM11_NONVOL_CEKP_USED		0x00000200

// operate on the TPMs volatile flags
#define TPM11_VOL_TEMP_DEACTIVATED	0x00000001
#define TPM11_VOL_PRES_CLEARABLE	0x00000002
#define TPM11_VOL_PRES			0x00000004
#define TPM11_VOL_PRES_LOCK		0x00000008

#endif
