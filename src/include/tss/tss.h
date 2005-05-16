
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _TSS_H_
#define _TSS_H_

#include <wchar.h>

#include <tss/tcpa_types.h>
#include <tss/spi_exports.h>
#include <tss/tcs_exports.h>
#include <tss/tcpa_literals.h>
#include <tss/spi_literals.h>

/* Return codes */

/* Layer bits */
#define TSS_ERROR_LAYER_TPM		0x00
#define TSS_ERROR_LAYER_TDDL		0x01
#define TSS_ERROR_LAYER_TCS		0x02
#define TSS_ERROR_LAYER_TSP		0x03

#define TSS_ERROR_LAYER_MASK		0x3000

/* These encode the layer information in a return code */
#define TPMerr(x)	(x | 0x0000000000000000)
#define TDDLerr(x)	(x | 0x0000000000001000)
#define TCSerr(x)	(x | 0x0000000000002000)
#define TSPerr(x)	(x | 0x0000000000003000)

/* TSS rets defined in TSS spec 1.1 pg. 41 */
#define TSS_SUCCESS			0
#define TSS_E_FAIL			TSPerr(1)
#define TSS_E_BAD_PARAMETER		TSPerr(2)
#define TSS_E_INTERNAL_ERROR		TSPerr(3)
#define TSS_E_NOTIMPL			TSPerr(4)
#define TSS_E_PS_KEY_NOTFOUND		TSPerr(5)
#define TSS_E_KEY_ALREADY_REGISTERED	TSPerr(6)
#define TSS_E_PS_KEY_EXISTS		TSS_E_KEY_ALREADY_REGISTERED
#define TSS_E_CANCELLED			TSPerr(7)
#define TSS_E_CANCELED			TSS_E_CANCELLED
#define TSS_E_TIMEOUT			TSPerr(8)
#define TSS_E_OUTOFMEMORY		TSPerr(9)
#define TSS_E_TPM_UNEXPECTED		TSPerr(10)
#define TSS_E_COMM_FAILURE		TSPerr(11)
#define TSS_E_TPM_UNSUPPORTED_FEATURE	TSPerr(12)

/* TSP rets defined in TSS spec 1.1 pg 65 */
#define TSS_E_INVALID_OBJECT_TYPE	TSPerr(13)
#define TSS_E_INVALID_OBJECT_INIT_FLAG	TSPerr(14)
#define TSS_E_INVALID_HANDLE		TSPerr(15)
#define TSS_E_NO_CONNECTION		TSPerr(16)
#define TSS_E_CONNECTION_FAILED		TSPerr(17)
#define TSS_E_CONNECTION_BROKEN		TSPerr(18)
#define TSS_E_HASH_INVALID_ALG		TSPerr(19)
#define TSS_E_HASH_INVALID_LENGTH	TSPerr(20)
#define TSS_E_HASH_NO_DATA		TSPerr(21)
#define TSS_E_SILENT_CONTEXT		TSPerr(22)
#define TSS_E_INVALID_ATTRIB_FLAG	TSPerr(23)
#define TSS_E_INVALID_ATTRIB_SUBFLAG	TSPerr(24)
#define TSS_E_INVALID_ATTRIB_DATA	TSPerr(25)
#define TSS_E_NO_PCRS_SET		TSPerr(26)
#define TSS_E_KEY_NOT_LOADED		TSPerr(27)
#define TSS_E_KEY_NOT_SET		TSPerr(28)
#define TSS_E_VALIDATION_FAILED		TSPerr(29)
#define TSS_E_EK_CHECKSUM		TSS_E_VALIDATION_FAILED
#define TSS_E_TSP_AUTHREQUIRED		TSPerr(30)
#define TSS_E_TSP_AUTH2REQUIRED		TSPerr(31)
#define TSS_E_TSP_AUTHFAIL		TSPerr(32)
#define TSS_E_TSP_AUTH2FAIL		TSPerr(33)
#define TSS_E_KEY_NO_MIGRATION_POLICY	TSPerr(34)
#define TSS_E_POLICY_NO_SECRET		TSPerr(35)
#define TSS_E_INVALID_OBJ_ACCESS	TSPerr(36)
#define TSS_E_INVALID_ENCSCHEME		TSPerr(37)
#define TSS_E_INVALID_SIGSCHEME		TSPerr(38)
#define TSS_E_ENC_INVALID_LENGTH	TSPerr(39)
#define TSS_E_ENC_NO_DATA		TSPerr(40)
#define TSS_E_ENC_INVALID_TYPE		TSPerr(41)
#define TSS_E_INVALID_KEYUSAGE		TSPerr(42)
#define TSS_E_VERIFICATION_FAILED	TSPerr(43)
#define TSS_E_HASH_NO_IDENTIFIER	TSPerr(44)

/* TDDL rets defined in TSS spec 1.1 pg. 306 */
#define TDDL_SUCCESS			TSS_SUCCESS
#define TDDL_E_FAIL			TDDLerr(1)
#define TDDL_E_BAD_PARAMETER		TDDLerr(2)
#define TDDL_E_COMPONENT_NOT_FOUND	TDDLerr(3)
#define TDDL_E_ALREADY_OPENED		TDDLerr(4)
#define TDDL_E_BADTAG			TDDLerr(5)
#define TDDL_E_TIMEOUT			TDDLerr(6)
#define TDDL_E_INSUFFICIENT_BUFFER	TDDLerr(7)
#define TDDL_COMMAND_COMPLETED		TDDLerr(8)
#define TDDL_E_OUTOFMEMORY		TDDLerr(9)
#define TDDL_E_ALREADY_CLOSED		TDDLerr(10)
#define TDDL_E_IOERROR			TDDLerr(11)
#define TDDL_E_COMMAND_ABORTED		TDDLerr(12)

/* TCS rets defined in TSS spec 1.1 pg. 198 */
#define TCS_SUCCESS			TSS_SUCCESS
#define TCS_E_FAIL			TCSerr(1)
#define TCS_E_KEY_MISMATCH		TCSerr(2)
#define TCS_E_KM_LOADFAILED		TCSerr(3)
#define TCS_E_KEY_CONTEXT_RELOAD	TCSerr(4)
#define TCS_E_INVALID_CONTEXTHANDLE	TCSerr(5)
#define TCS_E_INVALID_KEYHANDLE		TCSerr(6)
#define TCS_E_INVALID_AUTHHANDLE	TCSerr(7)
#define TCS_E_INVALID_AUTHSESSION	TCSerr(8)
#define TCS_E_INVALID_KEY		TCSerr(9)
#define TCS_E_KEY_NOT_REGISTERED	TCSerr(10)
#define TCS_E_KEY_ALREADY_REGISTERED	TCSerr(11)

#define NULL_HOBJECT	0
#define NULL_HCONTEXT	NULL_HOBJECT
#define NULL_HKEY	NULL_HOBJECT
#define NULL_HTPM	NULL_HOBJECT
#define NULL_HPOLICY	NULL_HOBJECT
#define NULL_HENCDATA	NULL_HOBJECT
#define NULL_HPCRS	NULL_HOBJECT
#define NULL_HHASH	NULL_HOBJECT

extern TSS_UUID NULL_UUID;
extern TSS_UUID SRK_UUID;

#endif
