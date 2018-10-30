/*
 * Copyright (c) 2018, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __SPCI_H__
#define __SPCI_H__

#include <utils_def.h>

#define SPCI_VERSION_MAJOR		U(0)
#define SPCI_VERSION_MAJOR_SHIFT	16
#define SPCI_VERSION_MAJOR_MASK		U(0x7FFF)
#define SPCI_VERSION_MINOR		U(1)
#define SPCI_VERSION_MINOR_SHIFT	0
#define SPCI_VERSION_MINOR_MASK		U(0xFFFF)
#define SPCI_VERSION_FORM(major, minor)	((major << SPCI_VERSION_MAJOR_SHIFT) | \
					 (minor))
#define SPCI_VERSION_COMPILED		SPCI_VERSION_FORM(SPCI_VERSION_MAJOR, \
							  SPCI_VERSION_MINOR)

/* The macros below are used to identify SPCI calls from the SMC function ID */
#define SPCI_FID_MASK			U(0xffff)
#define SPCI_FID_MIN_VALUE		U(0x60)
#define SPCI_FID_MAX_VALUE		U(0x7f)
#define is_spci_fid(_fid)						\
		((((_fid) & SPCI_FID_MASK) >= SPCI_FID_MIN_VALUE) &&	\
		 (((_fid) & SPCI_FID_MASK) <= SPCI_FID_MAX_VALUE))

#define SPCI_VERSION			U(0x84000060)
#define SPCI_HANDLE_OPEN		U(0x84000061)
#define SPCI_HANDLE_CLOSE		U(0x84000062)
#define SPCI_SHM_REGISTER_32		U(0x84000063)
#define SPCI_SHM_REGISTER_64		U(0xC4000063)
#define SPCI_SHM_UNREGISTER_32		U(0x84000064)
#define SPCI_SHM_UNREGISTER_64		U(0xC4000064)
#define SPCI_SHM_LIST_GET_32		U(0x84000065)
#define SPCI_SHM_LIST_GET_64		U(0xC4000065)
#define SPCI_REQUEST_BLOCKING_32	U(0x84000066)
#define SPCI_REQUEST_BLOCKING_64	U(0xC4000066)
#define SPCI_REQUEST_START_32		U(0x84000067)
#define SPCI_REQUEST_START_64		U(0xC4000067)
#define SPCI_REQUEST_RESUME_32		U(0x8400006b)
#define SPCI_REQUEST_RESUME_64		U(0xC400006b)
#define SPCI_GET_RESPONSE_32		U(0x84000068)
#define SPCI_GET_RESPONSE_64		U(0xC4000068)
#define SPCI_RESET_CLIENT_STATE_32	U(0x84000069)
#define SPCI_RESET_CLIENT_STATE_64	U(0xC4000069)
#define SPCI_REQUEST_START_BY_VAL_32	U(0x8400006a)
#define SPCI_REQUEST_START_BY_VAL_64	U(0xC400006a)
#define SPCI_REQUEST_BLOCKING_BY_VAL_32	U(0x8400006c)
#define SPCI_REQUEST_BLOCKING_BY_VAL_64	U(0xC400006c)

#define SPCI_RES_TYPE_BASE_ADDR		0
#define SPCI_RES_TYPE_ATTR_SIZE		1
#define SPCI_RES_TYPE_UUID_LOWER	2
#define SPCI_RES_TYPE_UUID_UPPER	3

/*
 * Get resource. Resources are arranged in a two dimensional matrix where
 * resource type selects the column and rows are selected by an index.
 *
 * UUID is identifying a SP with which messages can be exchanged through
 * this memory region. A SP is permitted to be associated with multiple
 * such memory regions.
 *
 * Call register usage:
 * w0	SMC Function ID, SPCI_RES_GET
 * w1	Index of resource (row)
 * w2	Resource type (column), one of SPCI_RES_TYPE_* above
 * w7	bits[31:16] MBZ
 *	bits[15:0]  Client ID as defined in Section 3.1 or [5] or MBZ
 *
 * Return register usage (all resource types):
 * w0	Error code:
 *	SPCI_SUCCESS success, valid data
 *	SPCI_NOT_PRESENT selected index is not available, invalid data
 *	SPCI_INVALID_PARAMETER index beyond max valid index, invalid data
 *
 * Return register usage resource type SPCI_RES_TYPE_BASE_ADDR
 * w1	Upper 32 bits of physical base address of memory region
 * w2	Lower 32 bits of physical base address of memory region, aligned to
 *	the to the maximum translation granule size specified in the
 *	ID_AA64MMFR0_EL1 system register.
 *
 * Return register usage resource type SPCI_RES_TYPE_ATTR_SIZE
 * w1	Attributes
 *	- bits[31:13]: Reserved (MBZ)
 *	- bits[12:11]: Granularity
 *			- b'00: 4KB
 *			- b'01: 16KB
 *			- b'10: 64KB
 *			- b'11: Reserved
 *	- bits[10:0] : Memory attributes
 *	     – bit[10]: Memory Type
 *		  - b’0: Normal Memory.
 *		       - Write-Back Cacheable.
 *		       - Non-transient Read-Allocate.
 *		       - Non-transient Write-Allocate.
 *		       - Inner Shareable.
 *		       - Read-Write.
 *		  - b’0: Reserved (bits[9:0] MBZ)
 *	     – bit[9:0]: Reserved. MBZ
 * w2	Upper 32 bits of size of memory region
 * w3	Lower 32 bits of size of memory region
 *
 * Return register usage resource type SPCI_RES_TYPE_UUID_LOWER
 * w1	UUID bytes 0...3 with byte 0 in the low-order bits
 * w2	UUID bytes 4...7 with byte 4 in the low-order bits
 *
 * Return register usage resource type SPCI_RES_TYPE_UUID_UPPER
 * w1	UUID bytes 8...11 with byte 8 in the low-order bits
 * w2	UUID bytes 12...15 with byte 12 in the low-order bits
 */
#define SPCI_GET_RESOURCE		U(0x8400006d)

/*
 * Get information on a registered shared memory handle.
 *
 * Call register usage:
 * w0	SMC Function ID, SPCI_GET_SHM_INFO
 * w1	shm handle
 *
 * Normal return register usage:
 * w0	SPCI_SUCCESS
 * w1	Upper 32 bits of addr of shared memory block
 * w2	Lower 32 bits of addr of shared memory block
 * w3	Number of pages where page size is defined in the attributes of
 *	shared memory region table
 *
 * Error return register usage:
 * w0	SPCI_INVALID_PARAMETER is the shared memory handle doesn't exist or
 *	is in the process of being removed
 */
#define SPCI_GET_SHM_INFO		U(0x8400006e)

#define SPCI_SHM_HANDLE_INVALID	0xffffffff

/* SPCI error codes. */
#define SPCI_SUCCESS		0
#define SPCI_NOT_SUPPORTED	-1
#define SPCI_INVALID_PARAMETER	-2
#define SPCI_NO_MEMORY		-3
#define SPCI_BUSY		-4
#define SPCI_QUEUED		-5
#define SPCI_DENIED		-6
#define SPCI_NOT_PRESENT	-7

#ifndef __ASSEMBLY__

#include <stdint.h>

uintptr_t spci_smc_handler(uint32_t smc_fid, u_register_t x1, u_register_t x2,
			   u_register_t x3, u_register_t x4, void *cookie,
			   void *handle, u_register_t flags);


#endif /* __ASSEMBLY__ */

#endif /* __SPCI_H__ */
