/*
 * Copyright (c) 2018, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <context_mgmt.h>
#include <common/debug.h>
#include <errno.h>
#include <platform.h>
#include <smccc.h>
#include <smccc_helpers.h>
#include <spci_alpha2.h>
#include <spinlock.h>
#include <string.h>
#include <utils.h>

#include "spm_private.h"

/*
 * Data structure to stash buffer description of each NS client.
 * TODO: Remove assumption of a single client.
 */
buf_desc_t ns_client_buf_desc[PLAT_SPM_MAX_CLIENTS][SPCI_MAX_BUFS];

/* Receive a list of message buffers from a client */
static int spci_msg_buf_list_exchange(uint64_t address,
				      uint32_t size)
{
	int32_t ret = SPCI_SUCCESS;
	uintptr_t va, pa;
	spci_buf_info_table_t *buf_info_tbl;
	spci_buf_info_desc_t *buf_info_desc;
	spci_buf_t *buf;
	spci_buf_hdr_t buf_hdr;
	unsigned int ctr, cnt, buf_pages, buf_gran;

	/* TODO: Free memory regions in case of an error */

	/* TODO: Validate address if not already done in below function */
	ret = mmap_add_dynamic_region_alloc_va(address,
					       &va,
					       size,
					       MT_MEMORY | MT_RW | MT_NS);
	if (ret < 0) {
		ERROR("Error while mapping buf info table (%d).\n", ret);
		return SPCI_NO_MEMORY;
	}

	buf_info_tbl = (spci_buf_info_table_t *) va;

	/* Validate the signature of the table */
	if (memcmp((void *) buf_info_tbl->signature,
		   SPCI_BUF_TABLE_SIGNATURE,
		   MAX_SIG_LENGTH)) {
		ERROR("Invalid buf info table signature\n");
		return SPCI_INVALID_PARAMETER;
	}

	/* Validate the length of the table */
	cnt = sizeof(spci_buf_info_table_t);
	cnt += buf_info_tbl->buf_cnt * sizeof(spci_buf_info_desc_t);

	if ((buf_info_tbl->length > size) || (buf_info_tbl->length != cnt)) {
		ERROR("Invalid buf info table length\n");
		return SPCI_INVALID_PARAMETER;
	}

	/* Validate version of the table */
	if (buf_info_tbl->version != 0) {
		ERROR("Invalid buf info table version\n");
		return SPCI_INVALID_PARAMETER;
	}

	/* Get number of pages allocated for each buffer */
	buf_pages =
		((buf_info_tbl->attributes >> SPCI_BUF_TABLE_ATTR_PGCNT_SHIFT)	\
		 & SPCI_BUF_TABLE_ATTR_PGCNT_MASK);

	/* TODO: Assume that each buffer occupies a single page */
	if (buf_pages != 1) {
		ERROR("Invalid buf page count\n");
		return SPCI_INVALID_PARAMETER;
	}

	/* Get granularity at which pages have been allocated for each buffer */
	buf_gran =
		((buf_info_tbl->attributes >> SPCI_BUF_TABLE_ATTR_GRAN_SHIFT)	\
		 & SPCI_BUF_TABLE_ATTR_GRAN_MASK);

	/* TODO: Assume 4K granularity */
	if (buf_gran != SPCI_BUF_TABLE_ATTR_GRAN_4K) {
		ERROR("Invalid buf page count\n");
		return SPCI_INVALID_PARAMETER;
	}

	/*
	 * Populate NS client message buffer descriptors.
	 * TODO: Loop assumes single client with 2 buffers
	 */
	buf_info_desc = buf_info_tbl->payload;
	cnt = buf_info_tbl->buf_cnt;
	if (cnt > SPCI_MAX_BUFS * PLAT_SPM_MAX_CLIENTS) {
		ERROR("Invalid buffer count\n");
		return SPCI_INVALID_PARAMETER;
	}

	for (ctr = 0; ctr < cnt; ctr++) {
		uint16_t buf_type, id;

		id = buf_info_desc[ctr].id;
		if (id != 0) {
			ERROR("Invalid client id (%u)\n", id);
			return SPCI_INVALID_PARAMETER;
		}

		/* TODO: Not considering the uuid for now */

		buf_type = buf_info_desc[ctr].flags;
		buf_type >>= SPCI_BUF_DESC_FLAG_TYPE_SHIFT;
		buf_type &= SPCI_BUF_DESC_FLAG_TYPE_MASK;

		pa = buf_info_desc[ctr].address;
		ret = mmap_add_dynamic_region_alloc_va(pa,
						       &va,
						       buf_pages * PAGE_SIZE,
						       MT_MEMORY | MT_RW | MT_NS);
		if (ret < 0) {
			ERROR("Error mapping %s buf@0x%lx\n",
			      buf_type ? "TX": "RX", (unsigned long) pa);
			return SPCI_NO_MEMORY;
		}

		buf = (spci_buf_t *) va;
		buf_hdr = buf->hdr;
		/* Validate the signature of the buffer */
		if (memcmp((void *) buf_hdr.signature,
			   SPCI_BUF_SIGNATURE,
			   MAX_SIG_LENGTH)) {
			ERROR("Invalid %s buf signature\n",
			      buf_type ? "TX": "RX");
			return SPCI_INVALID_PARAMETER;
		}

		INFO("Client %d %s buf mapped@0x%lx \n", id,
		     buf_type ? "TX": "RX", (unsigned long) va);

		ns_client_buf_desc[id][buf_type].pa = pa;
		ns_client_buf_desc[id][buf_type].va = va;
	}

	/* Remove SPCI buffer info table mapping */
	ret = mmap_remove_dynamic_region((uintptr_t) buf_info_tbl, size);
	if (ret != 0) {
		ERROR("Unable to remove buf info table@0x%lx (%d)\n",
		      (unsigned long) buf_info_tbl, ret);
		panic();
	}

	return ret;
}

/* Receive a message from a client or SP */
static int spci_msg_recv(uint32_t attributes)
{
	int32_t ret = SPCI_SUCCESS;
	unsigned int linear_id;
	sp_context_t *ctx;
	spci_buf_t *rx_buf;

	/* Get context of the SP in use by this CPU. */
	linear_id = plat_my_core_pos();
	ctx = spm_cpu_get_sp_ctx(linear_id);

	/* Get reference to current SP's RX buffer */
	rx_buf = ctx->msg_bufs[SECURE][SPCI_BUF_RX];

	if (ctx->state == SP_STATE_RESET) {
		if (rx_buf->hdr.state != SPCI_BUF_STATE_EMPTY)
			WARN("Non empty RX buffer after SP initialisation\n");

		spm_sp_synchronous_exit(!ret);
	}

	ERROR("Unexpected SP state 0x%x\n", ctx->state);
	panic();
	return ret;
}

/*******************************************************************************
 * This function handles all SMCs in the range reserved for SPCI.
 ******************************************************************************/
uint64_t spm_smc_handler(uint32_t smc_fid, uint64_t x1, uint64_t x2,
			 uint64_t x3, uint64_t x4, void *cookie, void *handle,
			 uint64_t flags)
{
	int32_t ret;

	switch (smc_fid) {

	case SPCI_VERSION:
		ret = SPCI_VERSION_COMPILED;
		SMC_RET1(handle, ret);

	case SPCI_MSG_RECV:
	{
		unsigned int blk;

		blk = x1 >> SPCI_MSG_RECV_ATTRS_SHIFT;
		blk &= SPCI_MSG_RECV_ATTRS_MASK;
		ret = spci_msg_recv(blk);
		SMC_RET1(handle, ret);
	}
	case SPCI_MSG_BUF_LIST_EXCHANGE:
		ret = spci_msg_buf_list_exchange(x1, x2);
		SMC_RET1(handle, ret);

	default:
		break;
	}

	WARN("SPM: Unsupported call 0x%08x\n", smc_fid);
	SMC_RET1(handle, SPCI_NOT_SUPPORTED);
}
