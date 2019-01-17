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
	default:
		break;
	}

	WARN("SPM: Unsupported call 0x%08x\n", smc_fid);
	SMC_RET1(handle, SPCI_NOT_SUPPORTED);
}
