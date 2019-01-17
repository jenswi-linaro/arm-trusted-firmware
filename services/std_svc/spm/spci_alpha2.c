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

/*
 * Return the TX of source id in x7 for a TX buffer.
 * Return the RX of target id in x7 for a RX buffer.
 */
static spci_buf_t *spci_msg_buf_ptr_get(unsigned int buf_type,
					uint32_t attrs,
					unsigned int target_ss,
					unsigned int source_ss,
					uint64_t x7)
{
	unsigned short source_id, target_id;
	sp_context_t *ctx;
	unsigned int linear_id, msg_loc;

	/*
	 * TODO: Assume source and target ids is 0. Other bits are unused and
	 * MBZ
	 */
	assert (x7 == 0);

	/*
	 * TODO: It is assumed that there is a single SP (OP-TEE) and single
	 * client (OS) in the Normal world. Both have an id = 0. The security
	 * state bit is used to distinguish which is which. In case of a TX
	 * buffer, the identity of its owner is determined through the client id
	 * bits as per the SMC calling convention. For an RX buffer, the
	 * identity of its owner is specified in the Secure OS ID bits.
	 */
	source_id = x7 >> CLIENT_ID_SHIFT;
	source_id &= CLIENT_ID_MASK;

	if (source_id != 0) {
		ERROR("Invalid source id\n");
		return NULL;
	}

	target_id = x7 >> SEC_OS_ID_SHIFT;
	target_id &= SEC_OS_ID_MASK;

	if (target_id != 0) {
		ERROR("Invalid target id\n");
		return NULL;
	}

	/* Obtain reference to a RX/TX buffer based upon specified parameters */
	switch (buf_type) {
	case SPCI_BUF_TX:

		/*
		 * If the client is a SP then determine if a pointer to the
		 * secure or non-secure TX buffer must be returned.
		 */
		if (source_ss == SECURE) {
			/* Get context of the SP in use by this CPU. */
			linear_id = plat_my_core_pos();
			ctx = spm_cpu_get_sp_ctx(linear_id);

			/* These should match */
			if (source_id != ctx->sp_id) {
				WARN("Mismatched client and SP ids \n");
				return NULL;
			}

			msg_loc = attrs >> SPCI_MSG_SEND_ATTRS_MSGLOC_SHIFT;
			msg_loc &= SPCI_MSG_SEND_ATTRS_MSGLOC_MASK;

			return ctx->msg_bufs[msg_loc][buf_type];

		}

		/* TX buffer of normal world client is easy */
		return (spci_buf_t *) ns_client_buf_desc[source_id][buf_type].va;

	case SPCI_BUF_RX:
		/*
		 * If the target is a SP then determine if pointer to the
		 * secure or non-secure RX buffer must be returned.
		 */
		if (target_ss == SECURE) {
			/*
			 * Now this makes the head spin! If the target is a SP,
			 * then the security state of its RX buffer depends upon
			 * the source security state.
			 */
			msg_loc = (source_ss == SECURE) ?
				SPCI_MSG_SEND_ATTRS_MSGLOC_SEC:
				SPCI_MSG_SEND_ATTRS_MSGLOC_NSEC;

			ctx = &sp_ctx_array[target_id];
			return ctx->msg_bufs[msg_loc][buf_type];
		}

		/* RX buffer of normal world target is easy */
		return (spci_buf_t *) ns_client_buf_desc[target_id][buf_type].va;

	default:
		ERROR("Invalid SPCI message buffer type (%u)\n", buf_type);
		return NULL;
	}
}

/*
 * Complete an SPCI_RUN call in response to a blocking SPCI_MSG_RECV or
 * SPCI_MSG_SEND_RECV from a SP
 */
static int spci_run_end(uint32_t comp_reason, uint16_t msg_target)
{
	int32_t ret;
	sp_context_t *ctx = spm_cpu_get_sp_ctx(plat_my_core_pos());

	switch (comp_reason) {
	case SPCI_RUN_COMP_REASON_DONE_MSG:

		/* Prepare the return status */
		ret = comp_reason << SPCI_RUN_COMP_REASON_SHIFT;
		ret |= (msg_target & SPCI_RUN_MSG_TARGET_MASK) <<
			SPCI_RUN_MSG_TARGET_SHIFT;

		/* Flag Secure Partition as idle. */
		assert(ctx->state == SP_STATE_BUSY);
		sp_state_set(ctx, SP_STATE_IDLE);

		/* Save secure state */
		cm_el1_sysregs_context_save(SECURE);

		/* Restore non-secure state */
		cm_el1_sysregs_context_restore(NON_SECURE);
		cm_set_next_eret_context(NON_SECURE);

		SMC_RET4(cm_get_context(NON_SECURE), ret, 0, 0, 0);
	default:
		/*
		 * TODO: At the moment, the OP-TEE SP will only issue
		 * SPCI_MESG_SEND_RECV.
		 */
		ERROR("Invalid completion reason (%u) \n", comp_reason);
		panic();
	}

	return ret;
}

/* Schedule a SP in response to an SPCI_RUN from Normal world */
static int spci_run_start(uint32_t target_info, uint64_t x7)
{
	int32_t ret;
	unsigned short source_id, target_id;
	sp_context_t *ctx;
	unsigned int linear_id = plat_my_core_pos();

	/*
	 * TODO: It is assumed that there is a single SP (OP-TEE) and single
	 * client (OS) in the Normal world. Both have an id = 0. A quirk of the
	 * specification is that the target is specified in both x7 and
	 * target_info. In future, the latter will be used to identify the
	 * target SP vCPU as well. Currently it is assumed each vCPU is pinned
	 * and identity mapped to the pCPU.
	 */
	source_id = x7 >> CLIENT_ID_SHIFT;
	source_id &= CLIENT_ID_MASK;

	if (source_id != 0) {
		ERROR("Invalid source id\n");
		return SPCI_INVALID_PARAMETER;
	}

	target_id = x7 >> SEC_OS_ID_SHIFT;
	target_id &= SEC_OS_ID_MASK;

	if (target_id != 0) {
		ERROR("Invalid target id\n");
		return SPCI_INVALID_PARAMETER;
	}

	/* Inspite of the spec. quirk, it is worth ensuring the targets match */
	if (target_id != ((target_info >> SEC_OS_ID_SHIFT) & SEC_OS_ID_MASK)) {
		ERROR("Mismatched SP ids\n");
		return SPCI_INVALID_PARAMETER;
	}

	/*
	 * All aboard! Lets save the non-secure state and restore the secure
	 * state.
	 * TODO: In the absence of S-EL2, it is assumed that re-entry into a SP
	 * will be done by completing an earlier SPCI_MESG_RECV or
	 * SPCI_MESG_SEND_RECV call.
	 */
	ctx = &sp_ctx_array[target_id];

	assert (ctx != NULL);
	assert (ctx->state == SP_STATE_IDLE);

	/* This SP is about to become busy */
	sp_state_set(ctx, SP_STATE_BUSY);

	/* Save the Normal world context */
	cm_el1_sysregs_context_save(NON_SECURE);

	/* Assign the context of the SP to this CPU */
	spm_cpu_set_sp_ctx(linear_id, ctx);
	cm_set_context(&(ctx->cpu_ctx), SECURE);

	/* Restore the context assigned above */
	cm_el1_sysregs_context_restore(SECURE);
	cm_set_next_eret_context(SECURE);

	/*
	 * Set 'ret' to indicate status upon completion of a SPCI_MSG_RECV or
	 * SPCI_MESG_SEND_RECV. Message location will always be the non-secure
	 * RX buffer of the SP.
	 */
	ret = SPCI_MSG_RECV_MSGLOC_NSEC << SPCI_MSG_RECV_MSGLOC_SHIFT;
	SMC_RET4(cm_get_context(SECURE), ret, 0, 0, 0);
}

/* Send a message to a client or SP */
static int spci_msg_send(uint32_t attributes,
			 unsigned int ns,
			 uint64_t x7,
			 uint16_t *msg_target)
{
	spci_buf_t *rx_buf, *tx_buf;
	spci_msg_hdr_t *msg_hdr;
	void *tmp;
	uint32_t id, msg_len;

	/* Check against garbage security state parameter */
	assert ((ns == SECURE) || (ns == !SECURE));

	/*
	 * If the caller/source is non-secure then target must be secure.
	 * TODO: Assume that if caller/source is secure then target must be
	 * non-secure. In future it could be another SP as well.
	 */
	tx_buf = spci_msg_buf_ptr_get(SPCI_BUF_TX, attributes, !ns, ns, x7);
	if (tx_buf == NULL) {
		ERROR("Unable to find TX buffer \n");
		return SPCI_INVALID_PARAMETER;
	}

	VERBOSE("%s: Src TX 0x%lx \n", __FUNCTION__, (unsigned long) tx_buf);

	/* Get the common message header */
	tmp = (void *) tx_buf->buf;
	msg_hdr = (spci_msg_hdr_t *) tmp;

	/* Check message length */
	if (msg_hdr->length == 0) {
		ERROR("Invalid zero legnth message\n");
		return SPCI_INVALID_PARAMETER;
	}

	/* Get the message target from x7 */
	id = x7 >> SEC_OS_ID_SHIFT;
	id &= SEC_OS_ID_MASK;

	/* Check if target in x7 matches the target in the message */
	if (msg_hdr->target_sp != id) {
		ERROR("Mismatched target ids in message and w7\n");
		return SPCI_INVALID_PARAMETER;
	}

	*msg_target = id;

	/* Get the message source from x7 */
	id = x7 >> CLIENT_ID_SHIFT;
	id &= CLIENT_ID_MASK;

	/* Check if source in x7 matches the source in the message */
	if (msg_hdr->source_sp != id) {
		ERROR("Mismatched source ids in message and w7\n");
		return SPCI_INVALID_PARAMETER;
	}

	/* Ensure buffer is full */
	if (tx_buf->hdr.state != SPCI_BUF_STATE_FULL) {
		ERROR("Invalid TX buffer state\n");
		return SPCI_INVALID_PARAMETER;
	}

	/*
	 * If the caller/source is non-secure then target must be secure.
	 * TODO: Assume that if caller/source is secure then target must be
	 * non-secure. In future it could be another SP as well.
	 */
	rx_buf = spci_msg_buf_ptr_get(SPCI_BUF_RX, attributes, !ns, ns, x7);
	if (rx_buf == NULL) {
		ERROR("Unable to find TX buffer \n");
		return SPCI_INVALID_PARAMETER;
	}

	VERBOSE("%s: Tgt RX 0x%lx \n", __FUNCTION__, (unsigned long) rx_buf);

	/* Ensure RX buffer is empty */
	if (rx_buf->hdr.state != SPCI_BUF_STATE_EMPTY) {
		WARN("Busy %s RX buffer state\n", ns ? "secure": "non-secure");
		return SPCI_BUSY;
	}

	/* Ensure message length <= space available in message buffer */
	msg_len = msg_hdr->length + sizeof(*msg_hdr);
	if (msg_len > (PAGE_SIZE - sizeof(spci_buf_t))) {
		ERROR("Invalid message length\n");
		return SPCI_INVALID_PARAMETER;
	}

	/* Copy message to from TX to RX */
	memcpy((void *) rx_buf->buf, (void *) msg_hdr, msg_len);

	/* Zero message in TX buffer */
	memset((void *) msg_hdr, 0, msg_len);

	/* Mark TX as empty and RX as full */
	rx_buf->hdr.state = SPCI_BUF_STATE_FULL;
	tx_buf->hdr.state = SPCI_BUF_STATE_EMPTY;

	return SPCI_SUCCESS;
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
	unsigned int ns;
	int32_t ret;
	uint16_t msg_target = 0;

	/* Determine which security state this SMC originated from */
	ns = is_caller_non_secure(flags);

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

		/*
		 * If SPCI_MESG_RECV was invoked in polling mode then success
		 * indicates a return back to the SP. Else it indicates a return
		 * back to the Normal world.
		 */
		if ((ret == SPCI_SUCCESS) && (blk == SPCI_MSG_RECV_ATTRS_BLK))
			return spci_run_end(SPCI_RUN_COMP_REASON_DONE, 0);

		SMC_RET1(handle, ret);
	}
	case SPCI_MSG_BUF_LIST_EXCHANGE:
		ret = spci_msg_buf_list_exchange(x1, x2);
		SMC_RET1(handle, ret);

	case SPCI_MSG_SEND:
		ret = spci_msg_send(x1, ns, SMC_GET_GP(handle, CTX_GPREG_X7),
				    &msg_target);

		SMC_RET1(handle, ret);

	case SPCI_MSG_SEND_RECV:
		if (ns)
			break;
		ret = spci_msg_send(x1, ns, SMC_GET_GP(handle, CTX_GPREG_X7),
				    &msg_target);

		/*
		 * If the message was sent successfully then tell the Normal
		 * world scheduler that a scheduling decision must be made.
		 */
		if (ret == SPCI_SUCCESS)
			return spci_run_end(SPCI_RUN_COMP_REASON_DONE_MSG,
					    msg_target);

		SMC_RET1(handle, ret);

	case SPCI_RUN:
		if (!ns)
			break;
		return spci_run_start(x1, SMC_GET_GP(handle, CTX_GPREG_X7));

	default:
		break;
	}

	WARN("SPM: Unsupported call 0x%08x\n", smc_fid);
	SMC_RET1(handle, SPCI_NOT_SUPPORTED);
}
