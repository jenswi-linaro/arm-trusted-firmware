/*
 * Copyright (c) 2013-2014, ARM Limited and Contributors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of ARM nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <arch_helpers.h>
#include <assert.h>
#include <bl_common.h>
#include <context_mgmt.h>
#include <debug.h>
#include <platform.h>
#include <optee.h>
#include "opteed_private.h"

/*******************************************************************************
 * The target cpu is being turned on. Allow the OPTEED/OPTEE to perform any
 * actions needed. Nothing at the moment.
 ******************************************************************************/
static void opteed_cpu_on_handler(uint64_t target_cpu)
{
}

/*******************************************************************************
 * This cpu is being turned off. Allow the OPTEED/OPTEE to perform any actions
 * needed
 ******************************************************************************/
static int32_t opteed_cpu_off_handler(uint64_t cookie)
{
	int32_t rc = 0;
	uint64_t mpidr = read_mpidr();
	uint32_t linear_id = platform_get_core_pos(mpidr);
	optee_context_t *optee_ctx = &opteed_sp_context[linear_id];

	assert(optee_vectors);
	assert(get_optee_pstate(optee_ctx->state) == OPTEE_PSTATE_ON);

	/* Program the entry point and enter OPTEE */
	cm_set_elr_el3(SECURE, (uint64_t) &optee_vectors->cpu_off_entry);
	rc = opteed_synchronous_sp_entry(optee_ctx);

	/*
	 * Read the response from OPTEE. A non-zero return means that
	 * something went wrong while communicating with OPTEE.
	 */
	if (rc != 0)
		panic();

	/*
	 * Reset OPTEE's context for a fresh start when this cpu is turned on
	 * subsequently.
	 */
	set_optee_pstate(optee_ctx->state, OPTEE_PSTATE_OFF);

	 return 0;
}

/*******************************************************************************
 * This cpu is being suspended. S-EL1 state must have been saved in the
 * resident cpu (mpidr format) if it is a UP/UP migratable OPTEE.
 ******************************************************************************/
static void opteed_cpu_suspend_handler(uint64_t power_state)
{
	int32_t rc = 0;
	uint64_t mpidr = read_mpidr();
	uint32_t linear_id = platform_get_core_pos(mpidr);
	optee_context_t *optee_ctx = &opteed_sp_context[linear_id];

	assert(optee_vectors);
	assert(get_optee_pstate(optee_ctx->state) == OPTEE_PSTATE_ON);

	/* Program the entry point, power_state parameter and enter OPTEE */
	write_ctx_reg(get_gpregs_ctx(&optee_ctx->cpu_ctx),
		      CTX_GPREG_X0,
		      power_state);
	cm_set_elr_el3(SECURE, (uint64_t) &optee_vectors->cpu_suspend_entry);
	rc = opteed_synchronous_sp_entry(optee_ctx);

	/*
	 * Read the response from OPTEE. A non-zero return means that
	 * something went wrong while communicating with OPTEE.
	 */
	if (rc != 0)
		panic();

	/* Update its context to reflect the state OPTEE is in */
	set_optee_pstate(optee_ctx->state, OPTEE_PSTATE_SUSPEND);
}

/*******************************************************************************
 * This cpu has been turned on. Enter OPTEE to initialise S-EL1 and other bits
 * before passing control back to the Secure Monitor. Entry in S-El1 is done
 * after initialising minimal architectural state that guarantees safe
 * execution.
 ******************************************************************************/
static void opteed_cpu_on_finish_handler(uint64_t cookie)
{
	int32_t rc = 0;
	uint64_t mpidr = read_mpidr();
	uint32_t linear_id = platform_get_core_pos(mpidr);
	optee_context_t *optee_ctx = &opteed_sp_context[linear_id];

	assert(optee_vectors);
	assert(get_optee_pstate(optee_ctx->state) == OPTEE_PSTATE_OFF);

	/* Initialise this cpu's secure context */
	opteed_init_secure_context((uint64_t)&optee_vectors->cpu_on_entry,
				   opteed_rw, mpidr, optee_ctx);

	/* Enter OPTEE */
	rc = opteed_synchronous_sp_entry(optee_ctx);

	/*
	 * Read the response from OPTEE. A non-zero return means that
	 * something went wrong while communicating with OPTEE.
	 */
	if (rc != 0)
		panic();

	/* Update its context to reflect the state OPTEE is in */
	set_optee_pstate(optee_ctx->state, OPTEE_PSTATE_ON);
}

/*******************************************************************************
 * This cpu has resumed from suspend. The OPTEED saved the OPTEE context when it
 * completed the preceding suspend call. Use that context to program an entry
 * into OPTEE to allow it to do any remaining book keeping
 ******************************************************************************/
static void opteed_cpu_suspend_finish_handler(uint64_t suspend_level)
{
	int32_t rc = 0;
	uint64_t mpidr = read_mpidr();
	uint32_t linear_id = platform_get_core_pos(mpidr);
	optee_context_t *optee_ctx = &opteed_sp_context[linear_id];

	assert(optee_vectors);
	assert(get_optee_pstate(optee_ctx->state) == OPTEE_PSTATE_SUSPEND);

	/* Program the entry point, suspend_level and enter the SP */
	write_ctx_reg(get_gpregs_ctx(&optee_ctx->cpu_ctx),
		      CTX_GPREG_X0,
		      suspend_level);
	cm_set_elr_el3(SECURE, (uint64_t) &optee_vectors->cpu_resume_entry);
	rc = opteed_synchronous_sp_entry(optee_ctx);

	/*
	 * Read the response from OPTEE. A non-zero return means that
	 * something went wrong while communicating with OPTEE.
	 */
	if (rc != 0)
		panic();

	/* Update its context to reflect the state OPTEE is in */
	set_optee_pstate(optee_ctx->state, OPTEE_PSTATE_ON);
}

/*******************************************************************************
 * Return the type of OPTEE the OPTEED is dealing with. Report the current
 * resident cpu (mpidr format) if it is a UP/UP migratable OPTEE.
 ******************************************************************************/
static int32_t opteed_cpu_migrate_info(uint64_t *resident_cpu)
{
	return OPTEE_MIGRATE_INFO;
}

/*******************************************************************************
 * Structure populated by the OPTEE Dispatcher to be given a chance to
 * perform any OPTEE bookkeeping before PSCI executes a power mgmt.
 * operation.
 ******************************************************************************/
const spd_pm_ops_t opteed_pm = {
	opteed_cpu_on_handler,
	opteed_cpu_off_handler,
	opteed_cpu_suspend_handler,
	opteed_cpu_on_finish_handler,
	opteed_cpu_suspend_finish_handler,
	NULL,
	opteed_cpu_migrate_info
};

