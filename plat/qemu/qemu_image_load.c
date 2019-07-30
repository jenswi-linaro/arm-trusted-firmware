/*
 * Copyright (c) 2017, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <common/desc_image_load.h>

/*******************************************************************************
 * This function is a wrapper of a common function which flushes the data
 * structures so that they are visible in memory for the next BL image.
 ******************************************************************************/
void plat_flush_next_bl_params(void)
{
	flush_bl_params_desc();
}

/*******************************************************************************
 * This function is a wrapper of a common function which returns the list of
 * loadable images.
 ******************************************************************************/
bl_load_info_t *plat_get_bl_image_load_info(void)
{
	return get_bl_load_info_from_mem_params_desc();
}

/*******************************************************************************
 * This function is a wrapper of a common function which returns the data
 * structures of the next BL image.
 ******************************************************************************/
bl_params_t *plat_get_next_bl_params(void)
{
	bl_params_t *next_bl_params = get_next_bl_params_from_mem_params_desc();

#if ENABLE_SPCI_ALPHA2
	populate_next_bl_params_config(next_bl_params);
#endif
	return next_bl_params;
}
