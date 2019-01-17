#
# Copyright (c) 2017-2018, ARM Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

ifneq (${SPD},none)
        $(error "Error: SPD and SPM are incompatible build options.")
endif
ifneq (${ARCH},aarch64)
        $(error "Error: SPM is only supported on aarch64.")
endif

include lib/sprt/sprt_host.mk

ifeq (${ENABLE_SPCI_ALPHA2},1)
SPM_SOURCES	+=	$(addprefix services/std_svc/spm/,	\
			${ARCH}/spm_helpers.S			\
			spci_alpha2.c				\
			spm_main.c				\
			spm_xlat.c)

else
SPM_SOURCES	:=	$(addprefix services/std_svc/spm/,	\
			${ARCH}/spm_helpers.S			\
			${ARCH}/spm_shim_exceptions.S		\
			spci.c					\
			spm_buffers.c				\
			spm_main.c				\
			spm_setup.c				\
			spm_xlat.c				\
			sprt.c)					\
			${SPRT_LIB_SOURCES}
endif

INCLUDES	+=	${SPRT_LIB_INCLUDES}

ifneq (${ENABLE_SPCI_ALPHA2},1)
# Force SMC Calling Convention 2 when using SPM
SMCCC_MAJOR_VERSION	:=	2
endif

# Let the top-level Makefile know that we intend to include a BL32 image
NEED_BL32		:=	yes
