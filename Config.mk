# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

#
# This file defines build rules.  The Build.mk file, which must exist,
# is used to implement build or site specific modifications.
#
ifeq (${BUILD_CONFIG},"true")
include ${TOPDIR}/Build.mk
endif

# Compiler selection.
CC ?= musl-gcc

# Kernel version selection.
KERNEL_VERSION ?= 6.1

export CC KERNEL_VERSION
