# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/


#
# The following section defines the default configuration directives
# for the build.
#

# Compiler selection.
CC = musl-gcc

# Kernel version selection.
KERNEL_VERSION = 6.1

export CC KERNEL_VERSION


#
# The Build.mk file must exist and is used to implement site specific
# modifications for the build directives.
#
ifeq (${BUILD_CONFIG},"true")
include ${TOPDIR}/Build.mk
endif
