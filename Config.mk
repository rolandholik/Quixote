# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

#
# This file contains global package definitions to be used for
# the build process.  Site specific modifications should be in
# the Build.mk file.
#

# Compiler selection.
CC ?= musl-gcc

# Kernel version selection.
# export KERNEL_VERSION=5.4
export KERNEL_VERSION=6.1
