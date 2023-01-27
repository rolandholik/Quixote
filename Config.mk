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

# Generic compiler flags to use for the build.
BUILD_CFLAGS = -O2 -fomit-frame-pointer -march=core2 -Wall

# Default linker flags.
ifeq (${CC}, musl-gcc)
BUILD_LDFLAGS = -Wl,-rpath-link=/usr/local/musl/lib -L ${TOPDIR}/HurdLib
endif

ifdef STATIC
BUILD_LDFLAGS += -static
endif

# ELF library location.
BUILD_ELFLIB = $(shell pkg-config libelf --libs)

# SSL library location.
BUILD_LIBCRYPTO = $(shell pkg-config libcrypto --libs)

# Kernel version selection.
KERNEL_VERSION = 6.1

export CC KERNEL_VERSION BUILD_LDFLAGS BUILD_ELFLIB BUILD_LIBCRYPTO


#
# The Build.mk file must exist and is used to implement site specific
# modifications for the build directives.
#
ifeq (${BUILD_CONFIG},"true")
include ${TOPDIR}/Build.mk
endif
