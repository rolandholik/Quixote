# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/
#
# This file includes make directives that need to be executed after the
# local modifications in the Build.mk file have been applied.  This
# file is automatically added to the Build.mk file rather than being
# soucred by the file.
#

# Default linker flags.
ifeq (${CC}, musl-gcc)
BUILD_LDFLAGS += -Wl,-rpath-link=/usr/local/musl/lib
endif

ifdef BUILD_STATIC
BUILD_LDFLAGS += -static
endif
