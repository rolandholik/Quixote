# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************


# Variable declarations.
CC=gcc

RANLIB = ranlib

PLATFORM = -mno-red-zone -O1 -fno-omit-frame-pointer -fno-pie \
	-fno-stack-protector -fno-exceptions -fno-asynchronous-unwind-tables
