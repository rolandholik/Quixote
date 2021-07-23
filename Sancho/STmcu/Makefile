# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************


# Variable declarations.
TOOLDIR = /opt/ESDembedded

CC	= ${TOOLDIR}/bin/arm-none-eabi-gcc
AS	= ${TOOLDIR}/bin/arm-none-eabi-as
RANLIB	= ${TOOLDIR}/bin/arm-none-eabi-ranlib

LIBDIR = ${TOOLDIR}/arm-none-eabi/lib
INCDIR = ${TOOLDIR}/arm-none-eabi/include

PLATFORM = -mthumb -mcpu=cortex-m4 -mfloat-abi=hard -O2 -mfpu=fpv4-sp-d16 \
	-DSTM32L496xx=1

PROGRAMMER = ${TOOLDIR}/bin/stm-programmer

export CC AS RANLIB LIBDIR INCDIR PLATFORM PROGRAMMER


SUBDIRS = HurdLib


#
# Target directives.
#
.PHONY: ${SUBDIRS}


#
# Subdirectory targets.
#
HurdLib:
	${MAKE} -C $@;


#
# Utility targets.
#
clean:
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clean; done;

clobber:
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clobber; done;
