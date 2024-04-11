# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************

TOOLDIR = ${BUILD_ARM_TOOLDIR}

NORDICDIR = ${BUILD_NORDIC_DIR}
RTOSDIR	  = ${NORDICDIR}/external/freertos
MBEDDIR	  = ${BUILD_MBEDDIR}
LIBDIR	  = ${TOOLDIR}/lib/arm-none-eabi/lib

CC	= ${TOOLDIR}/bin/arm-none-eabi-gcc
AS	= ${TOOLDIR}/bin/arm-none-eabi-as
RANLIB	= ${TOOLDIR}/bin/arm-none-eabi-ranlib
OBJCOPY = ${TOOLDIR}/bin/arm-none-eabi-objcopy

PLATFORM = -mcpu=cortex-m4 -mthumb -mabi=aapcs -mfloat-abi=hard \
	-mfpu=fpv4-sp-d16 -O2

PROGRAMMER = ${TOOLDIR}/bin/nordic-programmer
