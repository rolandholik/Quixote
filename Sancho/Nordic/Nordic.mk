# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************


# Variable declarations.
TOOLDIR = /opt/ESDembedded

NORDICDIR = /u/usr/src/Development_Nordic/nRF5_SDK_17.1.0_ddde560
RTOSDIR	  = ${NORDICDIR}/external/freertos
MBEDDIR	  = ${NORDICDIR}/external/mbedtls

CC	= ${TOOLDIR}/bin/arm-none-eabi-gcc
AS	= ${TOOLDIR}/bin/arm-none-eabi-as
RANLIB	= ${TOOLDIR}/bin/arm-none-eabi-ranlib

LIBDIR = ${TOOLDIR}/arm-none-eabi/lib
INCDIR = ${TOOLDIR}/arm-none-eabi/include

PLATFORM = -mcpu=cortex-m4 -mthumb -mabi=aapcs -mfloat-abi=hard \
	-mfpu=fpv4-sp-d16 -O2

PROGRAMMER = ${TOOLDIR}/bin/nordic-programmer
