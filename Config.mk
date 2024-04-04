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

# Release version and name.
RELEASE = 1
VERSION = 6
NAME	= Quixote-${RELEASE}.${VERSION}

# Compiler selection.
CC = gcc

# Generic compiler flags to use for the build.
BUILD_CFLAGS = -O2 -fomit-frame-pointer -march=core2 -Wall

# Default linker flags.
BUILD_LDFLAGS = -L ${TOPDIR}/HurdLib

# ELF library location.
BUILD_ELFLIB = $(shell pkg-config libelf --libs)

# SSL library location.
BUILD_LIBCRYPTO = $(shell pkg-config libcrypto --libs)

# Trusted Modeling Agent implentations.
BUILD_SANCHOS     = Xen # SGX Nordic STmcu
BUILD_XEN_VERSION = 4.15

# Installation paths.
BUILD_INSTPATH = ${DESTDIR}/opt/Quixote
BUILD_VARPATH  = ${DESTDIR}/var/lib/Quixote

# Path to mbedtls source.
BUILD_MBEDDIR = ${TOPDIR}/Support/mbedtls

# URL for mbedtls download.
BUILD_MBEDURL = https://github.com/Mbed-TLS/mbedtls/archive/refs/tags

# URL for Nordic Software Development Kit.
BUILD_NORDIC_URL = https://developer.nordicsemi.com/nRF5_SDK/nRF5_SDK_v17.x.x

# Source location for Nordic SDK.
BUILD_NORDIC_DIR = ${TOPDIR}/Support/nRF5_SDK

# Root for ARM Cortex R/M tools.
BUILD_ARM_TOOLDIR = /usr

# nrfutil program to use for programming NRF52840-DONGLE.
BUILD_NRFUTIL = nrfutil

export CC BUILD_KERNEL_VERSION BUILD_LDFLAGS BUILD_ELFLIB BUILD_LIBCRYPTO \
	BUILD_SANCHOS BUILD_INSTPATH BUILD_MBEDDIR BUILD_MBEDURL	  \
	BUILD_XEN_VERSION BUILD_NORDIC_URL BUILD_NORDIC_DIR		  \
	BUILD_ARM_TOOLDIR BUILD_NRFUTIL


#
# The Build.mk file must exist and is used to implement site specific
# modifications for the build directives.
#
ifeq (${BUILD_CONFIG},"true")
include ${TOPDIR}/Build.mk
endif
