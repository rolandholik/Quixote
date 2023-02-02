# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

#
# Include global build definitions if this is a sub-directory build.
#
ifndef BUILD_CONFIG
include ${shell cd ..; pwd}/Build.mk
endif

KERNEL_VERSION = ${BUILD_KERNEL_VERSION}


# Installation path.
INSTPATH = ${BUILD_INSTPATH}


# Definitions for building libcap.
LIBCAP_VERSION = 2.66
LIBCAP_FILE    = libcap-${LIBCAP_VERSION}.tar.gz
LIBCAP_URL     = https://mirrors.edge.kernel.org/pub/linux/libs/security/linux-privs/libcap2/${LIBCAP_FILE}
LIBCAP_TAR     = Build/${LIBCAP_FILE}

ifeq ("${KERNEL_VERSION}","5.4")
LIBCAP_PATCH = Build/libcap-2.66_cap_38.patch
endif

ifeq ("${KERNEL_VERSION}","5.15")
LIBCAP_PATCH = Build/libcap-2.66_cap_41.patch
endif

ifeq ("${KERNEL_VERSION}","6.1")
LIBCAP_PATCH = Build/libcap-2.66_cap_41.patch
endif


# Definitions for the mbedtls source package.
MBEDTLS_VERSION = 2.28.1
MBEDTLS_FILE    = v${MBEDTLS_VERSION}.tar.gz
MBEDTLS_TAR     = Build/${MBEDTLS_FILE}
MBEDTLS_URL     = ${BUILD_MBEDURL}/${MBEDTLS_FILE}


# Definitions for the Nordic Software Development kit.
NORDIC_FILE = nRF5_SDK_17.1.0_ddde560.zip
NORDIC_ZIP  = Build/${NORDIC_FILE}
NORDIC_URL  = ${BUILD_NORDIC_URL}/${NORDIC_FILE}


#
# Generic build targets.
#
.PHONY: all

all: libcap.stamp mbedtls.stamp nordic.stamp


#
# libcap build.
#
libcap.stamp: libcap/libcap/libcap.a
	touch $@;

libcap/libcap/libcap.a: libcap
	make -C libcap CC=${CC} SHARED=no PAM_CAP=no GOLANG=no;

libcap: ${LIBCAP_TAR}
	tar xf $<;
	patch -p0 < ${LIBCAP_PATCH};
	mv libcap-${LIBCAP_VERSION} libcap;

${LIBCAP_TAR}:
	wget -O $@ ${LIBCAP_URL};


#
# mbedtls source.
#
mbedtls.stamp: mbedtls
	touch $@;

mbedtls: ${MBEDTLS_TAR}
	tar xf $<;
	mv mbedtls-${MBEDTLS_VERSION} mbedtls;

${MBEDTLS_TAR}:
	wget -O $@ ${MBEDTLS_URL};


#
# Nordic SDK sources.
#
nordic.stamp: nRF5_SDK
	touch $@;

nRF5_SDK: ${NORDIC_ZIP}
	unzip -x $<;
	mv nRF5_SDK_17.1.0_ddde560 nRF5_SDK;

${NORDIC_ZIP}:
	wget -O $@ ${NORDIC_URL};


#
# Installation target.
#
install-bin:
	install -s libcap/progs/capsh ${INSTPATH}/sbin;


#
# Utility targets.
#
clean:
	[ -d libcap ] && make -C libcap clean || true;

distclean: clean
	[ -d libcap ] && rm -rf libcap || true;
	[ -d mbedtls ] && rm -rf mbedtls || true;
	[ -d nRF5_SDK ] && rm -rf nRF5_SDK || true;
	rm -f *.stamp;

purge: distclean
	rm -f Build/*.tar.gz;
