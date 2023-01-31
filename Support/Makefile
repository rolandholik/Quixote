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


#
# Generic build targets.
#
.PHONY: all

all: libcap.stamp


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
	rm -f *.stamp;

purge: distclean
	rm -f Build/*.tar.gz;
