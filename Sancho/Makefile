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

# Variable declarations.
SUBDIRS = ${BUILD_SANCHOS}


#
# Target directives.
#
.PHONY: ${SUBDIRS}


#
# Subdirectory targets.
#
all: ${SUBDIRS}

STmcu:
	${MAKE} -C $@;

Nordic:
	${MAKE} -C $@;

SGX:
	${MAKE} -C $@;

Xen:
	${MAKE} -C $@;


#
# Installation targets.
#
install-bin:
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i install-bin; done;


#
# Utility targets.
#
clean:
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clean; done;

distclean:
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i distclean; done;

purge: distclean
	${MAKE} -C Xen purge;
