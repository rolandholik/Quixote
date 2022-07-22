# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/


# Variable declarations.
SUBDIRS = STmcu Nordic SGX Xen


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
# Utility targets.
#
clean:
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clean; done;

clobber:
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clobber; done;
