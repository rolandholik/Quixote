# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************


#
# Variable declarations.
#
export MCUCFGDIR=${shell pwd}

SUBDIRS = HurdLib stm32l4xx


#
# Target directives.
#
.PHONY: ${SUBDIRS}

all: ${SUBDIRS}


#
# Subdirectory targets.
#
HurdLib:
	${MAKE} -C $@;

stm32l4xx:
	${MAKE} -C $@;


#
# Utility targets.
#
clean:
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clean; done;

clobber:
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clobber; done;
