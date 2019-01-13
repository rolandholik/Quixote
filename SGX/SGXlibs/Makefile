# ***************************************************************************
# (C)Copyright 2019, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
SUBDIRS = SGXfusion SGXnaaaim


#
# Target directives.
#
.PHONY: ${SUBDIRS}

all: ${SUBDIRS}

SGXfusion:
	${MAKE} -C $@;

SGXnaaaim:
	${MAKE} -C $@;

clean:
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clean; done
