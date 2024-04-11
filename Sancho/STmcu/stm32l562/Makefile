# **************************************************************************
# * (C)Copyright 2020, Enjellic Systems Development, LLC. All rights reserved.
# **************************************************************************/

# Variable declarations.
SUBDIRS = HurdLib NAAAIM Sancho


#
# Target directives.
#
.PHONY: ${SUBDIRS}


# Targets
all: ${SUBDIRS}


#
# Subdirectory targets
HurdLib:
	${MAKE} -C $@;

NAAAIM:
	${MAKE} -C $@;

Sancho:
	${MAKE} -C $@;


#
# Utility targets.
#
clean:
	set -e; for dir in ${SUBDIRS}; do ${MAKE} -C $$dir clean; done;

distclean: clean
	set -e; for dir in ${SUBDIRS}; do ${MAKE} -C $$dir distclean; done;
