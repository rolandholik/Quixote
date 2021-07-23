# **************************************************************************
# * (C)Copyright 2020, Enjellic Systems Development, LLC. All rights reserved.
# **************************************************************************/

# Variable declarations.
SUBDIRS = Sancho_Cell


#
# Target directives.
#
.PHONY: ${SUBDIRS}


# Targets
all: ${SUBDIRS}


#
# Subdirectory targets
Sancho_Cell:
	${MAKE} -C $@;


#
# Utility targets.
#
clean:
	set -e; for dir in ${SUBDIRS}; do ${MAKE} -C $$dir clean; done;

clobber: clean
	set -e; for dir in ${SUBDIRS}; do ${MAKE} -C $$dir clobber; done;
