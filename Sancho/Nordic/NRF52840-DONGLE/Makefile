# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************

# Variable declarations.
SUBDIRS = Sancho


#
# Target directives.
#
.PHONY: ${SUBDIRS}


# Targets
all: ${SUBDIRS}


#
# Subdirectory targets
Sancho:
	${MAKE} -C $@;


#
# Utility targets.
#
clean:
	set -e; for dir in ${SUBDIRS}; do ${MAKE} -C $$dir clean; done;

distclean: clean
	set -e; for dir in ${SUBDIRS}; do ${MAKE} -C $$dir distclean; done;
