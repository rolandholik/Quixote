# **************************************************************************
# * (C)Copyright IDfusion, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/


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

install-bin:
	set -e; for dir in ${SUBDIRS}; do ${MAKE} -C $$dir $@; done;

install-dev:
	set -e; for dir in ${SUBDIRS}; do ${MAKE} -C $$dir $@; done;

clean:
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clean; done
