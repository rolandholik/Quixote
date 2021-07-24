# **************************************************************************
# * (C)Copyright 2021, Enjellic Systems Development, LLC. All rights reserved.
# **************************************************************************/

#
# Variable declarations.
#
LIBDIRS = Com Cellular_Service Ipc Trace AT_Core Rtosal Cellular_Ctrl \
	Runtime_Library Error Data_Cache PPPosif


#
# Target directives.
#
.PHONY: ${LIBDIRS}


#
# Target definitions.
#
all: ${LIBDIRS}
	set -e; for dir in ${LIBDIRS}; do ${MAKE} -C $$dir; done;

clean:
	set -e; for dir in ${LIBDIRS}; do ${MAKE} -C $$dir $@; done;

clobber: clean
