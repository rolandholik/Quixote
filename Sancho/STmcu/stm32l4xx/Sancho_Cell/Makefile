# **************************************************************************
# * (C)Copyright 2020, Enjellic Systems Development, LLC. All rights reserved.
# **************************************************************************/

# Variable declarations.

STMDIR = /u/usr/sources/Development_STM/STM32CubeExpansion_CELLULAR_V6.0.0

LIBDIRS = RTOS Modem STM32_Cellular Sancho

DEFINES = -DUSE_HAL_DRIVER=1						      \
	-DHWREF_B_CELL_BG96_V2=1					      \
	-DUSE_STM32L496G_DISCO=1					      \
	-DAPPLICATION_CONFIG_FILE=\"plf_cellular_app_config.h\"		      \
	-DAPPLICATION_THREAD_CONFIG_FILE=\"plf_cellular_app_thread_config.h\"

export STMDIR DEFINES


#
# Target directives.
#
.PHONY: ${LIBDIRS} ${SUBDIRS}


# Targets
all: ${LIBDIRS}


#
# Subdirectory targets
#
RTOS:
	make -C $@;

Modem:
	make -C $@;

STM32_Cellular:
	make -C $@;

Sancho:
	make -C $@;


#
# Utility targets.
#
clean:
	set -e; for dir in ${LIBDIRS}; do ${MAKE} -C $$dir clean; done;

clobber: clean
	set -e; for dir in ${LIBDIRS}; do ${MAKE} -C $$dir clobber; done;
