# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

ifndef BUILD_CONFIG
include ${shell cd ..; pwd}/Build.mk
endif


obj-m += tsem-integrity.o
ccflags-y += -I${KERNELSRC}/security/tsem


all:
	make V=1 -C ${KERNELSRC} M=${PWD} modules;

build:
	make V=1 KERNELSRC=${BUILD_KERNEL_SOURCE} M=${PWD};

clean:
	rm -f *.o *.mod *.ko;
	rm -f modules.order Module.symvers tsem-integrity.mod.c .*.cmd;
