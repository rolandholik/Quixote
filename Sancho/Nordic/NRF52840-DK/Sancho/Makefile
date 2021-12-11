# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************

#
# Include micro-controller build definitions.
#
ifndef MCUCFGDIR
MCUCFGDIR=${shell cd ../..; pwd}
endif

include ${MCUCFGDIR}/Nordic.mk


#
# Variable definitions.
#
CINCLUDE = -I . -I ../../../HurdLib -I ../../../../../HurdLib 		  \
	-I ../../../../../lib -I ../../../../../Quixote			  \
	-I ../../../../../SecurityModel	 -I ../../../../../		  \
	-I ${NORDICDIR}/components/boards				  \
	-I ${NORDICDIR}/components/toolchain/cmsis/include		  \
	-I ${NORDICDIR}/components/libraries/log			  \
	-I ${NORDICDIR}/components/libraries/log/src			  \
	-I ${NORDICDIR}/components/libraries/util			  \
	-I ${NORDICDIR}/components/libraries/delay			  \
	-I ${NORDICDIR}/components/libraries/usbd			  \
	-I ${NORDICDIR}/components/libraries/strerror			  \
	-I ${NORDICDIR}/components/libraries/usbd/class/cdc		  \
	-I ${NORDICDIR}/components/libraries/usbd/class/cdc/acm		  \
	-I ${NORDICDIR}/components/libraries/experimental_section_vars	  \
	-I ${NORDICDIR}/components/drivers_nrf/nrf_soc_nosd		  \
	-I ${NORDICDIR}/modules/nrfx/hal -I ${NORDICDIR}/modules/nrfx	  \
	-I ${NORDICDIR}/integration/nrfx				  \
	-I ${NORDICDIR}/integration/nrfx/legacy				  \
	-I ${NORDICDIR}/modules/nrfx/mdk				  \
	-I ${NORDICDIR}/modules/nrfx/drivers/include			  \
	-I ${NORDICDIR}/examples/peripheral/cli/pca10056/blank/config	  \

DEFINES = -DAPP_TIMER_V2 -DAPP_TIMER_V2_RTC1_ENABLED -DBOARD_PCA10056 \
	-DCONFIG_GPIO_AS_PINRESET -DFLOAT_ABI_HARD -DNRF52840_XXAA

CFLAGS = ${PLATFORM} ${DEFINES} ${CDEBUG} ${CINCLUDE} -fno-diagnostics-color \
	-Wall

NORDICSRC = system_nrf52840.c nrf_drv_clock.c nrfx_clock.c nrfx_power.c \
	app_util_platform.c

APPSRC = sancho.c

CSRC = ${NORDICSRC} ${APPSRC}

ASRC = gcc_startup_nrf52840.S

# LIBS =  -L ../../../HurdLib -l HurdLib				  \
# 	-L ../../../NAAAIM -l NAAAIM

LDFLAGS = ${PLATFORM} -Wl,--script=sancho.ld -lc -lm ${LIBS}


#
# Compilation directives.
#
%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ../../../../../SecurityModel/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/modules/nrfx/mdk/%.S
	${CC} -c -D__STARTUP_CONFIG=1 $< -o $@;

%.o: ${NORDICDIR}/modules/nrfx/mdk/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/modules/nrfx/drivers/src/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/integration/nrfx/legacy/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/util/%.c
	${CC} ${CFLAGS} -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}
AOBJS = ${ASRC:.S=.o}


#
# Target definitions.
#
all: link-script sancho.elf

sancho.elf: ${COBJS} ${AOBJS}
	${CC} -specs ${LIBDIR}/nano.specs -o $@ $^ ${LDFLAGS};

link-script:
	[ ! -e "sancho-common.ld" ] && ln -s ${NORDICDIR}/modules/nrfx/mdk/nrf_common.ld sancho-common.ld || true;

flash: sancho.elf
	${PROGRAMMER} --program $^ --chiperase;

reset:
	${PROGRAMMER} -r;

clean:
	rm -f *.o;

clobber: clean
	rm -f sancho-common.ld sancho.elf;
