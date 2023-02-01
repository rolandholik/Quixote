# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************

#
# Include global and sub-system build configuration.
#
ifndef BUILD_CONFIG
include ${shell cd ../../../..; pwd}/Build.mk
endif

ifndef MCUCFGDIR
MCUCFGDIR=${shell cd ../..; pwd}
endif

include ${MCUCFGDIR}/Nordic.mk


#
# Variable definitions.
#
CINCLUDE = -I . -I ../../HurdLib -I ../../../../HurdLib -I ../../NAAAIM	  \
	-I ../../../../lib -I ../../../../Quixote -I ../../../../../	  \
	-I ../../../../SecurityModel -I ../../NRF52840-DK/Sancho	  \
	-I ${NORDICDIR}/examples/peripheral/usbd_cdc_acm/pca10056/blank/config	  \
	-I ${NORDICDIR}/components/boards				  \
	-I ${NORDICDIR}/components/toolchain/cmsis/include		  \
	-I ${NORDICDIR}/components/libraries/log			  \
	-I ${NORDICDIR}/components/libraries/log/src			  \
	-I ${NORDICDIR}/components/libraries/util			  \
	-I ${NORDICDIR}/components/libraries/delay			  \
	-I ${NORDICDIR}/components/libraries/queue			  \
	-I ${NORDICDIR}/components/libraries/memobj			  \
	-I ${NORDICDIR}/components/libraries/balloc			  \
	-I ${NORDICDIR}/components/libraries/ringbuf			  \
	-I ${NORDICDIR}/components/libraries/atomic			  \
	-I ${NORDICDIR}/components/libraries/timer			  \
	-I ${NORDICDIR}/components/libraries/sortlist			  \
	-I ${NORDICDIR}/components/libraries/usbd			  \
	-I ${NORDICDIR}/components/libraries/cli			  \
	-I ${NORDICDIR}/components/libraries/cli/uart			  \
	-I ${NORDICDIR}/components/libraries/strerror			  \
	-I ${NORDICDIR}/components/libraries/atomic_fifo		  \
	-I ${NORDICDIR}/components/libraries/usbd/class/cdc		  \
	-I ${NORDICDIR}/components/libraries/usbd/class/cdc/acm		  \
	-I ${NORDICDIR}/components/libraries/experimental_section_vars	  \
	-I ${NORDICDIR}/components/drivers_nrf/nrf_soc_nosd		  \
	-I ${NORDICDIR}/modules/nrfx/hal -I ${NORDICDIR}/modules/nrfx	  \
	-I ${NORDICDIR}/integration/nrfx				  \
	-I ${NORDICDIR}/integration/nrfx/legacy				  \
	-I ${NORDICDIR}/modules/nrfx/soc				  \
	-I ${NORDICDIR}/modules/nrfx/mdk				  \
	-I ${NORDICDIR}/modules/nrfx/drivers/include			  \
	-I ${NORDICDIR}/external/fprintf				  \
	-I ${NORDICDIR}/external/utf_converter			  	  \
	-I ${NORDICDIR}/components/libraries/bsp \
	-I ${NORDICDIR}/components/libraries/button \
	-I ${NORDICDIR}/components/libraries/pwr_mgmt \
	-I ${NORDICDIR}/components/libraries/mutex			 \
	-I ${NORDICDIR}/components/softdevice/mbr/headers

DEFINES = -DAPP_TIMER_V2 -DAPP_TIMER_V2_RTC1_ENABLED -DBOARD_PCA10059	 \
	-DCONFIG_GPIO_AS_PINRESET -DMBR_PRESENT -DFLOAT_ABI_HARD	 \
	-DNRF52840_XXAA -DUSE_APP_CONFIG=1

CFLAGS = ${PLATFORM} ${DEFINES} ${CDEBUG} ${CINCLUDE} -fno-diagnostics-color \
	-Wall

NORDICSRC = system_nrf52840.c nrfx_clock.c				 \
	app_util_platform.c app_timer.c app_usbd.c app_usbd_serial_num.c \
	app_usbd_cdc_acm.c app_usbd_core.c nrfx_usbd.c nrf_drv_power.c	 \
	app_error.c nrf_atomic.c nrfx_atomic.c app_usbd_string_desc.c	 \
	nrf_atfifo.c boards.c bsp.c app_error_weak.c app_button.c	 \
	nrfx_gpiote.c app_error_handler_gcc.c nrfx_power.c		 \
	nrf_drv_clock.c

APPSRC = sancho.c sancho-interpreter.c TTYduct.c COE.c Cell.c SecurityEvent.c \
	SecurityPoint.c TSEM.c EventModel.c EventParser.c

CSRC = ${NORDICSRC} ${APPSRC}
ASRC = gcc_startup_nrf52840.S

LIBS =  -L ../../HurdLib -l HurdLib -L ../../NAAAIM -l NAAAIM

LDFLAGS = ${PLATFORM} -Wl,--script=sancho.ld ${LIBS}


#
# Compilation directives.
#
%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ../../NRF52840-DK/Sancho/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ../../../../SecurityModel/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/modules/nrfx/mdk/%.S
	${CC} -c -D__STARTUP_CONFIG=1 $< -o $@;

%.o: ${NORDICDIR}/modules/nrfx/mdk/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/modules/nrfx/soc/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/modules/nrfx/drivers/src/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/integration/nrfx/legacy/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/util/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/atomic/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/atomic_fifo/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/timer/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/usbd/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/usbd/class/cdc/acm/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/boards/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/cli/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/external/fprintf/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/bsp/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/button/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/memobj/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/pwr_mgmt/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/queue/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/balloc/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/experimental_section_vars/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/cli/uart/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/ringbuf/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/modules/nrfx/drivers/src/prs/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/log/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${NORDICDIR}/components/libraries/log/src/%.c
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
	${CC} -specs ${LIBDIR}/nosys.specs -o $@ $^ ${LDFLAGS};
link-script:
	[ ! -e "sancho.ld" ] && \
		ln -s ${NORDICDIR}/examples/peripheral/cli/pca10059/mbr/armgcc/cli_gcc_nrf52.ld sancho.ld || true;
	[ ! -e "nrf_common.ld" ] && ln -s ${NORDICDIR}/modules/nrfx/mdk/nrf_common.ld . || true;

flash: sancho.elf
	${OBJCOPY} -O ihex $^ $^.hex;

reset:
	${PROGRAMMER} -r;

clean:
	rm -f *.o;

distclean: clean
	rm -f nrf_common.ld sancho.ld sancho.elf sancho.elf.hex;
