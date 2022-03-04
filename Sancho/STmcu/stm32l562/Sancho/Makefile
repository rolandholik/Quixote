# **************************************************************************
# * (C)Copyright 2020, Enjellic Systems Development, LLC. All rights reserved.
# **************************************************************************/

#
# Include STmicro build definitions.
#
STMCU=STM32L5

ifndef MCUCFGDIR
MCUCFGDIR=${shell cd ../..; pwd}
endif

include ${MCUCFGDIR}/STmcu.mk


#
# Variable definitions for the architecture development kit.
#
STMDIR = /u/usr/sources/Development_STM/STM32CubeL5-1.2.0

CINCLUDE = -I . -I ../../include -I ../HurdLib -I ../../../../HurdLib	 \
	-I ../../../.. -I ../../../../lib -I ../../../../Quixote	 \
	-I ../../../../SecurityModel					 \
	-I ${STMDIR}/Drivers/BSP/STM32L562E-DK				 \
	-I ${STMDIR}/Drivers/STM32L5xx_HAL_Driver/Inc			 \
	-I ${STMDIR}/Drivers/CMSIS/Device/ST/STM32L5xx/Include		 \
	-I ${STMDIR}/Middlewares/Third_Party/trustedfirmware/platform/ext/cmsis \
	-I ${INCDIR}


#
# -mthumb -mcpu=cortex-mN
# -mcpu=cortex-mN -march=armv7e-m+fp.dp -mlittle-endian -mthumb -masm-syntax-unified
#
CFLAGS = ${PLATFORM} ${DEFINES} ${CINCLUDE} -fno-diagnostics-color -Wall

STMSRC = stm32l5xx_hal_msp.c stm32l5xx_it.c system_stm32l5xx.c syscalls.c    \
	sysmem.c stm32l5xx_hal.c stm32l5xx_hal_uart.c stm32l5xx_hal_pwr_ex.c \
	stm32l5xx_hal_gpio.c stm32l5xx_hal_rcc.c stm32l5xx_hal_uart_ex.c     \
	stm32l5xx_hal_dma.c stm32l5xx_hal_pwr.c stm32l5xx_hal_rcc_ex.c	     \
	stm32l5xx_hal_cortex.c stm32l5xx_hal_exti.c

APPSRC = sancho.c sancho-interpreter.c TTYduct.c COE.c Cell.c SecurityEvent.c \
	SecurityPoint.c EventModel.c TSEM.c regcomp.c regexec.c regerror.c    \
	tre-mem.c reg-support.c

CSRC = syscalls.c sysmem.c board_interrupts.c ${STMSRC} ${APPSRC}

ASRC = startup.s

LIBS = -L ../NAAAIM -lNAAAIM -L ../HurdLib -lHurdLib

LDFLAGS = ${PLATFORM} -Wl,--script=sancho.ld ${LIBS}


#
# Compilation directives.
#
%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ../../../../SecurityModel/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ../STM32CubeIDE/Example/User/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${STMDIR}/Drivers/STM32L5xx_HAL_Driver/Src/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${STMDIR}/Drivers/BSP/STM32L562E-DK/%.c
	${CC} ${CFLAGS} -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}
AOBJS = ${ASRC:.s=.o}


#
# Target directives.
#
# .PHONY: client lib ${SUBDIRS}


# Targets
all: sancho.elf

sancho.elf: ${COBJS} ${AOBJS}
	${CC} -specs ${LIBDIR}/nosys.specs -o $@ $^ ${LDFLAGS};

flash: sancho.elf
	${PROGRAMMER} -c port=swd -w sancho.elf;

reset:
	${PROGRAMMER} -c port=swd -rst;

reset_hard:
	${PROGRAMMER} -c port=swd -hardRst;

clean:
	rm -f *.o;

clobber:
	rm -f sancho.elf;
