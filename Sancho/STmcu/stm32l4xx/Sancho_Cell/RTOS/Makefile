# **************************************************************************
# * (C)Copyright 2020, Enjellic Systems Development, LLC. All rights reserved.
# **************************************************************************/


#
# Include micro-controller build definitions.
#
ifndef MCUCFGDIR
MCUCFGDIR=${shell cd ../../..; pwd}
endif

include ${MCUCFGDIR}/STmcu.mk


# Variable declarations.
RTOSDIR = ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source

CINCLUDE = -I ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source/include \
	-I ${STMDIR}/Projects/Misc/RTOS/FreeRTOS/Inc			\
	-I ${STMDIR}/Projects/Misc/Samples/Cellular/Inc			\
	-I ${STMDIR}/Projects/32L496GDISCOVERY/Demonstrations/Cellular/STM32_Cellular/Config \
	-I ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source/portable/GCC/ARM_CM4F \
	-I ${STMDIR}/Drivers/CMSIS/Include

CFLAGS = ${CDEBUG} ${PLATFORM} ${DEFINES} -fno-diagnostics-color -Wall \
	${CINCLUDE}

CSRC = cmsis_os.c croutine.c event_groups.c heap_4.c list.c port.c queue.c \
	tasks.c timers.c


#
# Compilation directives.
#
%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${RTOSDIR}/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${RTOSDIR}/CMSIS_RTOS/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${RTOSDIR}/portable/MemMang/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${RTOSDIR}/portable/GCC/ARM_CM4F/%.c
	${CC} ${CFLAGS} -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}


#
# Target directives.
#
# .PHONY: client lib ${SUBDIRS}


# Targets
all: librtos.a

librtos.a: ${COBJS}
	${AR} r librtos.a $^;
	${RANLIB} librtos.a;

clean:
	rm -f *.o;

clobber: clean
	rm -f librtos.a;
