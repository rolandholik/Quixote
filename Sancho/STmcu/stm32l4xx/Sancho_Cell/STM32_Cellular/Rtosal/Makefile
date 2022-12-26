# **************************************************************************
# * (C)Copyright 2020, Enjellic Systems Development, LLC. All rights reserved.
# **************************************************************************/


#
# Include micro-controller build definitions.
#
ifndef MCUCFGDIR
MCUCFGDIR=${shell cd ../../../..; pwd}
endif

include ${MCUCFGDIR}/STmcu.mk


#
# Variable declarations.
#
CINCLUDE = -I ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source/include \
	-I ${STMDIR}/Projects/Misc/RTOS/FreeRTOS/Inc			\
	-I ${STMDIR}/Projects/Misc/Samples/Cellular/Inc			\
	-I ${STMDIR}/Projects/32L496GDISCOVERY/Demonstrations/Cellular/STM32_Cellular/Config \
	-I ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source/portable/GCC/ARM_CM4F \
	-I ${STMDIR}/Drivers/CMSIS/Include \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Rtosal/Inc \
	-I ${RTOSDIR}/CMSIS_RTOS

CFLAGS = ${CDEBUG} ${PLATFORM} ${DEFINES} -fno-diagnostics-color -Wall \
	${CINCLUDE}

CSRC = rtosal.c

LIBNAME = librtosal.a


#
# Compilation directives.
#
%.o: ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Rtosal/Src/%.c
	${CC} ${CFLAGS} -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}


#
# Target definitions.
#
${LIBNAME}: ${COBJS}
	${AR} r ${LIBNAME} $^;
	${RANLIB} ${LIBNAME};

clean:
	rm -f *.o ${LIBNAME};

distclean: clean
