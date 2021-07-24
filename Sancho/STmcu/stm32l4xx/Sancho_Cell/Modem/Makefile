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

CINCLUDE = -I ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source/include	     \
	-I ${STMDIR}/Projects/Misc/RTOS/FreeRTOS/Inc			     \
	-I ${STMDIR}/Projects/Misc/Cmd/Inc				     \
	-I ${STMDIR}/Projects/Misc/Samples/Cellular/Inc			     \
	-I ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source/portable/GCC/ARM_CM4F \
	-I ${STMDIR}/Drivers/CMSIS/Include				     \
	-I ${STMDIR}/Drivers/CMSIS/Device/ST/STM32L4xx/Include		     \
	-I ${STMDIR}/Drivers/STM32L4xx_HAL_Driver/Inc			     \
	-I ${STMDIR}/Drivers/BSP/X_STMOD_PLUS_MODEMS/BG96/AT_modem_bg96/Inc  \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Rtosal/Inc	     \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Data_Cache/Inc	     \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Error/Inc    	     \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Trace/Inc    	     \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/PPPosif/Inc	     \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Ipc/Inc    	     \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Runtime_Library/Inc  \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/AT_Core/Inc	     \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Cellular_Service/Inc \
	-I ${STMDIR}/Projects/32L496GDISCOVERY/Demonstrations/Cellular/STM32_Cellular/Config \
	-I ${STMDIR}/Projects/32L496GDISCOVERY/Demonstrations/Cellular/Core/Inc \
	-I ${RTOSDIR}/CMSIS_RTOS					     \
	-I ../..


#
CDEBUG = -O2

CFLAGS = ${PLATFORM} ${DEFINES} ${CDEBUG} ${CINCLUDE} -fno-diagnostics-color \
	-Wall

CSRC = at_custom_modem_api.c at_custom_modem_signalling.c \
	at_custom_modem_socket.c at_custom_modem_specific.c sysctrl_specific.c

LIBNAME = libmodem.a


#
# Compilation directives.
#
%.o: ${STMDIR}/Drivers/BSP/X_STMOD_PLUS_MODEMS/BG96/AT_modem_bg96/Src/%.c
	${CC} ${CFLAGS} -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}


#
# Target directives.
#
${LIBNAME}: ${COBJS}
	${AR} r ${LIBNAME} $^;
	${RANLIB} ${LIBNAME};

clean:
	rm -f *.o;

clobber:
	rm -f ${LIBNAME};
