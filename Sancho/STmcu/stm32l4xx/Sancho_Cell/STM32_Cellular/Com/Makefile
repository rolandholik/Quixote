# **************************************************************************
# * (C)Copyright 2020, Enjellic Systems Development, LLC. All rights reserved.
# **************************************************************************/

# Variable declarations.

STMDIR  = /u/usr/sources/Development_STM/STM32CubeExpansion_CELLULAR_V6.0.0
RTOSDIR = ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source

LIBDIR = /opt/ESDembedded/arm-none-eabi/lib
INCDIR = /opt/ESDembedded/arm-none-eabi/include


#
# Compiler and tool definitions.
#

# CC = arm-gcc
# AS = arm-as

CC =	 /opt/ESDembedded/bin/arm-none-eabi-gcc
AS =	 /opt/ESDembedded/bin/arm-none-eabi-as
AR =	 /opt/ESDembedded/bin/arm-none-eabi-ar
RANLIB = /opt/ESDembedded/bin/arm-none-eabi-ranlib

CINCLUDE = -I ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source/include	     \
	-I ${STMDIR}/Projects/Misc/RTOS/FreeRTOS/Inc			     \
	-I ${STMDIR}/Projects/Misc/Cmd/Inc				     \
	-I ${STMDIR}/Projects/Misc/Samples/Cellular/Inc			     \
	-I ${STMDIR}/Projects/32L496GDISCOVERY/Demonstrations/Cellular/STM32_Cellular/Config \
	-I ${STMDIR}/Projects/32L496GDISCOVERY/Demonstrations/Cellular/Core/Inc \
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
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Interface/Com/Inc	     \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Interface/Cellular_Ctrl/Inc \
	-I ../..							     \
	-I ${RTOSDIR}/CMSIS_RTOS


#
CFLAGS = ${CDEBUG} ${PLATFORM} ${DEFINES} ${CINCLUDE} \
	-fno-diagnostics-color -Wall

CSRC = com_core.c com_sockets_err_compat.c com_sockets_statistic.c \
	com_icc.c com_sockets_ip_modem.c com_utils.c com_sockets.c \
	com_sockets_lwip_mcu.c

LIBNAME = libcom.a


#
# Compilation directives.
#
%.o: ${STMDIR}/Middlewares/ST/STM32_Cellular/Interface/Com/Src/%.c
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
${LIBNAME}: ${COBJS}
	${AR} r ${LIBNAME} $^;
	${RANLIB} ${LIBNAME};

clean:
	rm -f *.o ${LIBNAME};
