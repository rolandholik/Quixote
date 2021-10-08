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


#
# Variable definitions.
#
DEMODIR = ${STMDIR}/Projects/32L496GDISCOVERY/Demonstrations/Cellular

CINCLUDE = -I . -I ../../../../../HurdLib -I ../../../include		\
	-I ../../../../../Quixote -I ../../../../../ISOidentity		\
	-I ../../../../../						\
	-I ${STMDIR}/Drivers/CMSIS/Device/ST/STM32L4xx/Include		\
	-I ${STMDIR}/Drivers/CMSIS/Include				\
	-I ${STMDIR}/Drivers/STM32L4xx_HAL_Driver/Inc			\
	-I ${STMDIR}/Drivers/BSP/X_STMOD_PLUS_MODEMS/BG96/AT_modem_bg96/Inc  \
	-I ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source/CMSIS_RTOS	\
	-I ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source/include	\
	-I ${STMDIR}/Middlewares/Third_Party/FreeRTOS/Source/portable/GCC/ARM_CM4F \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Rtosal/Inc	\
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Error/Inc	\
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Trace/Inc	\
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Interface/Com/Inc	\
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Ipc/Inc		\
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/AT_Core/Inc	\
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Data_Cache/Inc	\
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Cellular_Service/Inc \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Core/Runtime_Library/Inc \
	-I ${STMDIR}/Middlewares/ST/STM32_Cellular/Interface/Cellular_Ctrl/Inc \
	-I ${STMDIR}/Projects/Misc/RTOS/FreeRTOS/Inc			\
	-I ${STMDIR}/Projects/Misc/Samples/Cellular/Inc			\
	-I ${STMDIR}/Projects/Misc/Cmd/Inc				\
	-I ${DEMODIR}/STM32_Cellular/Config				\
	-I ${DEMODIR}/Core/Inc

DEFINES = -DUSE_HAL_DRIVER=1 -DHWREF_B_CELL_BG96_V2=1			      \
	-DUSE_STM32L496G_DISCO=1					      \
	-DAPPLICATION_CONFIG_FILE=\"plf_cellular_app_config.h\"		      \
	-DAPPLICATION_THREAD_CONFIG_FILE=\"plf_cellular_app_thread_config.h\"

CFLAGS = ${PLATFORM} ${DEFINES} ${CDEBUG} ${CINCLUDE} -fno-diagnostics-color \
	-Wall

STMSRC = stm32l4xx_hal.c stm32l4xx_hal_rcc.c stm32l4xx_hal_rcc_ex.c	    \
	stm32l4xx_hal_pwr.c stm32l4xx_hal_pwr_ex.c stm32l4xx_hal_gpio.c	    \
	stm32l4xx_hal_cortex.c stm32l4xx_hal_rng.c stm32l4xx_hal_rtc.c	    \
	stm32l4xx_hal_rtc_ex.c stm32l4xx_hal_uart.c stm32l4xx_hal_uart_ex.c \
	stm32l4xx_hal_dma.c stm32l4xx_hal_tim.c stm32l4xx_hal_tim_ex.c

MISCSRC = cmd.c

APPSRC = sancho.c command-interpreter.c ip4_addr.c sha256.c SHA256.c	   \
	Duct.c Actor.c Subject.c SecurityEvent.c SecurityPoint.c	   \
	TSEM.c TTYduct.c regcomp.c regexec.c regerror.c tre-mem.c	   \
	reg-support.c gpio.c rng.c rtc.c usart.c stm32l4xx_hal_msp.c	   \
	stm32l4xx_it.c stm32l4xx_hal_timebase_TIM.c system_stm32l4xx.c usart.c

CSRC = syscalls.c sysmem.c board_interrupts.c ${STMSRC} ${MISCSRC} ${APPSRC}

ASRC = startup_stm32l496agix.s

LIBS =  -L ../../../HurdLib -l HurdLib				  \
	-L ../RTOS/ -l rtos					  \
	-L ../STM32_Cellular/Cellular_Ctrl -l cellular_control	  \
	-L ../STM32_Cellular/Error -l error_handler		  \
	-L ../STM32_Cellular/Com -l com				  \
	-L ../STM32_Cellular/Rtosal -l rtosal			  \
	-L ../STM32_Cellular/Data_Cache -l dc_common		  \
	-L ../STM32_Cellular/Cellular_Service -l cellular_service \
	-L ../STM32_Cellular/AT_Core -l AT_Core			  \
	-L ../Modem -l modem					  \
	-L ../STM32_Cellular/AT_Core -l AT_Core			  \
	-L ../STM32_Cellular/Ipc -l ipc				  \
	-L ../STM32_Cellular/Trace -l trace			  \
	-L ../STM32_Cellular/Runtime_Library -l runtime

LDFLAGS = ${PLATFORM} -Wl,--script=sancho.ld -lc -lm ${LIBS}


#
# Compilation directives.
#
%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${DEMODIR}/Core/Src/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${STMDIR}/Drivers/STM32L4xx_HAL_Driver/Src/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${STMDIR}/Projects/Misc/RTOS/FreeRTOS/Src/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${STMDIR}/Projects/Misc/Samples/Cellular/Src/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${STMDIR}/Projects/Misc/Cmd/Src/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${DEMODIR}/STM32_Cellular/Target/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${DEMODIR}/IDE/STM32CubeIDE/DiscoL496_BG96/Application/User/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ../../../../../ISOidentity/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${DEMODIR}/IDE/STM32CubeIDE/DiscoL496_BG96/Application/Startup/%.s
	${AS} $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}
AOBJS = ${ASRC:.s=.o}


#
# Target definitions.
#
all: link-script sancho.elf

sancho.elf: ${COBJS} ${AOBJS}
	${CC} -specs ${LIBDIR}/nosys.specs -o $@ $^ ${LDFLAGS};

sancho-term.elf: ${COBJS} ${AOBJS}
	${CC} -specs ${LIBDIR}/nosys.specs -o $@ $^ ${LDFLAGS};

link-script:
	[ ! -e "sancho.ld" ] && ln -s ${DEMODIR}/IDE/STM32CubeIDE/DiscoL496_BG96/STM32L496AGIX_FLASH.ld sancho.ld || true;

flash: sancho.elf
	${PROGRAMMER} -c port=swd -w $^;

reset:
	${PROGRAMMER} -c port=swd -rst;

reset_hard:
	${PROGRAMMER} -c port=swd -hardRst;

clean:
	rm -f *.o;

clobber: clean
	rm -f sancho.ld sancho.elf;
