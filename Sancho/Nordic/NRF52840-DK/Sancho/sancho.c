/** \file
 *
 * This file contains the setup code for implenting a SanchoMCU
 * implementation based on the Nordic 52840 development board.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

/* Includes. */
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>

#include <nrf.h>
#include <nrf_drv_clock.h>
#include <nrf_gpio.h>
#include <nrf_delay.h>

#include <boards.h>
#include <bsp.h>
#include <bsp_cli.h>

#include <nrf_cli_uart.h>
#include <nrf_log.h>
#include <nrf_log_ctrl.h>
#include <nrf_log_default_backends.h>

#include <HurdLib.h>
#include <Buffer.h>

#include <NAAAIM.h>
#include <TTYduct.h>

#include "sancho.h"


/* Static variable definitions. */

/** UART definition for sancho console. */
NRF_CLI_UART_DEF(sancho_console_uart, 0, 64, 16);
NRF_CLI_DEF(sancho_console,
            "sancho_console:~$ ",
            &sancho_console_uart.transport,
            '\r',
            4);


static void bsp_event_callback(bsp_event_t ev)

{
	return;
}


void console_init(void)

{
	nrf_drv_uart_config_t uart_config = NRF_DRV_UART_DEFAULT_CONFIG;


	bsp_cli_init(bsp_event_callback);

	uart_config.pseltxd = TX_PIN_NUMBER;
	uart_config.pselrxd = RX_PIN_NUMBER;
	uart_config.hwfc    = NRF_UART_HWFC_DISABLED;

	nrf_cli_init(&sancho_console, &uart_config, true, true, \
		     NRF_LOG_SEVERITY_INFO);
	nrf_cli_start(&sancho_console);

	return;
}


int main(void)

{
	Buffer bufr = NULL;

	TTYduct duct = NULL;


	/* Platform initialization. */
	NRF_LOG_INIT(NULL);

	nrf_drv_clock_init();

	nrf_drv_clock_lfclk_request(NULL);
	while ( !nrf_drv_clock_lfclk_is_running() )
		continue;

	app_timer_init();

	console_init();


	/* Wait for port open event. */
	INIT(NAAAIM, TTYduct, duct, ERR(goto done));
	if ( !duct->init_device(duct, NULL) )
		ERR(goto done);

	NRF_LOG_INFO("Waiting for connection.");
	while ( !duct->accept_connection(duct) ) {
		nrf_cli_process(&sancho_console);
		NRF_LOG_PROCESS();
		__WFE();
	}


	/* Invoke command interpreter, this should not return. */
	NRF_LOG_INFO("Starting interpreter.");
	sancho_interpreter(duct);


 done:
	NRF_LOG_INFO("Error loop.");

	while ( true ) {
		nrf_cli_process(&sancho_console);
		NRF_LOG_PROCESS();
		__WFE();
	}
}


__attribute__((weak)) int _write(int file, char *ptr, int len)

{
	int cnt;

	nrf_cli_t const *cp = &sancho_console;


	for (cnt= 0; cnt < len; ++cnt)
		nrf_cli_fprintf(cp, NRF_CLI_NORMAL, "%c", ptr[cnt]);


	return len;
}


void Error(const char *file, const char *function, int line)

{
	char bufr[80];


	memset(bufr, '\0', sizeof(bufr));
	snprintf(bufr, sizeof(bufr), "T[%s,%s,%d]: Error location.", file, \
		 function, line);

	NRF_LOG_INFO(bufr);

	return;
}
