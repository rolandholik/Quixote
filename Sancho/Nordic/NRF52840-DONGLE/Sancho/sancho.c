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
#include <app_timer.h>

#include <HurdLib.h>
#include <Buffer.h>

#include <NAAAIM.h>
#include <TTYduct.h>

#include "sancho.h"


/* Static variable definitions. */


#if 0
static void bsp_event_callback(bsp_event_t ev)

{
	return;
}
#endif


int main(void)

{
	unsigned int cnt;

	TTYduct duct = NULL;


	/* Platform initialization. */
	nrf_drv_clock_init();

	nrf_drv_clock_lfclk_request(NULL);
	while ( !nrf_drv_clock_lfclk_is_running() )
		continue;

	app_timer_init();

	bsp_board_init(BSP_INIT_LEDS);


	/* Wait for port open event. */
	INIT(NAAAIM, TTYduct, duct, ERR(goto done));
	if ( !duct->init_device(duct, NULL) )
		ERR(goto done);

	/* Signal that the device is activated. */
	for (cnt= 0; cnt < 3; ++cnt) {
		bsp_board_led_on(ACTIVITY_LED);
		nrf_delay_ms(750);
		bsp_board_led_off(ACTIVITY_LED);
		nrf_delay_ms(750);
	}

	/* Invoke the interpreter on each connection. */
	while ( true ) {
		bsp_board_led_on(ACTIVE_LED);

		while ( !duct->accept_connection(duct) ) {
			__WFE();
		}


		/* Invoke command interpreter, return on port closure. */
		bsp_board_led_on(CONNECTION_LED);
		sancho_interpreter(duct);
		bsp_board_leds_off();
	}


 done:
	while ( true) {
		bsp_board_led_on(0);
		nrf_delay_ms(500);
		bsp_board_led_off(0);

		bsp_board_led_on(1);
		nrf_delay_ms(500);
		bsp_board_led_off(1);
	}
}


__attribute__((weak)) int _write(int file, char *ptr, int len)

{
	return len;
}


void Error(const char *file, const char *function, int line)

{
	return;
}
