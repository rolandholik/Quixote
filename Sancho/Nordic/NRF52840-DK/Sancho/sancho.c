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

#include <nrf_drv_usbd.h>
#include <app_usbd_core.h>
#include <app_usbd.h>
#include <app_usbd_string_desc.h>
#include <app_usbd_cdc_acm.h>


int main(void)
{

	nrf_drv_clock_init();
	nrf_drv_clock_lfclk_request(NULL);

	while ( 1 )
		continue;
}
