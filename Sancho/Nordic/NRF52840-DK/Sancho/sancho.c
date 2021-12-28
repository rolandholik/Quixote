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

#include <nrf_drv_usbd.h>
#include <app_usbd_core.h>
#include <app_usbd.h>
#include <app_usbd_string_desc.h>
#include <app_usbd_serial_num.h>
#include <app_usbd_cdc_acm.h>

#include <nrf_cli_uart.h>
#include <nrf_log.h>
#include <nrf_log_ctrl.h>
#include <nrf_log_default_backends.h>


/** Flag to indicate that the USB port has been opened. */
static _Bool Port_Open = false;

/** Flag to indicate that I/O is available from read. */
static _Bool Have_Read = false;

/** USB read buffer. */
static char RXbuffer[1];

/** USB transmit buffer. */
static char TXbuffer[NRF_DRV_USBD_EPSIZE];


/** UART definition. */
NRF_CLI_UART_DEF(sancho_console_uart, 0, 64, 16);
NRF_CLI_DEF(sancho_console,
            "sancho_console:~$ ",
            &sancho_console_uart.transport,
            '\r',
            4);

			
static void acm_event_handler(app_usbd_class_inst_t const * p_inst, \
			      app_usbd_cdc_acm_user_event_t event);


APP_USBD_CDC_ACM_GLOBAL_DEF(cmd_cdc_acm,			\
			    acm_event_handler,			\
			    0,					\
			    1,					\
			    NRF_DRV_USBD_EPIN2,			\
			    NRF_DRV_USBD_EPIN1,			\
			    NRF_DRV_USBD_EPOUT2,		\
			    APP_USBD_CDC_COMM_PROTOCOL_AT_V250);


static void _acm_event_read(app_usbd_cdc_acm_t const * acm)

{
	ret_code_t rc;

	size_t read_size;


	do {
		read_size = app_usbd_cdc_acm_rx_size(acm);
		rc = app_usbd_cdc_acm_read(&cmd_cdc_acm, RXbuffer, \
					   sizeof(RXbuffer));
		NRF_LOG_INFO("%s: Size=%lu, buffer=%c/%02x", __func__, \
			     read_size, RXbuffer[0], RXbuffer[0]);

	} while ( rc == NRF_SUCCESS );


	return;
}


static void acm_event_handler(app_usbd_class_inst_t const * p_inst, \
			      app_usbd_cdc_acm_user_event_t event)

{
	app_usbd_cdc_acm_t const * p_cdc_acm = \
		app_usbd_cdc_acm_class_get(p_inst);


	switch ( event ) {
		case APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN:
			NRF_LOG_INFO("PORT OPEN");
			Port_Open = true;
			app_usbd_cdc_acm_read(&cmd_cdc_acm, RXbuffer, \
					      sizeof(RXbuffer));
			break;

		case APP_USBD_CDC_ACM_USER_EVT_RX_DONE:
			NRF_LOG_INFO("RX_DONE");
			_acm_event_read(p_cdc_acm);
			Have_Read = true;
			break;

		case APP_USBD_CDC_ACM_USER_EVT_TX_DONE:
			NRF_LOG_INFO("TX_DONE");
			break;

		case APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE:
			NRF_LOG_INFO("PORT CLOSE");
			break;
	}

	return;
}
			

static void usb_event_handler(app_usbd_event_type_t event)

{
	switch ( event ) {
		case APP_USBD_EVT_DRV_SUSPEND:
			break;

		case APP_USBD_EVT_DRV_RESUME:
			break;

		case APP_USBD_EVT_STARTED:
			break;

		case APP_USBD_EVT_STOPPED:
			app_usbd_disable();
			break;

		case APP_USBD_EVT_POWER_DETECTED:
			if ( !nrf_drv_usbd_is_enabled() )
				app_usbd_enable();
			break;

		case APP_USBD_EVT_POWER_REMOVED:
			app_usbd_stop();
			break;

		case APP_USBD_EVT_POWER_READY:
			app_usbd_start();
			break;

		case APP_USBD_EVT_DRV_RESET:
			break;
		case APP_USBD_EVT_DRV_WUREQ:
			break;
		case APP_USBD_EVT_DRV_SETUP:
			break;
		case APP_USBD_EVT_DRV_EPTRANSFER:
			break;
		case APP_USBD_EVT_FIRST_POWER:
			break;
		case APP_USBD_EVT_FIRST_APP:
			break;
		case APP_USBD_EVT_INST_REMOVE:
			break;
		case APP_USBD_EVT_STATE_CHANGED:
			break;
		case APP_USBD_EVT_FIRST_INTERNAL:
			break;
		case APP_USBD_EVT_START_REQ:
			break;
		case APP_USBD_EVT_STOP_REQ:
			break;
		case APP_USBD_EVT_SUSPEND_REQ:
			break;
		case APP_USBD_EVT_WAKEUP_REQ:
			break;
		case APP_USBD_EVT_SETUP_SETADDRESS:
			break;
		case APP_USBD_EVT_DRV_SOF:
			break;
	}


	return;
}


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
	size_t size;

	static app_usbd_config_t usbd_config = {
		.ev_state_proc = usb_event_handler
	};

	app_usbd_class_inst_t const * class_cdc_acm = \
		app_usbd_cdc_acm_class_inst_get(&cmd_cdc_acm);


	/* Platform initialization. */
	NRF_LOG_INIT(NULL);

	nrf_drv_clock_init();

	nrf_drv_clock_lfclk_request(NULL);
	while ( !nrf_drv_clock_lfclk_is_running() )
		continue;

	app_timer_init();

	console_init();


	/* USB initialization. */
	NRF_LOG_INFO("Starting USB configuration.");
	app_usbd_serial_num_generate();

	app_usbd_init(&usbd_config);
	app_usbd_class_append(class_cdc_acm);

	app_usbd_enable();
	app_usbd_start();


	/* Wait for port open event. */
	NRF_LOG_INFO("Waiting for connection.");
	while ( !Port_Open ) {
		while ( app_usbd_event_queue_process() )
			continue;

		nrf_cli_process(&sancho_console);
		NRF_LOG_PROCESS();
		__WFE();
	}


	NRF_LOG_INFO("Starting USB loop.");
	while ( true ) {
		while ( app_usbd_event_queue_process() )
			continue;

		if ( Have_Read ) {
			NRF_LOG_INFO("Have read indication: buffer=%02x.", \
				     RXbuffer[0]);

			memset(TXbuffer, '\0', sizeof(TXbuffer));
			size = snprintf(TXbuffer, sizeof(TXbuffer), "%s", \
					RXbuffer);
			if ( size >= sizeof(TXbuffer) )
				continue;
			NRF_LOG_INFO("Sending: size=%lu, char=%c/%02x", \
				     size, TXbuffer[0], TXbuffer[0]);
			app_usbd_cdc_acm_write(&cmd_cdc_acm, TXbuffer, 1);
			app_usbd_cdc_acm_serial_state_notify(&cmd_cdc_acm, \
						     APP_USBD_CDC_ACM_SERIAL_STATE_BREAK, \
						     false);
			Have_Read = false;
		}

		nrf_cli_process(&sancho_console);
		NRF_LOG_PROCESS();
		__WFE();
	}
}
