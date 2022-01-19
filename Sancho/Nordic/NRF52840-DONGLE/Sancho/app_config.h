/** \file
 * This file contains configuration overrides for the Nordic development
 * kit for the Sancho implementation.
 */

/**************************************************************************
 * (C)Copyright 2022, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/


/* Turn off the console command-line interface. */
#define NRF_CLI_UART_ENABLED		0
#define NRF_CLI_LOG_BACKEND		0
#define NRF_LOG_BACKEND_UART_ENABLED	0
#define NRF_LOG_ENABLED			0


/* Define the product name for the USB CDC-ACM device. */
#define APP_USBD_STRINGS_PRODUCT APP_USBD_STRING_DESC("Enjellic SanchoMCU")
