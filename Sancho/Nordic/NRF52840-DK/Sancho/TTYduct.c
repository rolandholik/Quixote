/** \file
 * This file provides the implementation of an object that provides
 * packet based communications over a tty device using interrupt
 * based input.
 */

/**************************************************************************
 * (C)Copyright 2021, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/


/** Define to enable console logging. */
#define CONSOLE_LOGGING 0


/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <nrf_log.h>
#include <nrf_log_ctrl.h>
#include <nrf_log_default_backends.h>

#include <nrf_drv_usbd.h>
#include <app_usbd_core.h>
#include <app_usbd.h>
#include <app_usbd_string_desc.h>
#include <app_usbd_serial_num.h>
#include <app_usbd_cdc_acm.h>

#include <HurdLib.h>

#include <Origin.h>
#include <Buffer.h>
#include <String.h>

#include <NAAAIM.h>
#include "TTYduct.h"

/* State extraction macro. */
#define STATE(var) CO(TTYduct_State, var) = this->state

/* Maximum receive buffer size - 1K. */
#define MAX_RECEIVE_SIZE 1024

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_TTYduct_OBJID)
#error Object identifier not defined.
#endif


/** LocalDuct private state information. */
struct NAAAIM_TTYduct_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* End of transmission flag. */
	_Bool eof;

	/* Debug flag. */
	_Bool debug;
	/* Error code. */
	int error;

	/* Output file descriptor. */
	int fd;
};


/** Flag variable indicating the USB port has been opened. */
static _Bool Port_Open = false;

/** Flag variable indicating the USB port has been closed. */
static _Bool Port_Close = false;

/** Flag variable indicating that a read has completed. */
static _Bool Have_Read = false;

/** Flag variable indicating that a transmit is complete. */
static _Bool TX_Done = false;

/** Total number of blocks and residual data to receive. */
static uint32_t Receive_Blocks	 = 0;
static uint32_t Receive_Residual = 0;

/* Amount of receiver buffer occupied. */
static uint8_t Input_Buffer[NRF_DRV_USBD_EPSIZE];
static uint8_t Receive_Buffer[NRF_DRV_USBD_EPSIZE];

/* Input state. */
static enum {
	receiving_sync=0,
	receiving_size,
	receiving_block,
	receiving_residual,
} Receive_State = receiving_sync;


/* Forward declaration for the USB event handlers. */
static void acm_event_handler(app_usbd_class_inst_t const * p_inst, \
			      app_usbd_cdc_acm_user_event_t event);

static void usb_event_handler(app_usbd_event_type_t event);



APP_USBD_CDC_ACM_GLOBAL_DEF(USB_cdc_acm,			\
			    acm_event_handler,			\
			    0,					\
			    1,					\
			    NRF_DRV_USBD_EPIN2,			\
			    NRF_DRV_USBD_EPIN1,			\
			    NRF_DRV_USBD_EPOUT2,		\
			    APP_USBD_CDC_COMM_PROTOCOL_AT_V250);

/** USB CDC/ACM class definition. */
static app_usbd_config_t USB_config = {
	.ev_state_proc = usb_event_handler
};

static app_usbd_class_inst_t const * USB_cdc_acm_class;


/* Replacements for byte swapping functions. */
static inline uint32_t htonl(uint32_t value)

{
	return value >> 24 | (value >> 8 & 0xff00) | \
		(value << 8 & 0xff0000) | value << 24;
}

static inline uint32_t ntohl(uint32_t value)

{
	return value >> 24 | (value >> 8 & 0xff00) | \
		(value << 8 & 0xff0000) | value << 24;
}


/**
 * Internal static function.
 *
 * This function manages the incoming USB TTYduct receive state.
 *
 * \return	No return value is defined.
 */

static void receive_handler(app_usbd_cdc_acm_t const * acm)

{
	uint32_t read_size,
		 receive_size,
		 request_size = 1;

	static uint8_t sync_char = '@';


	read_size = app_usbd_cdc_acm_rx_size(acm);
	Have_Read = (read_size > 0 );

#if CONSOLE_LOGGING
	NRF_LOG_INFO("%s: Called state=%d, stored=%d, read size=%d, read=%s", \
		     __func__, Receive_State,				      \
		     app_usbd_cdc_acm_bytes_stored(acm), read_size,	      \
		     Have_Read ? "YES" : "NO");
#endif

	if ( !Have_Read )
		return;

	memset(Input_Buffer, '\0', sizeof(Input_Buffer));
	memcpy(Input_Buffer, Receive_Buffer, read_size);

#if CONSOLE_LOGGING
	NRF_LOG_INFO("%s: ib[0]=%02x, ib[1]=%02x, ib[2]=%02x, ib[3]=%02x", \
		     __func__, Input_Buffer[0], Input_Buffer[1],	   \
		     Input_Buffer[2], Input_Buffer[3]);
#endif


	switch ( Receive_State ) {
		case receiving_sync:
#if CONSOLE_LOGGING
			NRF_LOG_INFO("%s: Checking sync: %02x", __func__, \
				     Input_Buffer[0]);
#endif
			if ( Have_Read && (Input_Buffer[0] == '\n') ) {
#if CONSOLE_LOGGING
				NRF_LOG_INFO("%s: Writing sync.", __func__);
#endif
				TX_Done = false;
				app_usbd_cdc_acm_write(&USB_cdc_acm, \
						       &sync_char,   \
						       sizeof(sync_char));
				while ( !TX_Done ) {
					app_usbd_event_queue_process();
				}

				Receive_State = receiving_size;
				request_size = 4;
			}
			break;

		case receiving_size:
			memcpy(&receive_size, Input_Buffer, \
			       sizeof(receive_size));
			receive_size  = ntohl(receive_size);
			Receive_State = receiving_block;

			Receive_Blocks   = receive_size / NRF_DRV_USBD_EPSIZE;
			Receive_Residual = receive_size % NRF_DRV_USBD_EPSIZE;

#if CONSOLE_LOGGING
			NRF_LOG_INFO("%s: Receive size=%d, blocks=%d, "	    \
				     "residual=%d", __func__, receive_size, \
				     Receive_Blocks, Receive_Residual);
#endif

			if ( Receive_Blocks != 0 ) {
				--Receive_Blocks;
				request_size  = NRF_DRV_USBD_EPSIZE;
				Receive_State = receiving_block;
			}
			else {
				request_size  = Receive_Residual;
				Receive_State = receiving_residual;
			}
			break;

		case receiving_block:
			if ( Receive_Blocks == 0 ) {
				if ( Receive_Residual == 0 ) {
					request_size  = 4;
					Receive_State = receiving_size;
				} else {
					request_size  = Receive_Residual;
					Receive_State = receiving_residual;
				}
			}
			else {
				request_size = NRF_DRV_USBD_EPSIZE;
				--Receive_Blocks;
			}
			break;

		case receiving_residual:
			request_size  = 4;
			Receive_State = receiving_size;
			break;
	}


#if CONSOLE_LOGGING
	NRF_LOG_INFO("%s: Scheduling read, state=%d, request=%d", __func__, \
		     Receive_State, request_size);
#endif

	memset(Receive_Buffer, '\0', sizeof(Receive_Buffer));
	app_usbd_cdc_acm_read(&USB_cdc_acm, Receive_Buffer, request_size);

	return;
}


static void acm_event_handler(app_usbd_class_inst_t const * p_inst, \
			      app_usbd_cdc_acm_user_event_t event)

{
	app_usbd_cdc_acm_t const * p_cdc_acm = \
		app_usbd_cdc_acm_class_get(p_inst);


	switch ( event ) {
		case APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN:
#if CONSOLE_LOGGING
			NRF_LOG_INFO("PORT OPEN");
#endif
			Port_Open  = true;
			Port_Close = false;
			app_usbd_cdc_acm_read(&USB_cdc_acm, Receive_Buffer, 1);
			break;

		case APP_USBD_CDC_ACM_USER_EVT_RX_DONE:
#if CONSOLE_LOGGING
			NRF_LOG_INFO("RX_DONE");
#endif
			receive_handler(p_cdc_acm);
			break;

		case APP_USBD_CDC_ACM_USER_EVT_TX_DONE:
			TX_Done = true;
#if CONSOLE_LOGGING
			NRF_LOG_INFO("TX_DONE");
#endif
			break;

		case APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE:
#if CONSOLE_LOGGING
			NRF_LOG_INFO("PORT CLOSE");
#endif
			Port_Open  = false;
			Port_Close = true;
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


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_LocalDuct_State
 * structure which holds state information for each instantiated object.
 * The object is started out in poisoned state to catch any attempt
 * to use the object without initializing it.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(TTYduct_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TTYduct_OBJID;


	S->poisoned = false;
	S->debug    = false;
	S->fd	    = fileno(stdout);

	return;
}


/**
 * External public method.
 *
 * This method initializes a local device for communications.
 *
 * \param this	The communications object for which the device is to be
 *		opened.
 *
 * \param path	The path to the device to be used for this object.
 *
 * \return	If the tty device is successfully opened and initialized
 *		a boolean true value is returned.  If open or
 *		initialization fails a false value is returned and the
 *		object is poisoned.
 */

static _Bool init_device(CO(TTYduct, this), CO(char *, path))

{
	bool retn = false;


	app_usbd_serial_num_generate();
	app_usbd_init(&USB_config);

	app_usbd_cdc_acm_class_inst_get(&USB_cdc_acm);
	USB_cdc_acm_class = app_usbd_cdc_acm_class_inst_get(&USB_cdc_acm);
	app_usbd_class_append(USB_cdc_acm_class);

	app_usbd_enable();
	app_usbd_start();

	/* Clear the receive buffers buffer. */
	memset(Input_Buffer,   '\0', sizeof(Input_Buffer));
	memset(Receive_Buffer, '\0', sizeof(Receive_Buffer));

	Receive_State = receiving_sync;

	retn = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements checking for the acceptance of a connection
 * on a USB port.
 *
 * \param this	The communications object which connection acceptance
 *		is to be checked.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a connection has been detected.  A false value
 *		indicates there is no connection while a true value
 *		indicates a connection is available.
 */

static _Bool accept_connection(CO(TTYduct, this))

{
	if ( Receive_State == receiving_sync ) {
		app_usbd_event_queue_process();
		return false;
	}

#if CONSOLE_LOGGING
	NRF_LOG_INFO("%s: Returning port open, state = %d", __func__, \
		     Receive_State);
#endif
	return Port_Open;
}


/**
 * External public method.
 *
 * This method implements sending the contents of a specified Buffer object
 * over the connection represented by the callingn object.
 *
 * \param this	The LocalDuct object over which the Buffer is to be sent.
 *
 * \return	A boolean value is used to indicate whether or the
 *		write was successful.  A true value indicates the
 *		transmission was successful.
 */

static _Bool send_Buffer(CO(TTYduct, this), CO(Buffer, bf))

{
	STATE(S);

	uint8_t *sp;

	uint32_t blocks,
		 residual;

	_Bool retn = false;

	uint32_t size = htonl(bf->size(bf));

	Buffer bufr = NULL;


	if ( S->poisoned )
		ERR(goto done);
	if ( (bf == NULL) || bf->poisoned(bf))
		ERR(goto done);


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	bufr->add(bufr, (unsigned char *) &size, sizeof(size));
	if ( !bufr->add_Buffer(bufr, bf) )
		ERR(goto done);

	if ( S->debug ) {
		fputs("Sending buffer.\n", stdout);
		bufr->hprint(bufr);
		fflush(stdout);
	}


	/* Calculate blocks and residuals based on USB packet size. */
	blocks	 = bufr->size(bufr) / NRF_DRV_USBD_EPSIZE;
	residual = bufr->size(bufr) % NRF_DRV_USBD_EPSIZE;
#if CONSOLE_LOGGING
	NRF_LOG_INFO("%s: sending blocks=%u, residual=%u", __func__, blocks, \
		     residual);
#endif


	/* Send blocks and residual. */
	sp = bufr->get(bufr);

	while ( blocks-- ) {
		TX_Done = false;
		app_usbd_cdc_acm_write(&USB_cdc_acm, sp, NRF_DRV_USBD_EPSIZE);
		sp += NRF_DRV_USBD_EPSIZE;

		while ( !TX_Done ) {
			app_usbd_event_queue_process();
		}
	}

	if ( residual != 0 ) {
		TX_Done = false;
		app_usbd_cdc_acm_write(&USB_cdc_acm, sp, residual);

		while ( !TX_Done ) {
			app_usbd_event_queue_process();
		}
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);

	return retn;
}


/**
 * External public method.
 *
 * This method implements loading the specified number of bytes into
 * the provided Buffer object.
 *
 * \param this	The object that data is to be read into.
 *
 * \return	A boolean value is used to indicate whether or the
 *		read was successful.  A true value indicates the receive
 *		was successful.
 */

static _Bool receive_Buffer(CO(TTYduct, this), CO(Buffer, bf))

{
	STATE(S);

	_Bool retn = false;


	/* Validate object. */
	if ( S->poisoned )
		ERR(goto done);
	if ( (bf == NULL) || bf->poisoned(bf) )
		ERR(goto done);


#if CONSOLE_LOGGING
	NRF_LOG_INFO("%s: Waiting for size.", __func__);
#endif

	/* Block until USB receive handler has a size. */
	while ( Receive_State == receiving_size ) {
		if ( app_usbd_event_queue_process() ) {
			if ( Port_Close )
				goto closed;
		}
	}
#if CONSOLE_LOGGING
	NRF_LOG_INFO("%s: Have size.", __func__);
#endif


	Have_Read = false;
	while ( Receive_State == receiving_block ) {
		if ( app_usbd_event_queue_process() ) {
			if ( Port_Close )
				goto closed;
			if ( Have_Read ) {
				Have_Read = false;
				if ( !bf->add(bf, Input_Buffer, \
					      NRF_DRV_USBD_EPSIZE) )
					ERR(goto done);
			}
		}
	}
#if CONSOLE_LOGGING
	NRF_LOG_INFO("%s: Received blocks.", __func__);
#endif


	/* Receive the residual data. */
	Have_Read = false;
	while ( Receive_State == receiving_residual ) {
		if ( app_usbd_event_queue_process() ) {
			if ( Port_Close )
				goto closed;
			if ( Have_Read ) {
				Have_Read = false;
				if ( !bf->add(bf, Input_Buffer, \
					      Receive_Residual) )
					ERR(goto done);
			}
		}
	}

#if CONSOLE_LOGGING
	NRF_LOG_INFO("%s: Received residual, size=%lu, bufr size=%lu", \
		     __func__, Receive_Residual, bf->size(bf));
#endif
	retn = true;


 done:
	memset(Input_Buffer,   '\0', sizeof(Input_Buffer));
	memset(Receive_Buffer, '\0', sizeof(Receive_Buffer));

	Receive_Blocks	 = 0;
	Receive_Residual = 0;

	if ( !retn )
		S->poisoned = true;

	return retn;


 closed:
#if CONSOLE_LOGGING
	NRF_LOG_INFO("Port closed.");
#endif
	memset(Input_Buffer,   '\0', sizeof(Input_Buffer));
	memset(Receive_Buffer, '\0', sizeof(Receive_Buffer));

	Receive_Blocks 	 = 0;
	Receive_Residual = 0;
	Receive_State	 = receiving_sync;

	return false;
}


/**
 * External public method.
 *
 * This method activates debug mode for the object.
 *
 * \param this	A pointer to the object which is to have debug mode
 *		activated.
 */

static void debug(CO(TTYduct, this))

{
	STATE(S);


	S->debug = true;

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a LocalDuct object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(TTYduct, this))

{
	STATE(S);


	/* Destroy resources. */
	S->root->whack(S->root, this, S);

	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a LocalDuct object.
 *
 * \return	A pointer to the initialized LocalDuct.  A null value
 *		indicates an error was encountered in object generation.
 */

extern TTYduct NAAAIM_TTYduct_Init(void)

{
	Origin root;

	TTYduct this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_TTYduct);
	retn.state_size   = sizeof(struct NAAAIM_TTYduct_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_TTYduct_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->init_device	= init_device;
	this->accept_connection	= accept_connection;

	this->send_Buffer	= send_Buffer;
	this->receive_Buffer	= receive_Buffer;

	this->debug		= debug;

	this->whack		= whack;

	return this;
}
