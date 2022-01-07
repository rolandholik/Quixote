/** \file
 * This file provides the implementation of an object that provides
 * packet based communications over a tty device using interrupt
 * based input.
 */

/**************************************************************************
 * (C)Copyright 2021, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

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

/* Amount of data to be received. */
static uint32_t Receive_Size;

/* Amount of receiver buffer occupied. */
static uint32_t Input_Size;
static uint8_t Input_Byte;
static uint8_t Input_Buffer[MAX_RECEIVE_SIZE];

/* Input state. */
static enum {
	receiving_sync=0,
	receiving_size,
	receiving_buffer,
	received_buffer
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

static void _acm_event_read(app_usbd_cdc_acm_t const * acm)

{
	size_t read_size = app_usbd_cdc_acm_rx_size(acm);


	app_usbd_cdc_acm_read(&USB_cdc_acm, &Input_Byte, \
			      sizeof(Input_Byte));
	if ( read_size > 0 )
		Have_Read = true;
#if 0
	NRF_LOG_INFO("%s: rc=%d, Input=%c/%02x", __func__, rc, Input_Byte, \
		     Input_Byte);
#endif

	return;
}


static void acm_event_handler(app_usbd_class_inst_t const * p_inst, \
			      app_usbd_cdc_acm_user_event_t event)

{
	app_usbd_cdc_acm_t const * p_cdc_acm = \
		app_usbd_cdc_acm_class_get(p_inst);


	switch ( event ) {
		case APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN:
#if 1
			NRF_LOG_INFO("PORT OPEN");
#endif
			Port_Open  = true;
			Port_Close = false;
			_acm_event_read(p_cdc_acm);
			break;

		case APP_USBD_CDC_ACM_USER_EVT_RX_DONE:
#if 1
			NRF_LOG_INFO("RX_DONE");
#endif
			_acm_event_read(p_cdc_acm);
			break;

		case APP_USBD_CDC_ACM_USER_EVT_TX_DONE:
			TX_Done = true;
#if 1
			NRF_LOG_INFO("TX_DONE");
#endif
			break;

		case APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE:
#if 1
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
 * This function manages the USB incoming state.
 *
 * \return	No return value is defined.
 */

static void receive_handler(void)

{
	static uint8_t sync_char = '@';


	switch ( Receive_State ) {
		case receiving_sync:
			if ( Input_Byte == '\n' ) {
				TX_Done = false;
				app_usbd_cdc_acm_write(&USB_cdc_acm, \
						       &sync_char,   \
						       sizeof(sync_char));
				while ( !TX_Done ) {
					app_usbd_event_queue_process();
				}
				Receive_State = receiving_size;
				goto done;
			}
			break;

		case receiving_size:
		        Input_Buffer[Input_Size] = Input_Byte;
			if ( ++Input_Size < sizeof(uint32_t) )
				goto done;

			memcpy(&Receive_Size, Input_Buffer, \
			       sizeof(Receive_Size));
			Receive_Size  = ntohl(Receive_Size);
			Receive_State = receiving_buffer;

			memset(Input_Buffer, '\0', Input_Size);
			Input_Size = 0;
			break;

		case receiving_buffer:
		        Input_Buffer[Input_Size] = Input_Byte;
			if ( ++Input_Size == Receive_Size )
				Receive_State = received_buffer;
			break;

		case received_buffer:
			break;
	}


 done:
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

	/* Clear the input buffer. */
	Input_Size    = 0;
	memset(Input_Buffer, '\0', sizeof(Input_Buffer));

	Receive_Size  = 0;
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
		if ( app_usbd_event_queue_process() ) {
			if ( Have_Read ) {
				receive_handler();
				Have_Read = false;
			}
		}
		return false;
	}

	NRF_LOG_INFO("%s: Returning port open, state = %d", __func__, \
		     Receive_State);
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
#if 1
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


	NRF_LOG_INFO("Waiting for size.");

	/* Block until USB receive handler has a size. */
	while ( Receive_State == receiving_size ) {
		if ( app_usbd_event_queue_process() ) {
			if ( Port_Close )
				goto closed;
			if ( Have_Read ) {
				receive_handler();
				Have_Read = false;
			}
		}
		__WFE();
	}
	NRF_LOG_INFO("Have size: %lu", Receive_Size);


	/* Block until the USB receive handler has the packet being sent. */
	while ( Receive_State == receiving_buffer ) {
		if ( app_usbd_event_queue_process() ) {
			if ( Port_Close )
				goto closed;
			if ( Have_Read ) {
				receive_handler();
				Have_Read = false;
			}
		}
		__WFE();
	}
	NRF_LOG_INFO("Have buffer.");
	

	/* Load the buffer with the input stream and reset input. */
	if ( !bf->add(bf, Input_Buffer, Receive_Size) )
		ERR(goto done);
	retn = true;


 done:
	Input_Size = 0;
	memset(Input_Buffer, '\0', sizeof(Input_Buffer));

	Receive_Size  = 0;
	Receive_State = receiving_size;

	if ( !retn )
		S->poisoned = true;

	return retn;


 closed:
	NRF_LOG_INFO("Port closed.");

	Input_Size = 0;
	memset(Input_Buffer, '\0', sizeof(Input_Buffer));

	Receive_Size  = 0;
	Receive_State = receiving_sync;

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
