#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <SHA256.h>

#include <NAAAIM.h>

#include "ISOidentity-interface.h"
#include "regex.h"
#include "ContourPoint.h"
#include "ExchangeEvent.h"
#include "ISOidentity.h"


/**
 * The model being implemented.
 */
ISOidentity Model = NULL;


/**
 * External ECALL 0.
 *
 * This method implements the initialization of the ISOidentity model
 * inside of the enclave.
 *
 * \return	A boolean value is used to indicate whether or not
 *		initialization of the model succeeded.  A false value
 *		indicates initialization failed while a true value
 *		indicates the enclave is ready to receive measurements.
 */

_Bool init_model(void)

{
	_Bool retn = false;


	INIT(NAAAIM, ISOidentity, Model, ERR(goto done));
	retn = true;


 done:

	return retn;
}


/**
 * External ECALL 1.
 *
 * This method implements adding updates to the ISOidentity model
 * being implemented inside an enclave.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the update to the model had succeeded.  A false value
 *		indicates the update had failed while a true value
 *	        indicates the enclave model had been updated.
 */

_Bool update_model(char *update)

{
	_Bool updated,
	      discipline,
	      retn = false;

	String input = NULL;

	ExchangeEvent event = NULL;


	/* Initialize a string object with the model update. */
	INIT(HurdLib, String, input, ERR(goto done));
	if ( !input->add(input, update) )
		ERR(goto done);


	/* Parse and measure the event. */
	INIT(NAAAIM, ExchangeEvent, event, ERR(goto done));
	if ( !event->parse(event, input) )
		ERR(goto done);
	if ( !event->measure(event) )
		ERR(goto done);


	/* Update the model. */
	if ( !Model->update(Model, event, &updated, &discipline) )
		ERR(goto done);
	if ( !updated )
		WHACK(event);

	retn = true;


 done:
	WHACK(input);

	return retn;
}


/**
 * External ECALL 2.
 *
 * This method implements sealing the current state of the model.
 *
 * \return	No return value is defined.
 */

void seal_model(void)

{
	Model->seal(Model);
	return;
}


/**
 * External ECALL.
 *
 * This function implements returning the size of the model.  In order
 * to reduce the number of required ECALL's the element size being
 * requested is encoded by an arguement to this call.
 *
 * \param type	Specifies which model size is to be returned.  The
 *		options which can be selected are either the general
 *		size of the model or the size of the forensics
 *		elements.
 *
 * \returns	The number of elements in the model.  The default
 *		value returned is 0 which is also returned if the
 *		model is not initialized.
 */

size_t get_size(int type)

{
	size_t size = 0;


	/* Verify that model is initialized. */
	if ( Model == NULL )
		ERR(goto done);


	/* Return the requested model size. */
	switch ( type ) {
		case 0:
			size = Model->size(Model);
			break;
		case 1:
			size = Model->forensics_size(Model);
			break;
	}


 done:
	return size;
}


/**
 * External ECALL 3.
 *
 * This method implements dumping the current state of the model.
 *
 * \return	No return value is defined.
 */

void dump_model(void)

{
	fputs("Events:\n", stdout);
	Model->dump_events(Model);

	fputs("Contours:\n", stdout);
	Model->dump_contours(Model);
	fputc('\n', stdout);

	fputs("Forensics:\n", stdout);
	Model->dump_forensics(Model);

	return;
}


/**
 * External ECALL.
 *
 * This method implements setting the aggregate measurement value
 * for the model.
 *
 * \param aggregate	The buffer containing the binary value
 *			of the aggregate.
 *
 * \param length	The size of the buffer.
 *
 * \return		A boolean value is used to indicate the
 *			status of setting the aggregate.  A false
 *			value indicates the aggregate value was not
 *			set with a true value indicating the model
 *			aggregate has been set.
 */

_Bool set_aggregate(unsigned char *aggregate, size_t length)

{
	_Bool retn = false;

	Buffer bufr = NULL;


	/* Verify the model is initialized. */
	if ( Model == NULL )
		ERR(goto done);


	/*
	 * Load the aggregate value into an object for submission
	 * to the model and then set the aggregate value.
	 */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, aggregate, length) )
		ERR(goto done);

	if ( !Model->set_aggregate(Model, bufr) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(bufr);

	return retn;
}


/**
 * External ECALL.
 *
 * This method implements retrieving the current measurement value
 * from the model.
 *
 * \param aggregate	The buffer which will be loaded with the
 *			binary measurement value.  This routine
 *			assumes the length of the buffer to be
 *			the current identity size of 32 bytes.
 *
 * \return		A boolean value is returned to indicate the
 *			status of the retrieval of the measurement
 *			value.  A false value indicates the buffer
 *			does not have a valid measurement while a
 *			true value indicates the measurement is
 *			valid.
 */

_Bool get_measurement(unsigned char *measurement)

{
	_Bool retn = false;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( !Model->get_measurement(Model, bufr) )
		ERR(goto done);

	memcpy(measurement, bufr->get(bufr), bufr->size(bufr));
	retn = true;


 done:
	WHACK(bufr);

	return retn;
}
