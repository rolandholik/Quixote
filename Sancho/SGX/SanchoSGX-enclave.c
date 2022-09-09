/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <SHA256.h>

#include <NAAAIM.h>

#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include "SanchoSGX-interface.h"
#include "regex.h"
#include "SecurityPoint.h"
#include "SecurityEvent.h"
#include "TSEM.h"
#include "SanchoSGX.h"


/**
 * The model being implemented.
 */
TSEM Model = NULL;


/**
 * Internal private function.
 *
 * This method is responsible for marshalling arguements and generating
 * the OCALL for a request to discipline a process which has been
 * determined to have engaged in an extra-dimensional behavior
 *
 * \param ocall	The structure used to marshall the arguements for
 *		the ocall.
 *
 * \return	An integer value is used to indicate the status of
 *		the SGX call.  A value of zero indicate there was no
 *		error while a non-zero value, particularly negative
 *		indicates an error occurred in the call.  The return
 *		value from the external object is embedded in the
 *		data marshalling structure.
 */

static int discipline_ocall(struct SanchoSGX_ocall *ocall)

{
	_Bool retn = false;

	int status = SGX_ERROR_INVALID_PARAMETER;

	size_t arena_size = sizeof(struct SanchoSGX_ocall);

	struct SanchoSGX_ocall *ocp = NULL;


	/* Allocate and initialize the outbound method structure. */
	if ( (ocp = sgx_ocalloc(arena_size)) == NULL )
		goto done;

	memset(ocp, '\0', arena_size);
	*ocp = *ocall;


	/* Setup arena and pointers to it. */
	if ( ocall->ocall == SanchoSGX_discipline )
		ocp->pid = ocall->pid;


	/* Call the SanchoSGX ocall routine. */
	if ( (status = sgx_ocall(SRDENAAAIM_MAX_OCALL + 1, ocp)) == 0 ) {
		retn = true;
		*ocall = *ocp;
	}


 done:
	sgx_ocfree();

	if ( status != 0 )
		return status;
	if ( !retn )
		return SGX_ERROR_UNEXPECTED;
	return 0;
}


/**
 * External ECALL 0.
 *
 * This method implements the initialization of the SecurityState model
 * inside of the enclave.
 *
 * \param init	A boolean value used to indicate whether the model
 *		should be initialized or destroyed.
 *
 * \return	A boolean value is used to indicate whether or not
 *		initialization of the model succeeded.  A false value
 *		indicates initialization failed while a true value
 *		indicates the enclave is ready to receive measurements.
 */

_Bool init_model(_Bool init)

{
	_Bool retn = false;


	if ( init ) {
		INIT(NAAAIM, TSEM, Model, ERR(goto done));
	}
	else
		WHACK(Model);

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
 * \param ecall1	A pointer to the structure which contains
 *			the inputs to this function.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the update to the model had succeeded.  A false value
 *		indicates the update had failed while a true value
 *	        indicates the enclave model had been updated.
 */

_Bool update_model(struct ISOidentity_ecall1_interface *ecall1)

{
	_Bool updated,
	      retn = false;

	pid_t pid;

	struct SanchoSGX_ocall ocall;

	String input = NULL;

	SecurityEvent event = NULL;


	/* Initialize a string object with the model update. */
	INIT(HurdLib, String, input, ERR(goto done));
	if ( !input->add(input, ecall1->update) )
		ERR(goto done);


	/* Parse and measure the event. */
	INIT(NAAAIM, SecurityEvent, event, ERR(goto done));
	if ( !event->parse(event, input) )
		ERR(goto done);


	/* Update the model. */
	if ( !Model->update(Model, event, &updated, &ecall1->discipline, \
			    &ecall1->sealed) )
		ERR(goto done);
	if ( !updated )
		WHACK(event);
	if ( !Model->discipline_pid(Model, &pid) )
		ERR(goto done);

	memset(&ocall, '\0', sizeof(struct SanchoSGX_ocall));
	ocall.pid	 = pid;
	ocall.debug	 = ecall1->debug;
	ocall.ocall	 = SanchoSGX_discipline;
	ocall.discipline = ecall1->discipline;
	if ( discipline_ocall(&ocall) != 0 )
		ERR(goto done);

	retn = true;


 done:
	WHACK(input);

	return retn;
}


/**
 * External ECALL.
 *
 * This method implements adding entries into a security model.
 *
 * \param ecall12	A pointer to the structure that describes the
 *			entry to be added.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the entry was successfully added to the model.  A false
 *		value indicates the update had failed while a true
 *		value indicates the model was updated.
 */

_Bool load(struct ISOidentity_ecall12_interface *ecall12)

{
	_Bool retn = false;

	String entry = NULL;


	/* Initialize a Buffer object with the point. */
	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, ecall12->update) )
		ERR(goto done);


	/* Update the model. */
	if ( !Model->load(Model, entry) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(entry);

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
		case ISO_IDENTITY_EVENT:
			size = Model->points_size(Model);
			break;
		case ISO_IDENTITY_FORENSICS:
			size = Model->forensics_size(Model);
			break;
		case DOMAIN_POINTS:
			size = Model->trajectory_size(Model);
			break;
		case TSEM_EVENTS:
			size = Model->TSEM_events_size(Model);
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

	fputs("Points:\n", stdout);
	Model->dump_points(Model);
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
 * External ECALL 14
 *
 * This method implements adding an AI event to the ISOidentity model
 * being implemented inside the enclave being managed by an instance
 * of this object.
 *
 * \param ecall14	A pointer to the structure which marshalls
 *			the inputs to this function.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the update to the model succeeded.  A false value
 *		indicates the update had failed while a true value
 *	        indicates the enclave model had been updated.
 */

_Bool add_ai_event(struct ISOidentity_ecall14 *ecall14)

{
	_Bool retn = false;

	String event = NULL;


	/* Verify the model is initialized. */
	if ( Model == NULL )
		ERR(goto done);


	/*
	 * Load the aggregate value into an object for submission
	 * to the model and then set the aggregate value.
	 */
	INIT(HurdLib, String, event, ERR(goto done));
	if ( !event->add(event, (char *) ecall14->ai_event) )
		ERR(goto done);

	if ( !Model->add_TSEM_event(Model, event) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External ECALL.
 *
 * This method implements retrieving the security domain attestation
 * value.
 *
 * \param aggregate	The buffer which will be loaded with the
 *			binary measurement value.  This routine
 *			assumes the length of the buffer to be
 *			the current identity size of 32 bytes.
 *
 * \param type		An integer value indicating the type of
 *			measurement to be returned.  A value of zero
 *			indicates that the time domain dependent
 *			measurement is to be returned.  A value of
 *			one indicates that the time independent state
 *			value should be returned.
 *
 * \return		A boolean value is returned to indicate the
 *			status of the retrieval of the measurement
 *			value.  A false value indicates the buffer
 *			does not have a valid measurement while a
 *			true value indicates the measurement is
 *			valid.
 */

_Bool get_measurement(unsigned char *measurement, int type)

{
	_Bool retn = false;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( type == DOMAIN_MEASUREMENT ) {
		if ( !Model->get_measurement(Model, bufr) )
			ERR(goto done);
	}
	else {
		if ( !Model->get_state(Model, bufr) )
			ERR(goto done);
	}

	memcpy(measurement, bufr->get(bufr), bufr->size(bufr));
	retn = true;


 done:
	WHACK(bufr);

	return retn;
}


/**
 * External ECALL.
 *
 * This method implements retrieving the process ID value of an
 * event.
 *
 * \param pidptr	A pointer to the variable which the PID is
 *			to be copied into.
 *
 * \return		A boolean value is returned to indicate the
 *			status of the retrieval of the PID value.
 *			A false value indicates the variable does not
 *			have a valid PID while a true value indicates
 *			the PID is valid.
 */

_Bool get_pid(pid_t *pidptr)

{
	_Bool retn = false;

	pid_t pid;


	if ( !Model->discipline_pid(Model, &pid) )
		ERR(goto done);

	*pidptr = pid;
	retn = true;


 done:
	return retn;
}


/**
 * External ECALL.
 *
 * This method implements the reset of the three model components.
 * The component to be reset is signalled through an arguement to
 * the caller.
 *
 * \param type	The type of the event to be reset.  The available
 *		defines to select these are in the interface
 *		definition file.  The possible types are events,
 *		contours and forensics.
 *
 * \return	No return value is defined.
 */

void rewind(int type)

{
	switch ( type ) {
		case ISO_IDENTITY_EVENT:
			Model->rewind_event(Model);
			break;
		case ISO_IDENTITY_FORENSICS:
			Model->rewind_forensics(Model);
			break;
		case DOMAIN_POINTS:
			Model->rewind_points(Model);
			break;
		case TSEM_EVENTS:
			Model->TSEM_rewind_event(Model);
			break;
	}

	return;
}


/**
 * External ECALL.
 *
 * This method implements the retrieval of model events.  The
 * function is designed to be multiplexed by the arguement to the
 * function which selects either accepted model update events or
 * events which have been tagged as forensic violations.  This is
 * once again to decreate the number of interfaces into the enclace
 * which are required.
 *
 * Since enclaves do not have a good method for returning
 * null-terminated strings this function takes a length value and
 * the function verifies that the event value being returned does
 * not exceed this value.
 *
 * \param type	The type of the event to be reset.  The available
 *		defines to select these are in the interface
 *		definition file.  The possible types are standard
 *		model update events and those that are classified as
 *		forensic events.
 *
 * \param event A pointer to the buffer which the event will be
 *		loaded into.
 *
 * \param size	The size of the buffer which is available to hold
 *		the event.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid value is returned.  A false value indicates
 *		a valid event is not available while a true value
 *		indicates the event return was valid.
 */

_Bool get_event(char type, char *update, size_t size)

{
	_Bool retn = false;

	String es = NULL;

	SecurityEvent event;


	memset(update, '\0', size);


	if ( type == TSEM_EVENTS ) {
		if ( !Model->get_TSEM_event(Model, &es) )
			ERR(goto done);
		if ( es == NULL ) {
			retn = true;
			goto done;
		}

		if ( (es->size(es) + 1) > size )
			ERR(goto done);
		memcpy(update, es->get(es), es->size(es));

		es   = NULL;
		retn = true;
		goto done;
	}


	INIT(HurdLib, String, es, ERR(goto done));

	if ( type == ISO_IDENTITY_EVENT ) {
		if ( !Model->get_event(Model, &event) )
			ERR(goto done);
		if ( event == NULL ) {
			retn = true;
			goto done;
		}
	}
	if ( type == ISO_IDENTITY_FORENSICS ) {
		if ( !Model->get_forensics(Model, &event) )
			ERR(goto done);
		if ( event == NULL ) {
			retn = true;
			goto done;
		}
	}


	if ( !event->format(event, es) )
		ERR(goto done);
	if ( (es->size(es) + 1) > size )
		ERR(goto done);
	memcpy(update, es->get(es), es->size(es));

	retn = true;


 done:
	WHACK(es);

	return retn;
}


/**
 * External ECALL 15.
 *
 * This method implements the retrieval of security event state points
 *
 * \param point		A character pointer to the buffer that the binary
 *			value of the state point will be loaded into.
 *			An assumption is made that the pointer
 *			references an area large enough to hold
 *			the binary value of a state point.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid value is returned.  A false value indicates
 *		a valid event is not available while a true value
 *		indicates the event return was valid.
 */

_Bool get_point(unsigned char *pt)

{
	_Bool retn = false;

	SecurityPoint cp = NULL;


	if ( !Model->get_point(Model, &cp) )
		ERR(goto done);
	if ( cp == NULL )
		ERR(goto done);

	cp->get(cp);
	memcpy(pt, cp->get(cp), NAAAIM_IDSIZE);

	retn = true;


 done:
	return retn;
}
