/** \file
 * This file contains the implementation of an object which manages
 * communications with an ISOidentity model running in an SGX enclave.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#define SGX_DEVICE "/dev/isgx"


/* Include files. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <Duct.h>

#include <SRDE.h>
#include <SRDEenclave.h>
#include <SRDEquote.h>
#include <SRDEocall.h>
#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include <SecurityPoint.h>
#include <SecurityEvent.h>

#include <TSEMcontrol.h>

#include "SanchoSGX.h"
#include "SanchoSGX-interface.h"


/* Object state extraction macro. */
#define STATE(var) CO(SanchoSGX_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SanchoSGX_OBJID)
#error Object identifier not defined.
#endif


/**
 * The object that controls the TSEM implementation.
 */
static TSEMcontrol Control = NULL;


/* OCALL interface to handle the request to discipline a process. */
static int discipline_pid_ocall(struct SanchoSGX_ocall *oc)

{
	_Bool retn = false;


	if ( oc->discipline ) {
		if ( Control->discipline(Control, oc->pid) )
			ERR(goto done);
	} else {
		if ( Control->release(Control, oc->pid) )
			ERR(goto done);
	}

	retn = true;


 done:
	oc->retn = retn;
	return 0;
}


/** SanchoSGX private state information. */
struct NAAAIM_SanchoSGX_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;
	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Debug status of the enclave. */
	_Bool debug;

	/* Enclave error code. */
	int enclave_error;

	/* SGX enclave object. */
	SRDEenclave enclave;

	/* OCALL dispatch handlers. */
	SRDEocall ocall;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the
 * NAAAIM_SanchoSGX_State structure which holds state information
 * for the object.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(SanchoSGX_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SanchoSGX_OBJID;

	S->poisoned	 = false;
	S->debug	 = false;
	S->enclave_error = 0;

	S->enclave = NULL;
	S->ocall   = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements opening the SGX enclave which will implement
 * the ISOidentity model in a trusted environment.
 *
 * \param this 		A pointer to the object which will manage
 *			communications with the enclave.
 *
 * \param enclave	A null terminated buffer containing the name
 *			of the enclave to load.
 *
 * \param token		A null terminated buffer containing the name
 *			of the file containing the initialization
 *			token.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the enclave was successfully loaded..  A false value
 *		indicates a failure while a true value indicates
 *	        the enclave was loaded an initialized.
 */

static _Bool load_enclave(CO(SanchoSGX, this), CO(char *, enclave), \
			  CO(char *, token))

{
	STATE(S);

	int rc;

	_Bool retn = false;

	struct SGX_einittoken *einit_token;

	struct ISOidentity_ecall0_interface ecall0;

	struct OCALL_api *ocall_table;

	Buffer tbufr = NULL;

	File token_file = NULL;


	/* Load the EINITTOKEN. */
	INIT(HurdLib, File, token_file, ERR(goto done));
	INIT(HurdLib, Buffer, tbufr, ERR(goto done));

	if ( !token_file->open_ro(token_file, token) )
		ERR(goto done);
	if ( !token_file->slurp(token_file, tbufr) )
		ERR(goto done);
	einit_token = (struct SGX_einittoken *) tbufr->get(tbufr);


	/* Load and initialize the enclave. */
	INIT(NAAAIM, SRDEenclave, S->enclave, ERR(goto done));

	if ( !S->enclave->open_enclave(S->enclave, SGX_DEVICE, enclave, \
				       ENCLAVE_DEBUG) )
		ERR(goto done);

	if ( !S->enclave->create_enclave(S->enclave) )
		ERR(goto done);

	if ( !S->enclave->load_enclave(S->enclave) )
		ERR(goto done);

	if ( !S->enclave->init_enclave(S->enclave, einit_token) )
		ERR(goto done);


	/* Setup the OCALL dispatch table. */
	INIT(NAAAIM, SRDEocall, S->ocall, ERR(goto done));

	S->ocall->add_table(S->ocall, SRDEfusion_ocall_table);
	S->ocall->add_table(S->ocall, SRDEnaaaim_ocall_table);
	S->ocall->add(S->ocall,	discipline_pid_ocall);

	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);


	/* Call ECALL slot 0 to initialize the ISOidentity model. */
	ecall0.init = true;

	if ( !S->enclave->boot_slot(S->enclave, 0, ocall_table, &ecall0, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall0.retn )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(tbufr);
	WHACK(token_file);

	return retn;
}


/**
 * External public method.
 *
 * This method implements opening a SanchoSGX trusted modeling agent
 * from a memory image.
 *
 * \param this 		A pointer to the SanchoSGX modeling object.
 *
 * \param enclave	A pointer to the memory buffer containing
 *			the enclave to load.
 *
 * \param size		The size of the memory buffer containing the
 *			enclave image.
 *
 * \param token		A null terminated buffer containing the name
 *			of the file containing the initialization
 *			token.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the enclave was successfully loaded..  A false value
 *		indicates a failure while a true value indicates
 *	        the enclave was loaded an initialized.
 */

static _Bool load_enclave_memory(CO(SanchoSGX, this), CO(uint8_t *, enclave), \
				 size_t size, CO(char *, token))

{
	STATE(S);

	int rc;

	_Bool retn = false;

	struct SGX_einittoken *einit_token;

	struct ISOidentity_ecall0_interface ecall0;

	struct OCALL_api *ocall_table;

	Buffer tbufr = NULL;

	File token_file = NULL;


	/* Initialize the static TSEM control instance once. */
	if ( Control == NULL )
		INIT(NAAAIM, TSEMcontrol, Control, ERR(goto done));


	/* Load the EINITTOKEN. */
	INIT(HurdLib, File, token_file, ERR(goto done));
	INIT(HurdLib, Buffer, tbufr, ERR(goto done));

	if ( !token_file->open_ro(token_file, token) )
		ERR(goto done);
	if ( !token_file->slurp(token_file, tbufr) )
		ERR(goto done);
	einit_token = (struct SGX_einittoken *) tbufr->get(tbufr);


	/* Load and initialize the enclave. */
	INIT(NAAAIM, SRDEenclave, S->enclave, ERR(goto done));

	if ( !S->enclave->open_enclave_memory(S->enclave, SGX_DEVICE, \
					      (const char *) enclave, size,
					      ENCLAVE_DEBUG) )
		ERR(goto done);

	if ( !S->enclave->create_enclave(S->enclave) )
		ERR(goto done);

	if ( !S->enclave->load_enclave(S->enclave) )
		ERR(goto done);

	if ( !S->enclave->init_enclave(S->enclave, einit_token) )
		ERR(goto done);


	/* Setup the OCALL dispatch table. */
	INIT(NAAAIM, SRDEocall, S->ocall, ERR(goto done));

	S->ocall->add_table(S->ocall, SRDEfusion_ocall_table);
	S->ocall->add_table(S->ocall, SRDEnaaaim_ocall_table);
	S->ocall->add(S->ocall,	discipline_pid_ocall);

	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);


	/* Call ECALL slot 0 to initialize the ISOidentity model. */
	ecall0.init = true;

	if ( !S->enclave->boot_slot(S->enclave, 0, ocall_table, &ecall0, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall0.retn )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(tbufr);
	WHACK(token_file);

	return retn;
}


/**
 * External public method.
 *
 * This method implements updating the currently maintained behavioral
 * model with an information exchange event.
 *
 * \param this		A pointer to the object which is being modeled.
 *
 * \param update	The object containing the event which is to be
 *			registered.
 *
 * \param discipline	A pointer to a boolean value used to inform
 *			the caller as to whether or not the update
 *			requires the process to be disciplined.
 *
 * \param sealed	A poiner to a boolean value that is used to
 *			advise the caller whether or not the model
 *			was sealed.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the the event was registered.  A false value indicates
 *		a failure while a true value indicates the model
 *		was updated.
 */

static _Bool update(CO(SanchoSGX, this), CO(String, update), \
		    _Bool *discipline, _Bool *sealed)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall1_interface ecall1;


	/* Verify object status and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( update == NULL )
		ERR(goto done);
	if ( update->poisoned(update) )
		ERR(goto done);


	/* Call ECALL slot 0 to initialize the ISOidentity model. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall1.update = update->get(update);

	if ( !S->enclave->boot_slot(S->enclave, 1, ocall_table, &ecall1, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall1.retn )
		ERR(goto done);

	*discipline = ecall1.discipline;
	*sealed	    = ecall1.sealed;
	retn	    = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the loading of entries into a security model.
 *
 * \param this		A pointer to the object that is being modeled.
 *
 * \param entry		An object that contains the description of the
 *			entry that is to be entered into the security
 *			model.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the entry was successfully loaded into the security
 *		model.  A false value indicates a failure occurred while
 *		a true value indicates the security model was
 *		successfully updated.
 */

static _Bool load(CO(SanchoSGX, this), CO(String, entry))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall12_interface ecall12;


	/* Verify object status and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( entry == NULL )
		ERR(goto done);
	if ( entry->poisoned(entry) )
		ERR(goto done);


	/* Initialize the static TSEM control instance once. */
	if ( Control == NULL )
		INIT(NAAAIM, TSEMcontrol, Control, ERR(goto done));


	/* Call ECALL slot 12 to add the entry to the TSEM model. */

	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall12.update = entry->get(entry);

	if ( !S->enclave->boot_slot(S->enclave, 12, ocall_table, &ecall12, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall12.retn )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements initializing the model with an aggregate
 * measurement value.  The aggregate value typically reflects a
 * hardware root of trust value.
 *
 * \param this	A pointer to the canister whose aggregate value is
 *		to be set.
 *
 * \param bufr	The object containing the aggregate value to be
 *		used.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the aggregate measurement was successfully set.  A
 *		false value indicate a failure in returning measurement
 *		while a true value indicates the object contains a valid
 *		measurement.
 */

static _Bool set_aggregate(CO(SanchoSGX, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall5_interface ecall5;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Call ECALL slot 5 to set the model aggregate. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall5.aggregate	= bufr->get(bufr);
	ecall5.aggregate_length = bufr->size(bufr);

	if ( !S->enclave->boot_slot(S->enclave, 5, ocall_table, &ecall5, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall5.retn )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements adding an AI introspection event to the
 * current behavioral model.
 *
 * \param this	A pointer to the canister which is to have an
 *		introspection event added to it.
 *
 * \param event	The object containing the description of the AI event.
 *
 * \return	A boolean value is used to indicate whether or not
 *		addition of the AI event was successful.  A false value
 *		indicates a failure in adding the event while a true
 *		value indicates the model was successfully updated.
 */

static _Bool add_ai_event(CO(SanchoSGX, this), CO(String, event))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall14 ecall14;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event == NULL )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);


	/* Call ECALL slot 15 to set the AI event. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall14.ai_event      = (uint8_t *) event->get(event);
	ecall14.ai_event_size = event->size(event) + 1;

	if ( !S->enclave->boot_slot(S->enclave, 14, ocall_table, &ecall14, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall14.retn )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for retrieving a TE event from a
 * security domain model.  This method is designed to be called
 * repeatedly until the list of events is completely traversed.  The
 * traversal can be reset by calliong the ->rewind_event method.
 *
 * \param this	A pointer to the security domain whose TE events are to
 *		be retrieved.
 *
 * \param event	The object which the event will be copied into.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid event was returned.  A false value
 *		indicates a failure occurred and a valid event is
 *		not available.  A true value indicates the event
 *		object contains a valid value.
 *
 *		The end of the event list is signified by a NULL
 *		event object being set.
 */

static _Bool get_te_event(CO(SanchoSGX, this), String event)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall9_interface ecall9;


	/* Verify object and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event == NULL )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);


	/* Call slot 9 to get model event. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall9.type = TSEM_EVENTS;
	if ( !S->enclave->boot_slot(S->enclave, 9, ocall_table, &ecall9, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall9.retn )
		ERR(goto done);

	if ( strlen(ecall9.event) != 0 ) {
		if ( !event->add(event, ecall9.event) )
			ERR(goto done);
	}
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements returning the number of TE events in a
 * security domain
 *
 * \param this	A pointer to the object whose TE size is to be
 *		returned.
 *
 * \return	The number of TE events.
 *
 */

static size_t te_size(CO(SanchoSGX, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall4_interface ecall4;


	/* Call ECALL slot 4 to get the size. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall4.type = TSEM_EVENTS;
	ecall4.size = 0;
	if ( !S->enclave->boot_slot(S->enclave, 4, ocall_table, &ecall4, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return ecall4.size;
}


/**
 * External public method.
 *
 * This method resets the TE event cursor.
 *
 * \param this	A pointer to the security domain whose TE event cursor
 *		is to be rewound.
 *
 * \return	No return value is defined.
 */

static void rewind_te(CO(SanchoSGX, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall8_interface ecall8;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 8 to rewind event cursor. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall8.type = TSEM_EVENTS;
	if ( !S->enclave->boot_slot(S->enclave, 8, ocall_table, &ecall8, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return;
}


/**
 * External public method.
 *
 * This method is an accessor method for accessing the current
 * measurement of of a security domain.
 *
 * \param this	A pointer to the TMA for the domain whose measurement
 *		is to be retrieved.
 *
 * \param bufr	The object which the state will be returned in.
 *
 * \param bufr	The object which the measurement will be returned in.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid measurement was returned.  A false value
 *		indicate a failure in returning measurement while a
 *		true value indicates the object contains a valid
 *		measurement.
 */

static _Bool get_measurement(CO(SanchoSGX, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall6_interface ecall6;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Call ECALL slot 6 to get model measurement. */
	ecall6.type = DOMAIN_MEASUREMENT;

	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	if ( !S->enclave->boot_slot(S->enclave, 6, ocall_table, &ecall6, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall6.retn )
		ERR(goto done);
	if ( !bufr->add(bufr, ecall6.measurement, sizeof(ecall6.measurement)) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for accessing the currrent
 * security state value of a security domain.
 *
 * \param this	A pointer to the TMA for the domain whose state is to
 *		be retrieved.
 *
 * \param bufr	The object which the state will be returned in.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid state was returned.  A false value
 *		indicate a failure in returning state while a
 *		true value indicates the object contains a valid
 *		measurement.
 */

static _Bool get_state(CO(SanchoSGX, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall6_interface ecall6;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Call ECALL slot 6 to get model measurement. */
	ecall6.type = DOMAIN_STATE;

	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	if ( !S->enclave->boot_slot(S->enclave, 6, ocall_table, &ecall6, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall6.retn )
		ERR(goto done);
	if ( !bufr->add(bufr, ecall6.measurement, sizeof(ecall6.measurement)) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for accessing the process identifier
 * of the process which has engaged in an extra-dimensional behavior
 * event.
 *
 * \param this	A pointer to the canister whose pid is to be returned.
 *
 * \param pid	A pointer to the location where the pid is to be
 *		storaged.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid pid was returned.  A false value
 *		indicate a failure in returning the pid value while a
 *		true value indicates the destination contains a valid
 *		process ID.
 */

static _Bool discipline_pid(CO(SanchoSGX, this), pid_t * const pid)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall7_interface ecall7;


	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall7.retn = false;
	ecall7.pid  = 0;
	if ( !S->enclave->boot_slot(S->enclave, 7, ocall_table, &ecall7, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall7.retn )
		ERR(goto done);
	*pid = ecall7.pid;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for retrieving the information
 * exchange events which comprise the model.  This method is designed
 * to be called repeatedly until the list of events is completely
 * traversed.  The traversal can be reset by calliong the
 * ->rewind_event method.
 *
 * \param this	A pointer to the canister whose events are to be
 *		retrieved.
 *
 * \param event	The object which the event will be copied into.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid event was returned.  A false value
 *		indicates a failure occurred and a valid event is
 *		not available.  A true value indicates the event
 *		object contains a valid value.
 *
 *		The end of the event list is signified by a NULL
 *		event object being set.
 */

static _Bool get_event(CO(SanchoSGX, this), String event)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall9_interface ecall9;


	/* Verify object and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event == NULL )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);


	/* Call slot 9 to get model event. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall9.type = ISO_IDENTITY_EVENT;
	if ( !S->enclave->boot_slot(S->enclave, 9, ocall_table, &ecall9, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall9.retn )
		ERR(goto done);

	if ( strlen(ecall9.event) != 0 ) {
		if ( !event->add(event, ecall9.event) )
			ERR(goto done);
	}
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method resets the trajector cursor.
 *
 * \param this	A pointer to the canister whose events are to be
 *		retrieved.
 *
 * \return	No return value is defined.
 */

static void rewind_event(CO(SanchoSGX, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall8_interface ecall8;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 8 to rewind event cursor. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall8.type = ISO_IDENTITY_EVENT;
	if ( !S->enclave->boot_slot(S->enclave, 8, ocall_table, &ecall8, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return;
}


/**
 * External public method.
 *
 * This method implements returning the number of security state events
 * in the security domain
 *
 * \param this	A pointer to the object whose events size is to be
 *		returned.
 *
 * \return	The number of security state events
 *
 */

static size_t trajectory_size(CO(SanchoSGX, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall4_interface ecall4;


	/* Call ECALL slot 4 to get the size. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall4.type = DOMAIN_POINTS;
	ecall4.size = 0;
	if ( !S->enclave->boot_slot(S->enclave, 4, ocall_table, &ecall4, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return ecall4.size;
}


/**
 * External public method.
 *
 * This method is an accessor method for retrieving the security state
 * points in the domain.  This method is designed to be called
 * repeatedly until the list of points is completely traversed.  The
 * traversal can be reset by calling the ->rewind_contours method.
 *
 * \param this		A pointer to the domain whose contours are to
 *			be retrieved.
 *
 * \param point		The object which the point will be copied into.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a state pointd was returned.  A false value indicates
 *		a failure occurred and a valid state point is not
 *		available.  A true value indicates the point object
 *		contains a valid value.
 */

static _Bool get_point(CO(SanchoSGX, this), Buffer point)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct SanchoSGX_ecall15 ecall15;


	/* Verify object and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( point == NULL )
		ERR(goto done);
	if ( point->poisoned(point) )
		ERR(goto done);


	/* Call slot 15 to get the state point. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	if ( !S->enclave->boot_slot(S->enclave, 15, ocall_table, &ecall15, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall15.retn )
		ERR(goto done);

	if ( !point->add(point, ecall15.point, sizeof(ecall15.point)) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method resets the contour retrieval cursor.
 *
 * \param this	A pointer to the canister whose contours are to be
 *		retrieved.
 *
 * \return	No return value is defined.
 */

static void rewind_points(CO(SanchoSGX, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall8_interface ecall8;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 8 to rewind points cursor. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall8.type = DOMAIN_POINTS;
	if ( !S->enclave->boot_slot(S->enclave, 8, ocall_table, &ecall8, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return;
}


/**
 * External public method.
 *
 * This method is an accessor method for retrieving the exchange
 * events which have been registered for the canister being modeled.
 * This method is designed to be called repeatedly until the list of
 * events is completely traversed.  The traversal can be reset by
 * calling the ->rewind_forensics method.
 *
 * \param this	A pointer to the canister whose forensics events
 *		are to be retrieved.
 *
 * \Param event	The object which the event will be copied to.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid event was returned.  A false value
 *		indicates a failure occurred and a valid event is
 *		not available.  A true value indicates the event
 *		object contains a valid value.
 *
 *		The end of the event list is signified by a NULL
 *		event object being set.
 */

static _Bool get_forensics(CO(SanchoSGX, this), String event)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall9_interface ecall9;


	/* Verify object status and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event == NULL )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);


	/* Call ECALL slot 9 to get forensics event. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall9.type = ISO_IDENTITY_FORENSICS;
	if ( !S->enclave->boot_slot(S->enclave, 9, ocall_table, &ecall9, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall9.retn )
		ERR(goto done);

	if ( strlen(ecall9.event) != 0 ) {
		if ( !event->add(event, ecall9.event) )
			ERR(goto done);
	}
	retn = true;


 done:
	return retn;

}


/**
 * External public method.
 *
 * This method resets the forensics cursor.
 *
 * \param this	A pointer to the canister whose forensics event
 *		cursor is to be reset.
 *
 * \return	No return value is defined.
 */

static void rewind_forensics(CO(SanchoSGX, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall8_interface ecall8;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 8 to get forensics event. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall8.type = ISO_IDENTITY_FORENSICS;
	if ( !S->enclave->boot_slot(S->enclave, 8, ocall_table, &ecall8, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return;
}


/**
 * External public method.
 *
 * This method implements returning the number of events in the
 * behavioral forensics trajectory.
 *
 * \param this	A pointer to the object whose forensics trajectory
 *		size is to be returned.
 *
 * \return	The size of the forensics trajectory list.
 *
 */

static size_t forensics_size(CO(SanchoSGX, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall4_interface ecall4;


	/* Call ECALL slot 4 to get forensics size. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall4.type = 1;
	ecall4.size = 0;
	if ( !S->enclave->boot_slot(S->enclave, 4, ocall_table, &ecall4, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return ecall4.size;
}


/**
 * External public method.
 *
 * This method implements output of the information exchange updates in
 * the current behavioral model in verbose form.
 *
 * \param this	A pointer to the object whose identity state is to be
 *		dumped.
 */

static void dump_events(CO(SanchoSGX, this))

{
	STATE(S);

	size_t lp,
	       event_cnt;

	String update = NULL;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("*Poisoned.\n", stdout);
		return;
	}


	/* Traverse and dump the trajectory path. */
	INIT(HurdLib, String, update, ERR(goto done));

	event_cnt = this->size(this);
	this->rewind_event(this);

	for (lp= 1; lp <= event_cnt; ++lp) {
		if ( !this->get_event(this, update) )
			ERR(goto done);

		fprintf(stdout, "Point: %zu\n", lp);
		update->print(update);
		update->reset(update);
		fputc('\n', stdout);
	};


 done:
	WHACK(update);

	return;
}


/**
 * External public method.
 *
 * This method implements output of the information exchange events
 * which are registered for the behavioral model.
 *
 * \param this	A pointer to the object whose forensics state is to be
 *		dumped.
 */

static void dump_forensics(CO(SanchoSGX, this))

{
	STATE(S);

	size_t lp,
	       event_cnt;

	String update = NULL;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("*Poisoned.\n", stdout);
		return;
	}


	/* Traverse and dump the trajectory path. */
	INIT(HurdLib, String, update, ERR(goto done));

	event_cnt = this->forensics_size(this);
	this->rewind_forensics(this);

	for (lp= 1; lp <= event_cnt; ++lp) {
		if ( !this->get_forensics(this, update) )
			ERR(goto done);

		fprintf(stdout, "Point: %zu\n", lp);
		update->print(update);
		update->reset(update);
		fputc('\n', stdout);
	};


 done:
	WHACK(update);

	return;
}


/**
 * External public method.
 *
 * This method implements output of the information exchange events in
 * the current behavioral model in verbose form.
 *
 * \param this	A pointer to the object whose identity state is to be
 *		dumped.
 */

static void dump_contours(CO(SanchoSGX, this))

{
#if 0
	STATE(S);

	Buffer bufr = NULL;

	ContourPoint contour;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("*Poisoned.\n", stdout);
		return;
	}


	/* Traverse and dump the contours. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	rewind_contours(this);
	do {
		if ( !get_contour(this, &contour) ) {
			fputs("Error retrieving event.\n", stdout);
			return;
		}
		if ( contour != NULL ) {
			if ( !bufr->add(bufr, contour->get(contour), \
					NAAAIM_IDSIZE) )
				ERR(goto done);
			bufr->print(bufr);
			bufr->reset(bufr);
		}
	} while ( contour != NULL );


 done:
	WHACK(bufr);
#endif
	return;
}


/**
 * External public method.
 *
 * This method implements starting of the management mode of the
 * enclave.
 *
 * \param this		A pointer to the object which is to be sealed.
 *
 * \param id_bufr	The object containing the identity of the
 *			host the enclave is being run on.
 *
 * \param port		The number of the port the management daemon
 *			is to run on.
 *
 * \param spid		The Service Provider IDentity to be used for
 *			generating platform attestation quotes.
 *
 * \return		A boolean value is used to indicate the
 *			status of starting of the management thread.
 *			A false value indicates an error was encountered
 *			while a true indicates the thread was
 *			successfully initiated.
 */

static _Bool manager(CO(SanchoSGX, this), CO(Buffer, id_bufr), \
		     uint16_t port, char *spid)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall10_interface ecall10;


	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	memset(&ecall10, '\0', sizeof(struct ISOidentity_ecall10_interface));

	ecall10.debug	     = S->debug;
	ecall10.port	     = port;
	ecall10.current_time = time(NULL);

	ecall10.spid	  = spid;
	ecall10.spid_size = strlen(spid) + 1;

	ecall10.identity      = id_bufr->get(id_bufr);
	ecall10.identity_size = id_bufr->size(id_bufr);

	if ( !S->enclave->boot_slot(S->enclave, 10, ocall_table, \
				    &ecall10, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements starting of the management mode of the
 * enclave.
 *
 * \param this	A pointer to the object which is to be sealed.
 *
 */

static _Bool add_verifier(CO(SanchoSGX, this), CO(Buffer, verifier))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall13 ecall13;


	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	memset(&ecall13, '\0', sizeof(struct ISOidentity_ecall13));

	ecall13.verifier      = verifier->get(verifier);
	ecall13.verifier_size = verifier->size(verifier);

	if ( !S->enclave->boot_slot(S->enclave, 13, ocall_table, \
				    &ecall13, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements sealing the behavioral model in its current
 * state.  Sealing the model implies that any additional events which
 * are not in the behavioral map constitute forensic violations for
 * the system being modeled.
 *
 * \param this	A pointer to the object which is to be sealed.
 *
 */

static _Bool seal(CO(SanchoSGX, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 2 to seal the ISOidentity model. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	if ( !S->enclave->boot_slot(S->enclave, 2, ocall_table, NULL, &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements returning the number of points in the
 * behavioral map.
 *
 * \param this	A pointer to the object which is to be destroyed.
 *
 * \return	The size of the behavioral map.
 *
 */

static size_t size(CO(SanchoSGX, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall4_interface ecall4;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 4 to get model size. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	ecall4.type = 0;
	ecall4.size = 0;
	if ( !S->enclave->boot_slot(S->enclave, 4, ocall_table, &ecall4, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return ecall4.size;
}


/**
 * External public method.
 *
 * This method implements execution of the ECALL which returns the
 * host specific identity of the enclave.
 *
 * \param this	A pointer to the enclave which is to be measured.
 *
 * \param bufr	The object which the enclave measurement is to be
 *		loaded into.
 *
 * \return	A boolean value is returned to indicate if the identity
 *		was successfully generated.  A false value indicates
 *		the generation failed while a true value indicates the
 *		buffer contains a valid enclave identity.
 *
 */

static _Bool generate_identity(CO(SanchoSGX, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct OCALL_api *ocall_table;

	struct ISOidentity_ecall11_interface ecall11;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 11 to get the enclave identity. */
	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	memset(&ecall11, '\0', sizeof(struct ISOidentity_ecall11_interface));

	if ( !S->enclave->boot_slot(S->enclave, 11, ocall_table, \
				    &ecall11, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}
	if ( !ecall11.retn )
		ERR(goto done);

	if ( !bufr->add(bufr, ecall11.id, sizeof(ecall11.id)) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements setting the debug status of the enclave.
 *
 * \param this	A pointer to the object which is to be destroyed.
 *
 * \param state	A boolean value specifying the debug status of the
 *		enclave.
 *
 * \return	No return value is defined.
 */

static void debug(CO(SanchoSGX, this), const _Bool state)

{
	STATE(S);


	S->debug = state;
	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for an ExchangeEvent object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SanchoSGX, this))

{
	STATE(S);

	int rc;

	struct ISOidentity_ecall0_interface ecall0;

	struct OCALL_api *ocall_table;


	/* Call ECALL slot 0 to de-initialize the SecurityState model. */
	ecall0.init = false;

	if ( !S->ocall->get_table(S->ocall, &ocall_table) )
		ERR(goto done);

	S->enclave->boot_slot(S->enclave, 0, ocall_table, &ecall0, &rc);


 done:
	WHACK(S->enclave);
	WHACK(S->ocall);
	WHACK(Control);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for an ExchangeEvent object.
 *
 * \return	A pointer to the initialized exchange event.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SanchoSGX NAAAIM_SanchoSGX_Init(void)

{
	Origin root;

	SanchoSGX this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SanchoSGX);
	retn.state_size   = sizeof(struct NAAAIM_SanchoSGX_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SanchoSGX_OBJID,
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */

	/* Method initialization. */
	this->load_enclave	  = load_enclave;
	this->load_enclave_memory = load_enclave_memory;

	this->update = update;
	this->load   = load;

	this->add_ai_event = add_ai_event;
	this->get_te_event = get_te_event;
	this->te_size	   = te_size;
	this->rewind_te	   = rewind_te;

	this->set_aggregate   = set_aggregate;
	this->get_measurement = get_measurement;
	this->get_state	      = get_state;
	this->discipline_pid  = discipline_pid;

	this->get_event	      = get_event;
	this->rewind_event    = rewind_event;
	this->trajectory_size = trajectory_size;

	this->get_point     = get_point;
	this->rewind_points = rewind_points;

	this->get_forensics	= get_forensics;
	this->rewind_forensics	= rewind_forensics;
	this->forensics_size	= forensics_size;

	this->dump_events    = dump_events;
	this->dump_contours  = dump_contours;
	this->dump_forensics = dump_forensics;

	this->manager	   = manager;
	this->add_verifier = add_verifier;

	this->seal  = seal;
	this->size  = size;

	this->generate_identity = generate_identity;
	this->debug	      	= debug;
	this->whack		= whack;

	return this;
}
