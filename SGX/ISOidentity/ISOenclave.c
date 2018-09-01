/** \file
 * This file contains the implementation of an object which manages
 * communications with an ISOidentity model running in an SGX enclave.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
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

#include "../SGX/SGX.h"
#include "../SGX/SGXenclave.h"
#include <SGXquote.h>

#include <ContourPoint.h>
#include <ExchangeEvent.h>

#include "ISOenclave.h"
#include "ISOidentity-interface.h"


/* Object state extraction macro. */
#define STATE(var) CO(ISOenclave_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_ISOenclave_OBJID)
#error Object identifier not defined.
#endif


/**
 * System call wrapper for setting the actor status of a process.
 */
static inline int sys_set_bad_actor(pid_t pid, unsigned long flags)
{
	return syscall(327, pid, flags);
}


/** OCALL interface definitions. */
struct ocall1_interface {
	char* str;
} ocall1_string;

int ocall1_handler(struct ocall1_interface *interface)

{
	fprintf(stdout, "%s", interface->str);
	return 0;
}

struct ocall2_interface {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
};

static void cpuid(int *eax, int *ebx, int *ecx, int *edx)\

{
	__asm("cpuid\n\t"
	      /* Output. */
	      : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
	      /* Input. */
	      : "0" (*eax), "2" (*ecx));

	return;
}


int ocall2_handler(struct ocall2_interface *pms)

{
	struct ocall2_interface *ms = (struct ocall2_interface *) pms;


	ms->ms_cpuinfo[0] = ms->ms_leaf;
	ms->ms_cpuinfo[2] = ms->ms_subleaf;

	cpuid(&ms->ms_cpuinfo[0], &ms->ms_cpuinfo[1], &ms->ms_cpuinfo[2], \
	      &ms->ms_cpuinfo[3]);

	return 0;
}


/* Interface and handler for fgets function simulation. */
struct SGXfusion_fgets_interface {
	_Bool retn;

	int stream;
	char bufr_size;
	char bufr[];
};

int fgets_handler(struct SGXfusion_fgets_interface *oc)

{
	FILE *instream = NULL;


	if ( oc->stream == 3 )
		instream = stdin;
	else {
		fprintf(stderr, "%s: Bad stream number: %d", __func__, \
			oc->stream);
		return 1;
	}

	if ( fgets(oc->bufr, oc->bufr_size, instream) != NULL )
		oc->retn = true;
	return 0;
}


/* OCALL interface to handle the request to discipline a process. */
int discipline_pid_ocall(struct ISOenclave_ocall *oc)

{
	_Bool discipline,
	      retn = false;


	discipline = sys_set_bad_actor(oc->pid, 0);
	if (discipline < 0 ) {
		fprintf(stderr, "actor status error: %d:%s\n", errno, \
			strerror(errno));
		retn = false;
		goto done;
	}

	if ( discipline > 0 ) {
		if ( oc->debug )
			fprintf(stderr, "PID is disciplined: %d\n", oc->pid);
	}
	else {
		if ( oc->debug )
			fprintf(stderr, "PID not disciplined: %d, " \
				"disciplining.\n", oc->pid);
		discipline = sys_set_bad_actor(oc->pid, 1);
		if ( discipline < 0 ) {
			fprintf(stderr, "actor status error: %d:%s\n", errno, \
			        strerror(errno));
			retn = false;
			goto done;
		}
	}


 done:
	oc->retn = retn;
	return 0;
}


static const struct OCALL_api ocall_table = {
	OCALL_NUMBER,
	{
		ocall1_handler,
		fgets_handler,
		ocall2_handler,
		Duct_sgxmgr,
		SGXquote_sgxmgr,
		discipline_pid_ocall,
	}
};


/** ExchangeEvent private state information. */
struct NAAAIM_ISOenclave_State
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
	SGXenclave enclave;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the
 * NAAAIM_ISOenclave_State structure which holds state information
 * for the object.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(ISOenclave_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_ISOenclave_OBJID;

	S->poisoned	 = false;
	S->debug	 = false;
	S->enclave_error = 0;

	S->enclave = NULL;

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

static _Bool load_enclave(CO(ISOenclave, this), CO(char *, enclave), \
			  CO(char *, token))

{
	STATE(S);

	int rc;

	_Bool retn = false;

	struct SGX_einittoken *einit_token;

	struct ISOidentity_ecall0_interface ecall0;

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
	INIT(NAAAIM, SGXenclave, S->enclave, ERR(goto done));

	if ( !S->enclave->open_enclave(S->enclave, SGX_DEVICE, enclave, true) )
		ERR(goto done);

	if ( !S->enclave->create_enclave(S->enclave) )
		ERR(goto done);

	if ( !S->enclave->load_enclave(S->enclave) )
		ERR(goto done);

	if ( !S->enclave->init_enclave(S->enclave, einit_token) )
		ERR(goto done);


	/* Call ECALL slot 0 to initialize the ISOidentity model. */
	if ( !S->enclave->boot_slot(S->enclave, 0, &ocall_table, &ecall0, \
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
 * \return	A boolean value is used to indicate whether or not
 *		the the event was registered.  A false value indicates
 *		a failure while a true value indicates the model
 *		was updated.
 */

static _Bool update(CO(ISOenclave, this), CO(String, update), \
		    _Bool *discipline)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall1_interface ecall1;


	/* Verify object status and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( update == NULL )
		ERR(goto done);
	if ( update->poisoned(update) )
		ERR(goto done);


	/* Call ECALL slot 0 to initialize the ISOidentity model. */
	ecall1.update = update->get(update);

	if ( !S->enclave->boot_slot(S->enclave, 1, &ocall_table, &ecall1, \
				    &rc) ) {
		S->enclave_error = rc;
		ERR(goto done);
	}
	if ( !ecall1.retn )
		ERR(goto done);

	*discipline = ecall1.discipline;
	retn	    = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements updating the currently maintained behavioral
 * model a specific contour point.
 *
 * \param this		A pointer to the object which is being modeled.
 *
 * \param bpoint	The object containing the binary contour point
 *			that is to be added to the model.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the the contour point was mapped.  A false value
 *		indicates a failure while a true value indicates the
 *		model was updated.
 */

static _Bool update_map(CO(ISOenclave, this), CO(Buffer, bpoint))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall12_interface ecall12;


	/* Verify object status and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bpoint == NULL )
		ERR(goto done);
	if ( bpoint->poisoned(bpoint) )
		ERR(goto done);


	/* Call ECALL slot 0 to initialize the ISOidentity model. */
	memcpy(ecall12.point, bpoint->get(bpoint), sizeof(ecall12.point));

	if ( !S->enclave->boot_slot(S->enclave, 12, &ocall_table, &ecall12, \
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

static _Bool set_aggregate(CO(ISOenclave, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall5_interface ecall5;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Call ECALL slot 5 to set the model aggregate. */
	ecall5.aggregate	= bufr->get(bufr);
	ecall5.aggregate_length = bufr->size(bufr);

	if ( !S->enclave->boot_slot(S->enclave, 5, &ocall_table, &ecall5, \
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
 * This method is an accessor method for accessing the currrent
 * measurement of the model.
 *
 * \param this	A pointer to the canister whose measurement is to be
 *		retrieved.
 *
 * \param bufr	The object which the measurement will be returned in.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid measurement was returned.  A false value
 *		indicate a failure in returning measurement while a
 *		true value indicates the object contains a valid
 *		measurement.
 */

static _Bool get_measurement(CO(ISOenclave, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall6_interface ecall6;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Call ECALL slot 6 to get model measurement. */
	if ( !S->enclave->boot_slot(S->enclave, 6, &ocall_table, &ecall6, \
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

static _Bool discipline_pid(CO(ISOenclave, this), pid_t * const pid)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall7_interface ecall7;


	ecall7.retn = false;
	ecall7.pid  = 0;
	if ( !S->enclave->boot_slot(S->enclave, 7, &ocall_table, &ecall7, \
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

static _Bool get_event(CO(ISOenclave, this), String event)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall9_interface ecall9;


	/* Verify object and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event == NULL )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);


	/* Call slot 9 to get model event. */
	ecall9.type = ISO_IDENTITY_EVENT;
	if ( !S->enclave->boot_slot(S->enclave, 9, &ocall_table, &ecall9, \
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

static void rewind_event(CO(ISOenclave, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall8_interface ecall8;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 8 to rewind event cursor. */
	ecall8.type = ISO_IDENTITY_EVENT;
	if ( !S->enclave->boot_slot(S->enclave, 8, &ocall_table, &ecall8, \
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
 * This method is an accessor method for retrieving the contour points
 * which comprise the behavior model implemented in an object.  This
 * method is designed to be called repeatedly until the list of events
 * is completely traversed.  The traversal can be reset by calling the
 * ->rewind_contours method.
 *
 * \param this		A pointer to the canister whose contours are to
 *			be retrieved.
 *
 * \param contour	The object which the contour will be copied to.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a contour event was returned.  A false value
 *		indicates a failure occurred and a valid conour is
 *		not available.  A true value indicates the contour
 *		object contains a valid value.
 *
 *		The end of the contour list is signified by a NULL
 *		contour object being set.
 */

static _Bool get_contour(CO(ISOenclave, this), Buffer contour)

{
	_Bool retn = true;


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

static void rewind_contours(CO(ISOenclave, this))

{
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

static _Bool get_forensics(CO(ISOenclave, this), String event)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall9_interface ecall9;


	/* Verify object status and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event == NULL )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);


	/* Call ECALL slot 9 to get forensics event. */
	ecall9.type = ISO_IDENTITY_FORENSICS;
	if ( !S->enclave->boot_slot(S->enclave, 9, &ocall_table, &ecall9, \
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

static void rewind_forensics(CO(ISOenclave, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall8_interface ecall8;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 8 to get forensics event. */
	ecall8.type = ISO_IDENTITY_FORENSICS;
	if ( !S->enclave->boot_slot(S->enclave, 8, &ocall_table, &ecall8, \
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

static size_t forensics_size(CO(ISOenclave, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall4_interface ecall4;


	/* Call ECALL slot 4 to get forensics size. */
	ecall4.type = 1;
	ecall4.size = 0;
	if ( !S->enclave->boot_slot(S->enclave, 4, &ocall_table, &ecall4, \
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

static void dump_events(CO(ISOenclave, this))

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

static void dump_forensics(CO(ISOenclave, this))

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

static void dump_contours(CO(ISOenclave, this))

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

static _Bool manager(CO(ISOenclave, this), CO(Buffer, id_bufr), \
		     uint16_t port, char *spid)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall10_interface ecall10;


	memset(&ecall10, '\0', sizeof(struct ISOidentity_ecall10_interface));

	ecall10.debug	     = S->debug;
	ecall10.port	     = port;
	ecall10.current_time = time(NULL);

	ecall10.spid	  = spid;
	ecall10.spid_size = strlen(spid) + 1;

	ecall10.identity      = id_bufr->get(id_bufr);
	ecall10.identity_size = id_bufr->size(id_bufr);

	if ( !S->enclave->boot_slot(S->enclave, 10, &ocall_table, \
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

static _Bool add_verifier(CO(ISOenclave, this), CO(Buffer, verifier))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall13 ecall13;


	memset(&ecall13, '\0', sizeof(struct ISOidentity_ecall13));

	ecall13.verifier      = verifier->get(verifier);
	ecall13.verifier_size = verifier->size(verifier);

	if ( !S->enclave->boot_slot(S->enclave, 13, &ocall_table, \
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

static _Bool seal(CO(ISOenclave, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 2 to seal the ISOidentity model. */
	if ( !S->enclave->boot_slot(S->enclave, 2, &ocall_table, NULL, &rc) ) {
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

static size_t size(CO(ISOenclave, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall4_interface ecall4;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 4 to get model size. */
	ecall4.type = 0;
	ecall4.size = 0;
	if ( !S->enclave->boot_slot(S->enclave, 4, &ocall_table, &ecall4, \
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

static _Bool generate_identity(CO(ISOenclave, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct ISOidentity_ecall11_interface ecall11;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call ECALL slot 11 to get the enclave identity. */
	memset(&ecall11, '\0', sizeof(struct ISOidentity_ecall11_interface));

	if ( !S->enclave->boot_slot(S->enclave, 11, &ocall_table, \
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

static void debug(CO(ISOenclave, this), const _Bool state)

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

static void whack(CO(ISOenclave, this))

{
	STATE(S);


	WHACK(S->enclave);

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

extern ISOenclave NAAAIM_ISOenclave_Init(void)

{
	Origin root;

	ISOenclave this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_ISOenclave);
	retn.state_size   = sizeof(struct NAAAIM_ISOenclave_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_ISOenclave_OBJID,
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */

	/* Method initialization. */
	this->load_enclave = load_enclave;

	this->update	 = update;
	this->update_map = update_map;

	this->set_aggregate   = set_aggregate;
	this->get_measurement = get_measurement;
	this->discipline_pid  = discipline_pid;

	this->get_event	   = get_event;
	this->rewind_event = rewind_event;

	this->get_contour     = get_contour;
	this->rewind_contours = rewind_contours;

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
