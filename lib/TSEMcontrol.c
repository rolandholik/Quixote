/** \file
 * This file contains the implementation of an object that controls
 * the Trusted Security Event Modeling Linux Security Module.
 */

/**************************************************************************
 * Copyright (c) 2022, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local definitions. */
#define CONTROL_FILE	"/sys/kernel/security/tsem/control"
#define ID_FILE		"/sys/kernel/security/tsem/id"


/* Include files. */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <errno.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "RandomBuffer.h"
#include "TSEMcontrol.h"


/* State extraction macro. */
#define STATE(var) CO(TSEMcontrol_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_TSEMcontrol_OBJID)
#error Object identifier not defined.
#endif


/** TSEMcontrol private state information. */
struct NAAAIM_TSEMcontrol_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object state. */
	_Bool poisoned;

	/* Buffer object used to do I/O to the command file. */
	Buffer bufr;

	/* String object used to compose the command. */
	String cmdstr;


	/* File object that implements I/O to the control file. */
	File file;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_TSEMcontrol_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(TSEMcontrol_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TSEMcontrol_OBJID;

	S->poisoned = false;

	return;
}


/**
 * Internal private method.
 *
 * This method implements writing the contents of the supplied String
 * variable to the control file.
 *
 *
 * \param S     A pointer to the state information for the object that
 *		will be conducting the I/O.
 *
 * \return	A boolean value is used to indicate the status of the
 *		write operation.  A false value indicates the write
 *		failed with a true value indicated it succeeded.
 */

static _Bool _write_cmd(CO(TSEMcontrol_State, S))

{
	_Bool retn = false;


	if ( !S->bufr->add(S->bufr,
			   (unsigned char *) S->cmdstr->get(S->cmdstr), \
			   S->cmdstr->size(S->cmdstr)) )
		ERR(goto done);

	if ( !S->file->write_Buffer(S->file, S->bufr) )
		ERR(goto done);

	S->bufr->reset(S->bufr);
	S->cmdstr->reset(S->cmdstr);
	retn = true;


 done:
	return retn;
}


/**
 * Internal private method.
 *
 * This method sets the current security model to be in enforcing
 * mode.
 *
 * \param this	The object that will be implementing the command.
 *
 * \return	A boolean value is used to indicate the status of
 *		setting of enforcement mode.  A true value indicates
 *		the write succeeded while a false value indicates
 *		a failure.
 */

static _Bool enforce(CO(TSEMcontrol, this))

{
	STATE(S);

	_Bool retn = false;


	if ( !S->cmdstr->add(S->cmdstr, "enforce\n") )
		ERR(goto done);

	if ( !_write_cmd(S) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method creates a TSEM security namespace based on the parameters
 * provided to the function.
 *
 * \param this	The object that will be implementing the command.
 *
 * \param type         The type of the namespace, either internal or external,
 *		       that is to be created.
 *
 * \param model		The security model that is to be implemented if
 *			other than the default model.  Specifying a NULL
 *			value for this argument selects the default model.
 *
 * \param digest	A pointer to a null-terminated character buffer
 *			containing the name of the hash function to
 *			use.  A null pointer will cause SHA256 to
 *
 * \param ns_ref	The enumeration type defining what namespace should
 *			be used as a reference for the parameters for the
 *			security event decriptions.
 *
 * \param cache_size	The size of the event and export magazines that
 *			are to be used.  A value of zero uses the
 *			default magazine size the kernel has been
 *			compiled with.
 *
 * \return	A boolean value is used to indicate the status of
 *		creating the namespace.  A true value indicates
 *		the setup succeeded while a false value indicates
 *		a failure.
 */

static _Bool create_ns(CO(TSEMcontrol, this),
		       const enum TSEMcontrol_ns_config type, char *model,
		       char *digest, const enum TSEMcontrol_ns_config ns_ref,
		       const unsigned int cache_size)

{
	STATE(S);

	_Bool retn     = false,
	      external = (type == TSEMcontrol_TYPE_EXTERNAL);


	if ( external )
		S->cmdstr->add(S->cmdstr, "external");
	else if ( type == TSEMcontrol_TYPE_INTERNAL )
		S->cmdstr->add(S->cmdstr, "internal");
	else if ( type == TSEMcontrol_TYPE_EXPORT )
		S->cmdstr->add(S->cmdstr, "export");
	else
		ERR(goto done);

	if ( ns_ref != 0 ) {
		S->cmdstr->add(S->cmdstr, " nsref=");
		if ( ns_ref == TSEMcontrol_INIT_NS )
			S->cmdstr->add(S->cmdstr, "initial");
		else if ( ns_ref == TSEMcontrol_CURRENT_NS )
			S->cmdstr->add(S->cmdstr, "current");
		else
			ERR(goto done);
	}

	if ( model != NULL )
		S->cmdstr->add_sprintf(S->cmdstr, " model=%s", model);

	if ( digest != NULL )
		S->cmdstr->add_sprintf(S->cmdstr, " digest=%s", digest);

	if ( cache_size != 0 )
		S->cmdstr->add_sprintf(S->cmdstr, " cache=%u", cache_size);

	if ( !S->cmdstr->add(S->cmdstr, "\n") )
		ERR(goto done);

	if ( !_write_cmd(S) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method creates a TSEM security namespace that is modeled
 * by a kernel based Trusted Modeling Agent.
 *
 * \param this	The object that will be implementing the command.
 *
 * \return	A boolean value is used to indicate the status of
 *		setting of enforcement mode.  A true value indicates
 *		the write succeeded while a false value indicates
 *		a failure.
 */

static _Bool seal(CO(TSEMcontrol, this))

{
	STATE(S);

	_Bool retn = false;


	if ( !S->cmdstr->add(S->cmdstr, "seal\n") )
		ERR(goto done);

	if ( !_write_cmd(S) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method is used to signal the kernel that a process should
 * indicate that a security event should fail.
 *
 * \param this	The object that will be implementing the command.
 *
 * \param pid	The process ID whose security event status is to
 *		be set
 *
 * \param tnum	Thet number of the tasdk whose security event status is
 *		to be set.
 *
 * \return	A boolean value is used to indicate the status of
 *		setting the process security event status.  A false
 *		value indicates a failure to set the status while
 *		a trust value indicates the security event status
 *		was set.
 */

static _Bool discipline(CO(TSEMcontrol, this), pid_t pid, uint64_t tnum)

{
	STATE(S);

	_Bool retn = false;


	if ( !S->cmdstr->add_sprintf(S->cmdstr, "untrusted pid=%d tnum=%s\n", \
				     pid, tnum) )
		ERR(goto done);

	if ( !_write_cmd(S) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method is used to signal the kernel that a process should
 * indicate that a security event should be allowed.
 *
 * \param this	The object that will be implementing the command.
 *
 * \param pid	The process ID whose security event status is to
 *		be set.
 *
 * \param tnum	The task number whose security event status is to
 *		be set.
 *
 * \return	A boolean value is used to indicate the status of
 *		setting the process security event status.  A false
 *		value indicates a failure to set the status while
 *		a trust value indicates the security event status
 *		was set.
 */

static _Bool release(CO(TSEMcontrol, this), pid_t pid, uint64_t tnum)

{
	STATE(S);

	_Bool retn = false;


	if ( !S->cmdstr->add_sprintf(S->cmdstr, "trusted pid=%d tnum=%lu\n", \
				     pid, tnum) )
		ERR(goto done);

	if ( !_write_cmd(S) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method is used to return the identification number of the
 * TSEM modeling context.
 *
 * \param this	The object that is requesting the id number.
 *
 * \param id	A pointer to the variable that will be populated
 *		with the TSEM context id.
 *
 * \return	A boolean value is used to indicate the status of
 *		accessing the identifier value.  A false value indicates
 *		an error occured and the variable cannot be trusted
 *		to have a valid value.  A true value indicates the
 *		variable has been updated with the process identifier.
 */

static _Bool id(CO(TSEMcontrol, this), uint64_t *idptr)

{
	STATE(S);

	_Bool retn = false;

	uint64_t id;

	File file = NULL;


	INIT(HurdLib, File, file, ERR(goto done));
	if ( !file->open_ro(file, ID_FILE) )
		ERR(goto done);

	S->cmdstr->reset(S->cmdstr);
	if ( !file->read_String(file, S->cmdstr) )
		ERR(goto done);

	id = strtoll(S->cmdstr->get(S->cmdstr), NULL, 10);
	if ( errno == ERANGE )
		ERR(goto done);
	*idptr = id;
	retn = true;


 done:
	S->cmdstr->reset(S->cmdstr);

	WHACK(file);

	return retn;
}


/**
 * External public method.
 *
 * This method is used to set the base point for a modeling context.
 *
 * \param this	The object that is configuring the base point.
 *
 * \param state	The object containing the base point definition.
 *
 * \return	A boolean value is used to indicate the status of
 *		configuring the base point.  A false value indicates
 *		an error occured, a true value indicates the
 *		model has been updated with the base point.
 */

static _Bool set_base(CO(TSEMcontrol, this), CO(Buffer, state))

{
	STATE(S);

	_Bool retn = false;


	if ( !S->cmdstr->add_sprintf(S->cmdstr, "base value=%s\n", \
				     (char *) state->get(state)) )
		ERR(goto done);

	if ( !_write_cmd(S) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method is used to add a security event state to a modeling
 * context.
 *
 * \param this	The object that is configuring the pseudonym.
 *
 * \param state	The object containing the state definition.
 *
 * \return	A boolean value is used to indicate the status of
 *		configuring the state.  A false value indicates
 *		an error occured, a true value indicates the
 *		model has been updated with the state.
 */

static _Bool add_state(CO(TSEMcontrol, this), CO(Buffer, state))

{
	STATE(S);

	_Bool retn = false;


	if ( !S->cmdstr->add_sprintf(S->cmdstr, "state value=%s\n", \
				     (char *) state->get(state)) )
		ERR(goto done);

	if ( !_write_cmd(S) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method is used to configure a pseudonym for a TSEM modeling
 * context.
 *
 * \param this	The object that is configuring the pseudonym.
 *
 * \param pseudonym	The object containing the pseudonym definition.
 *
 * \return	A boolean value is used to indicate the status of
 *		configuring the pseudonym.  A false value indicates
 *		an error occured, a true value indicates the
 *		model has been updated with the pseudonym.
 */

static _Bool pseudonym(CO(TSEMcontrol, this), CO(Buffer, pseudonym))

{
	STATE(S);

	_Bool retn = false;


	if ( !S->cmdstr->add_sprintf(S->cmdstr, "pseudonym value=%s\n", \
				     (char *) pseudonym->get(pseudonym)) )
		ERR(goto done);

	if ( !_write_cmd(S) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a TSEMcontrol object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(TSEMcontrol, this))

{
	STATE(S);


	WHACK(S->bufr);
	WHACK(S->cmdstr);
	WHACK(S->file);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a TSEMcontrol object.
 *
 * \return	A pointer to the initialized TSEMcontrol.  A null value
 *		indicates an error was encountered in object generation.
 */

extern TSEMcontrol NAAAIM_TSEMcontrol_Init(void)

{
	Origin root;

	TSEMcontrol this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_TSEMcontrol);
	retn.state_size   = sizeof(struct NAAAIM_TSEMcontrol_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_TSEMcontrol_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->bufr, goto fail);
	INIT(HurdLib, String, this->state->cmdstr, goto fail);

	INIT(HurdLib, File, this->state->file, goto fail);
	if ( !this->state->file->open_wo(this->state->file, CONTROL_FILE) )
		goto fail;

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->enforce	= enforce;
	this->create_ns = create_ns;
	this->seal	= seal;

	this->discipline = discipline;
	this->release	 = release;

	this->set_base  = set_base;
	this->add_state = add_state;
	this->pseudonym = pseudonym;

	this->id = id;

	this->whack = whack;

	return this;


 fail:
	WHACK(this->state->bufr);
	WHACK(this->state->cmdstr);
	WHACK(this->state->file);

	root->whack(root, this, this->state);
	return NULL;
}
