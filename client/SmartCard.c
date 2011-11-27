/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2011, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <pcsclite.h>
#include <winscard.h>
#include <reader.h>

#include <Origin.h>

#include "NAAAIM.h"
#include "SmartCard.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SmartCard_OBJID)
#error Object identifier not defined.
#endif


/** SmartCard private state information. */
struct NAAAIM_SmartCard_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Reader groups. */
	char *groups;

	/* Card readers. */
	char *readers;

	/* Smartcard context. */
	SCARDCONTEXT context;

	/* Smartcard handle. */
	SCARDHANDLE card;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SmartCard_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const SmartCard_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SmartCard_OBJID;

	S->groups  = NULL;
	S->readers = NULL;

	S->context = -1;
	S->card	   = -1;

	return;
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the card reader context
 * which will be used to control the reader.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 *
 * \return	A boolean value is used to indicate whether or not
 *		establishment of the context was successful.  A true
 *		value is used to indicate a valid context is
 *		available.
 */

static _Bool _init_context(const SmartCard_State const S) {

	DWORD reader_cnt,
	      group_cnt;

	LONG retn;


	if ( (retn = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, \
					   &S->context)) != SCARD_S_SUCCESS )
		return false;
	if ( (retn = SCardIsValidContext(S->context)) != SCARD_S_SUCCESS )
		return false;


	if ( (retn = SCardListReaderGroups(S->context, NULL, &group_cnt) ) != \
	     SCARD_S_SUCCESS )
		return false;
	if ( (S->groups = calloc(group_cnt, sizeof(char))) == NULL )
		return false;
	if ( (retn = SCardListReaderGroups(S->context, S->groups, \
					   &group_cnt)) != SCARD_S_SUCCESS )
		return false;
	fprintf(stderr, "Group count: %ld\n", group_cnt);


	if ( (retn = SCardListReaders(S->context, S->groups, NULL, \
				      &reader_cnt)) ==		   \
	     SCARD_E_NO_READERS_AVAILABLE )
		return false;
	fprintf(stderr, "Reader count: %ld\n", reader_cnt);

	S->readers = calloc(reader_cnt, sizeof(char));
	if ( (retn = SCardListReaders(S->context, S->groups, S->readers, \
				      &reader_cnt)) != \
	     SCARD_S_SUCCESS )
		return false;
	fprintf(stderr, "Reader 1: %s\n", S->readers);

	return true;
}


/**
 * External public method.
 *
 * This method waits for a card insertion event.
 *
 * \param this	A pointer to the card reader waiting for a card insertion.
 *
 * \return	A boolean value is returned to indicate that a successful
 *		card insertion has been detected.  A true value
 *		indicates a valid card insertion.
 */

static _Bool wait_for_insertion(const SmartCard const this)

{
	const SmartCard_State const S = this->state;

	DWORD prefs;

	LONG retn;

	SCARD_READERSTATE state[1];


	state[0].szReader	= &S->readers[0];
	state[0].dwCurrentState = SCARD_STATE_EMPTY;
	if ( (retn = SCardGetStatusChange(S->context, INFINITE, state, 1)) != \
	     SCARD_S_SUCCESS )
		return false;

	if ( state[0].dwEventState & SCARD_STATE_UNKNOWN )
		return false;

	if ( (retn = SCardConnect(S->context, &S->readers[0],		   \
				  SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 |  \
				  SCARD_PROTOCOL_T1, &S->card, &prefs)) != \
	     SCARD_S_SUCCESS )
		return false;

	if ( (retn = SCardDisconnect(S->card, SCARD_UNPOWER_CARD) != \
	      SCARD_S_SUCCESS) )
		return false;
	S->card = -1;

	return true;
}

	
/**
 * External public method.
 *
 * This method implements a destructor for a SmartCard object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const SmartCard const this)

{
	const SmartCard_State const S = this->state;


	if ( S->groups != NULL )
		free(S->groups);
	if ( S->readers != NULL )
		free(S->readers);

	if ( S->context != -1 )
		SCardReleaseContext(S->context);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a SmartCard object.
 *
 * \return	A pointer to the initialized SmartCard.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SmartCard NAAAIM_SmartCard_Init(void)

{
	Origin root;

	SmartCard this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SmartCard);
	retn.state_size   = sizeof(struct NAAAIM_SmartCard_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SmartCard_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize internal state. */
	if ( !_init_context(this->state) ) {
		whack(this);
		return NULL;
	}

	/* Method initialization. */
	this->wait_for_insertion = wait_for_insertion;

	this->whack = whack;

	return this;
}
