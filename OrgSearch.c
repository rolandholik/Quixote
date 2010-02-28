/** \file
 * This file implements an object used to locate the organization which
 * orginates a user identity.
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "NAAAIM.h"
#include "OrgSearch.h"
#include "IDtoken.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_OrgSearch_OBJID)
#error Object identifier not defined.
#endif


/** OrgSearch private state information. */
struct NAAAIM_OrgSearch_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Number of identities in the block. */
	unsigned int idcnt;

	/* Memory block containing the organizational identities. */
	unsigned char *idblock;

	/* Matching organizational identity. */
	Buffer matched;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_OrgSearch_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const OrgSearch_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_OrgSearch_OBJID;

	S->poisoned = false;
	S->idcnt    = 0;
	S->idblock  = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements loading an ASCII organization file into a
 * memory buffer which will be iterated over to find the originating
 * identity.
 *
 * \param this		The organizational identity origin object which is
 *			to be searched.
 *
 * \param infile	The name of the text file containing the
 *			originating identities.
 *
 * \return		A boolean file is used to indicate whether or
 *			not loading of the file was successful.  A true
 *			value is used to indicate the load was
 *			successful.
 */

static _Bool load(const OrgSearch const this, const char * const infile)

{
	auto const OrgSearch_State const S = this->state;

	auto _Bool retn = false;

	auto char bufr[256];

	auto unsigned char *idbp;

	auto unsigned int size;

	auto FILE *fp = NULL;

	auto Buffer hex = NULL;


	/*
	 * Open the file and count the entries in the file in order to
	 * optimize the memory allocation of the buffer.
	 */
	if ( (fp = fopen(infile, "r")) == NULL ) {
		S->poisoned = true;
		goto done;
	}
	while ( fgets(bufr, sizeof(bufr), fp) != NULL )
		++S->idcnt;

	size = S->idcnt * sizeof(unsigned char) * NAAAIM_IDSIZE;
	if ( (S->idblock = malloc(size)) == NULL )
		goto done;
	idbp = S->idblock;


	/*
	 * Reset the input stream and read the file.  Treat the first
	 * field in the file as a hexademically coded identity and
	 * copy the binary form into the identity block.
	 */
	if ( (hex = HurdLib_Buffer_Init()) == NULL )
		goto done;

	rewind(fp);
	while ( fscanf(fp, "%64s ", bufr) == 1 ) {
		if ( !hex->add_hexstring(hex, bufr) )
			goto done;
		memcpy(idbp, hex->get(hex), hex->size(hex));
		idbp += NAAAIM_IDSIZE;
		hex->reset(hex);
	}

	retn = true;

	
 done:
	if ( retn == false )
		S->poisoned = true;

	if ( fp != NULL )
		fclose(fp);
	if ( hex != NULL )
		hex->whack(hex);

	return retn;
}


/**
 * External public method.
 *
 * This method implements searching for the identity which originated
 * the organizational key and identity provided in the form of an
 * identity token object.
 * 
 * \param this		The organizational identity origin object which is
 *			to be searched.
 *
 * \param token		The identity token containing the identity to
 *			be searched for.
 *
 * \return		A boolean file is used to indicate whether or
 *			not the file was successful.  A true value
 *			indicates a match was found.  If an error occured
 *			during he search the object is poisoned.  The
 *			poisoned method should be called to verify
 *			whether or not the failure was caused by an
 *			operational problem.
 */

static _Bool search(const OrgSearch const this, const IDtoken const token)

{
	auto const OrgSearch_State const S = this->state;

	auto _Bool retn = false;

	auto unsigned char *idbp = S->idblock;

	auto unsigned int lp = 0;


	/* Iterate through memory block looking for a match. */
	S->matched->reset(S->matched);
	for (lp= 0; lp < S->idcnt; ++lp) {
		if ( !S->matched->add(S->matched, idbp, NAAAIM_IDSIZE) ) {
			fputs("Failed addition of key.\n", stderr);
			goto done;
		}
		if ( token->matches(token, S->matched) ) {
			retn = true;
			goto done;
		}
		idbp += NAAAIM_IDSIZE;
		S->matched->reset(S->matched);
	}


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements retrieving the organizaional identity which
 * was matched.
 *
 * \param this	A pointer to the object from which the matching identity
 *		is to be retrieved.
 *
 * \param bufr	The Buffer object into which the identity is to be
 *		loaded.
 *
 * \return	A return value is used to indicate whether or not the
 *		retrieval was successful.  A true value indicates success.
 */

static _Bool get_match(const OrgSearch const this, const Buffer const bufr)

{
	auto const OrgSearch_State const S = this->state;

	auto _Bool retn = false;


	if ( S->poisoned )
		goto done;

	if ( !bufr->add_Buffer(bufr, S->matched) )
		goto done;

	retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	return retn;
}
	
	
/**
 * External public method.
 *
 * This method implements a destructor for a OrgSearch object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const OrgSearch const this)

{
	auto const OrgSearch_State const S = this->state;


	if ( S->idblock != NULL )
		free(S->idblock);
	if ( S->matched != NULL )
		S->matched->whack(S->matched);
	
	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a OrgSearch object.
 *
 * \return	A pointer to the initialized OrgSearch.  A null value
 *		indicates an error was encountered in object generation.
 */

extern OrgSearch NAAAIM_OrgSearch_Init(void)

{
	auto Origin root;

	auto OrgSearch this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_OrgSearch);
	retn.state_size   = sizeof(struct NAAAIM_OrgSearch_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_OrgSearch_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	if ( (this->state->matched = HurdLib_Buffer_Init()) == NULL ) {
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->load	= load;
	this->search	= search;
	this->get_match = get_match;

	this->whack = whack;

	return this;
}
