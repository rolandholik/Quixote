/** \file
 * This file contains the implementation of an object which is used to
 * manipulate the Software Guard Extensions (SGX) signature structure
 * SIGSTRUCT.
 *
 * The SIGSTRUCT is a data structure which implements the information
 * used to verify the ownership, integrity and measurement status of
 * an enclave.  This structure is a component of the SGX metadata
 * which is handled by the SRDEmetadata object.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libelf.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "SRDE.h"
#include "SRDEsigstruct.h"


/* Object state extraction macro. */
#define STATE(var) CO(SRDEsigstruct_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SRDEsigstruct_OBJID)
#error Object identifier not defined.
#endif


/**
 * This following include file holds a compile time generated character
 * array that holds the binary representation of the signature structure
 * that is released for the Intel Launch Enclave that is being used.  This
 * strategy eliminates the need to distribute the signature file as
 * a component of the runtime.
 */
#include "sigstruct.h"


/** SRDEsigstruct private state information. */
struct NAAAIM_SRDEsigstruct_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* The SGX signature structure. */
	struct SGX_sigstruct sigstruct;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SRDEsigstruct_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state information which
 *		is to be initialized.
 */

static void _init_state(CO(SRDEsigstruct_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SRDEsigstruct_OBJID;

	S->poisoned = false;

	memset(&S->sigstruct, '\0', sizeof(struct SGX_sigstruct));

	return;
}


/**
 * External public method.
 *
 * This method implements the loading of a SIGSTRUCT from an external
 * file.  It is currently implemented to support the fact that Intel
 * supplies data data for a SIGSTRUCT in binary form which is needed
 * to initialize the launch enclave (LE).
 *
 * \param this		A pointer to the object which is to hold the
 *			signature structure.
 *
 * \param fname		A pointer to the null-terminated character
 *			buffer which holds the name of the file
 *			containing a SIGSTRUCT in packed binary
 *			form.
 *
 * \return	If an error is encountered while loading the signature
 *		structure a false value is returned.  A true value is
 *		returned if the object contains valid signature
 *		structure.
 */

static _Bool load(CO(SRDEsigstruct, this), CO(char *, fname))

{
	STATE(S);

	_Bool retn = false;

	Buffer bufr = NULL;

	File file = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, file, ERR(goto done));


	file->open_ro(file, fname);
	if ( !file->slurp(file, bufr) )
		ERR(goto done);

	if ( bufr->size(bufr) != sizeof(struct SGX_sigstruct) )
		ERR(goto done);
	S->sigstruct = *(struct SGX_sigstruct *) bufr->get(bufr);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
		
	WHACK(bufr);
	WHACK(file);

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor method which populates a user
 * supplied signature structure with the value represented by the
 * object.
 *
 * \param this		A pointer to the object which holds the signature
 *			structure to be returned.
 *
 * \param sigstruct	A pointer to the structure which is to be
 *			populated.
 *
 * \return	If an error is encountered while loading the structure
 *		a false value is returned.  A true value is returned
 *		if the supplied structure posesses a valid copy of
 *		the structure.
 */

static _Bool get(CO(SRDEsigstruct, this), struct SGX_sigstruct *sigstruct)

{
	STATE(S);

	_Bool retn = false;


	/* Verify status of object. */
	if ( S->poisoned )
		ERR(goto done);

	*sigstruct = S->sigstruct;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor method which populates a user
 * supplied signature structure with the default launch enclave which
 * was encoded into this file at the time of its build.
 *
 * \param this		A pointer to the object which holds the launch
 *			enclave signature structure to be returned.
 *
 * \param sigstruct	A pointer to the structure which is to be
 *			populated.
 *
 * \return	If an error is encountered while loading the structure
 *		a false value is returned.  A true value is returned
 *		if the supplied structure posesses a valid copy of
 *		the structure.
 */

static _Bool get_LE(CO(SRDEsigstruct, this), struct SGX_sigstruct *sigstruct)

{
	STATE(S);

	_Bool retn = false;

	struct SGX_sigstruct *sp = (struct SGX_sigstruct *) LE_sigstruct;


	/* Verify status of object. */
	if ( S->poisoned )
		ERR(goto done);

	*sigstruct = *sp;
	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the generation of the conversion of a binary
 * SIGSTRUCT structure into a C based character array.  This is used
 * to automate conversion of a structure which is supplied in binary
 * to one which can be embedded in a program to avoid the need to
 * carry an additional file and then conduct I/O against it.
 *
 * \param this	A pointer to the object which holds the signature
 *		to be converted.
 *
 * \return	If an error is encountered while generating the output
 *		a false value is returned.  A true value indicates a
 *		valid structure was presented on the output.
 */

static _Bool generate(CO(SRDEsigstruct, this))

{
	STATE(S);

	_Bool retn = false;

	uint8_t *sp;

	uint16_t lp;


	/* Verify status of object and . */
	if ( S->poisoned )
		ERR(goto done);
	if ( sizeof(S->sigstruct) > (1 << 16) )
		ERR(goto done);


	fputs("static const uint8_t LE_sigstruct[] = {\n\t", stdout);

	sp = (uint8_t *) &S->sigstruct;
	for (lp= 1; lp <= sizeof(struct SGX_sigstruct); ++lp) {
		fprintf(stdout, "0x%02x", sp[lp-1]);
		if ( (lp % 8) == 0 ) {
			if ( lp == sizeof(struct SGX_sigstruct) )
				fputs("  \\\n", stdout);
			else
				fputs(", \\\n\t", stdout);
		}
		else
			fputs(", ", stdout);
	}
	fputs("};\n", stdout);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Internal private function
 *
 * This function implements printing out of a character buffer.  It is
 * a utility function to simplify output for the ->dump method.
 *
 * \param bufr		A pointer to the buffer to be dumped.
 *
 * \param cnt		The length of the buffer in bytes.
 *
 * \return		No return value is defined.
 */

static void _print_buffer(CO(char *, prefix), CO(uint8_t *, bufr), size_t cnt)

{
	size_t lp;


	fputs(prefix, stdout);
	for (lp= 0; lp < cnt; ++lp) {
		fprintf(stdout, "%02x ", bufr[lp]);
		if ( (lp+1 < cnt) && ((lp+1) % 16) == 0 )
			fputs("\n\t", stdout);
	}
	fputc('\n', stdout);

	return;
}


/**
 * External public method.
 *
 * This method implements dumping the contents of a SIGSTRUCT in
 * readable form for diagnostic purposes.
 *
 * \param this	A pointer to the object which holds the signature
 *		structure to be dumped.
 *
 * \return	No return value is defined.
 */

static void dump(CO(SRDEsigstruct, this))

{
	STATE(S);

	struct SGX_sigstruct *sp = &S->sigstruct;


	fputs("\nSIGSTRUCT:\n", stdout);
	fputs("header: ", stdout);
	_print_buffer("", sp->header, sizeof(sp->header));

	fprintf(stdout, "vendor: 0x%x\n", sp->vendor);
	fprintf(stdout, "date: %x\n", sp->date);
	fprintf(stdout, "hw version: 0x%x\n", sp->sw_defined);
	fprintf(stdout, "exponent: 0x%x\n", sp->exponent);

	fputs("modulus:\n", stdout);
	_print_buffer("\t", sp->modulus, sizeof(sp->modulus));

	fputs("signature:\n", stdout);
	_print_buffer("\t", sp->signature, sizeof(sp->signature));

	fprintf(stdout, "misc select: 0x%0x\n", sp->miscselect);
	fprintf(stdout, "misc mask: 0x%0x\n", sp->miscmask);

	fputs("attributes:\n", stdout);
	fprintf(stdout, "\tFlags: 0x%0lx\n", sp->attributes.flags);
	fprintf(stdout, "\tXFRM: 0x%0lx\n", sp->attributes.xfrm);

	fputs("attribute mask:\n", stdout);
	fprintf(stdout, "\tFlags: 0x%0lx\n", sp->attribute_mask.flags);
	fprintf(stdout, "\tXFRM: 0x%0lx\n", sp->attribute_mask.xfrm);

	fputs("enclave measurement:\n", stdout);
	_print_buffer("\t", sp->enclave_hash, sizeof(sp->enclave_hash));

	fprintf(stdout, "isv prodid: 0x%0x\n", sp->isv_prodid);
	fprintf(stdout, "isv svn: 0x%0x\n", sp->isv_svn);

	fputs("key q1:\n", stdout);
	_print_buffer("\t", sp->q1, sizeof(sp->q1));

	fputs("key q2:\n", stdout);
	_print_buffer("\t", sp->q2, sizeof(sp->q2));

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a SRDEsigstruct object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SRDEsigstruct, this))

{
	STATE(S);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SRDEsigstruct object.
 *
 * \return	A pointer to the initialized SRDEsigstruct.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SRDEsigstruct NAAAIM_SRDEsigstruct_Init(void)

{
	auto Origin root;

	auto SRDEsigstruct this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SRDEsigstruct);
	retn.state_size   = sizeof(struct NAAAIM_SRDEsigstruct_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SRDEsigstruct_OBJID, \
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->load = load;

	this->get    = get;
	this->get_LE = get_LE;

	this->generate = generate;
	this->dump     = dump;
	this->whack    = whack;

	return this;
}
