/** \file
 * This file contains the implementation of an object which is used
 * to manage a platform specific EPID 'blob'.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Local defines. */
#define EPID_BLOB_SIZE	  2836
#define DEFAULT_EPID_FILE "/var/lib/IDfusion/data/EPID.bin"


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"

#include "SRDE.h"
#include "SRDEepid.h"


/* Object state extraction macro. */
#define STATE(var) CO(SRDEepid_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SRDEepid_OBJID)
#error Object identifier not defined.
#endif


/**
 * The following structure defines an EPID private key.
 */
struct epid_private_key {
	uint8_t gid[4];
	uint8_t A[64];
	uint8_t x[32];
	uint8_t f[32];
} __attribute__((packed));


/**
 * The following structure defines a precomputed group member.
 */
struct epid_group_member {
	uint8_t e12[384];
	uint8_t e22[384];
	uint8_t e2w[384];
	uint8_t ea2[384];
} __attribute__((packed));


/**
 * The previous two structures are combined to produce a data
 * structure which is the secret portion of the EPID blob.
 */
struct epid_secret {
	struct epid_private_key private_key;
	struct epid_group_member group_member;
} __attribute__((packed));


/**
 * The following structure defines an EPID group public key.  It
 * is only used here for a size specification in the following
 * structure.
 */
struct group_pub_key {
	uint8_t gid[4];
	uint8_t h1[64];
	uint8_t h2[64];
	uint8_t w[128];
} __attribute__((packed));


/**
 * The following struct defines the plaintext portion of the EPID
 * blob.
 */
struct epid_plaintext {
	uint8_t seal_blob_type;
	uint8_t epid_key_version;

	/* sgx_cpu_svn_t */
	uint8_t equiv_cpu_svn[16];
	/*sgx_isv_svn_t */
	uint16_t equiv_pve_isv_svn;

	struct group_pub_key epid_group_cert;
	uint8_t         qsdk_exp[4];
	uint8_t         qsdk_mod[256];
	uint8_t         epid_sk[64];
	uint32_t        xeid;
};


/** SRDEepid private state information. */
struct NAAAIM_SRDEepid_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* The sealed EPID blob as provisioned from the Intel servers. */
	Buffer epid;

	/* The platform information associated with the EPID. */
	struct SGX_platform_info platform_info;

	/* Group information. */
	uint32_t xeid;
	uint8_t gid[4];
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SRDEepid_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(SRDEepid_State, S))

{

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SRDEepid_OBJID;

	S->poisoned = false;

	S->epid = NULL;
	memset(&S->platform_info, '\0', sizeof(struct SGX_platform_info));

	S->xeid = 0;
	memset(S->gid, '\0', sizeof(S->gid));

	return;
}


/**
 * Internal private method.
 *
 * This method is responsible for extracting the extended group identifier
 * and the EPID group certificate identifer from the plaintext portion
 * of the EPID blob.
 *
 * \param S	A pointer to the object containing the group information
 *		which is to be initialized.
 *
 * \return	No return value is specified.
 */

static void _set_group_info(CO(SRDEepid_State, S))

{
	uint32_t plaintext_offset;

	struct epid_plaintext *epid_plaintext;


	plaintext_offset = *(uint32_t *) (S->epid->get(S->epid) + 512);
	epid_plaintext = (struct epid_plaintext *) (S->epid->get(S->epid) + \
						    560 + plaintext_offset);
	S->xeid = epid_plaintext->xeid;

	memcpy(&S->gid, epid_plaintext->epid_group_cert.gid, \
	       sizeof(S->gid));

	return;
}


/**
 * External public method.
 *
 * This method implements loading of the EPID.
 *
 * \param this	A pointer to the EPID object which is to
 *		be loaded.
 *
 * \param file	A pointer to the null-terminated character buffer
 *		containing the name of the EPID file.  Specifying a
 *		null pointer causes the default EPID file location
 *		to be used.
 *
 * \return	A boolean value is returned to indicate the status
 *		of the EPID load.  A false value indicates the load
 *		failed while a true value indicates the object holds
 *		a valid EPID.
 */

static _Bool load(CO(SRDEepid, this), CO(char *, file))

{
	STATE(S);

	_Bool retn = false;

	const char *filename = \
		file == NULL ? DEFAULT_EPID_FILE : (char *) file;

	Buffer bufr = NULL;

	File infile = NULL;


	/* Verify object status and initialize the EPID buffer object. */
	if ( S->poisoned )
		ERR(goto done);


	/* Load the EPID blob and platform information. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, Buffer, S->epid, ERR(goto done));

	INIT(HurdLib, File, infile, ERR(goto done));
	if ( !infile->open_ro(infile, filename) )
		ERR(goto done);
	if ( !infile->read_Buffer(infile, bufr, EPID_BLOB_SIZE) )
		ERR(goto done);
	if ( !S->epid->add_Buffer(S->epid, bufr) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !infile->read_Buffer(infile, bufr, \
				  sizeof(struct SGX_platform_info)) )
		ERR(goto done);
	S->platform_info = *(struct SGX_platform_info *) bufr->get(bufr);


	/* Extract the EPID group information. */
	_set_group_info(S);

	retn = true;


 done:
	if ( !retn ) {
		WHACK(S->epid);
		S->epid = NULL;
		S->poisoned = true;
	}

	WHACK(bufr);
	WHACK(infile);

	return retn;
}


/**
 * External public method.
 *
 * This method implements saving the sealed EPID blob and the platform
 * information.  The objects are simply concantenated into the file.
 *
 * \param this	A pointer to the EPID object which is to
 *		be saved.
 *
 * \param file	A pointer to the null-terminated character buffer
 *		containing the name of the EPID file.  A null pointer
 *		specification causes the default EPID file location
 *		to be used.
 *
 * \return	A boolean value is returned to indicate the status
 *		of the EPID save.  A false value indicates the save
 *		failed while a true value indicates the object was
 *		properly saved.
 */

static _Bool save(CO(SRDEepid, this), CO(char *, file))

{
	STATE(S);

	_Bool retn = false;

	const char *filename = \
		file == NULL ? DEFAULT_EPID_FILE : (char *) file;

	Buffer bufr = NULL;

	File outfile = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Open the file and save the components. */
	INIT(HurdLib, File, outfile, ERR(goto done));
	if ( !outfile->open_rw(outfile, filename) )
		ERR(goto done);

	if ( !outfile->write_Buffer(outfile, S->epid) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (void *) &S->platform_info, \
			sizeof(S->platform_info)) )
		ERR(goto done);
	if ( !outfile->write_Buffer(outfile, bufr) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);
	WHACK(outfile);

	return retn;
}


/**
 * External public method.
 *
 * This method implements adding the sealed EPID blob to the object.
 *
 * \param this	A pointer to the EPID object which is to have an
 *		EPID blob added to it.
 *
 * \param epid	The object containing the EPID to be added.
 *
 * \return	A boolean value is returned to indicate the status
 *		of the EPID addition.  A false value indicates the
 *		addition failed while a true value indicates the
 *		EPID was successfully added.
 */

static _Bool add_epid(CO(SRDEepid, this), CO(Buffer, epid))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status and arguements. */
	if ( S->poisoned )
		ERR(goto done);
	if ( epid->poisoned(epid) )
		ERR(goto done);


	/* Add the EPID. */
	INIT(HurdLib, Buffer, S->epid, ERR(goto done));
	if ( !S->epid->add_Buffer(S->epid, epid) )
		ERR(goto done);

	_set_group_info(S);
	retn = true;


 done:
	if ( !retn ) {
		WHACK(S->epid);
		S->epid = NULL;
		S->poisoned = true;
	}

	return retn;
}


/**
 * External public method.
 *
 * This method implements adding platform information to the
 * EPID object.
 *
 * \param this	A pointer to the EPID object which is to have platform
 *		information added to it.
 *
 * \param info	A pointer to the platform information structure that
 *		is to be added.
 *
 * \return	No return value is defined.
 */

static void add_platform_info(CO(SRDEepid, this), \
			      struct SGX_platform_info *info)

{
	STATE(S);


	S->platform_info = *info;
	return;
}


/**
 * External public method.
 *
 * This method implements an accessor method for returning the object
 * which holds the sealed EPID blob.
 *
 * \param this	A pointer to the EPID object which is to have its
 *		EPID blob returned.
 *
 * \return	If the EPID blob has been loaded a pointer Buffer
 *		object holding the blob is returned.  If the blob
 *		has not been loaded or the object is poisoned a
 *		null pointer is returned.
 */

static Buffer get_epid(CO(SRDEepid, this))

{
	STATE(S);


	/* Verify object status. */
	if ( S->poisoned )
		return NULL;

	return S->epid;
}


/**
 * External public method.
 *
 * This method implements a diagnostic method for dumping out the
 * state of an EPID object.
 *
 * \param this	A pointer to the object whose state is to be printed.
 *
 * \return	No return value is defined.
 */

static void dump(CO(SRDEepid, this))

{
	STATE(S);

	Buffer bufr = NULL;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("Object is poisoned.\n", stderr);
		return;
	}
	if ( S->epid == NULL ) {
		fputs("EPID not loaded.\n", stderr);
		return;
	}


	/* Output the various components of the object. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	fputs("SEALED BLOB:\n", stdout);
	S->epid->hprint(S->epid);

	fputs("\nGROUP INFORMATION:\n", stdout);
	fprintf(stdout, "\tExtended group id: %u\n", S->xeid);
	fputs("\tGroup certificate id: ", stdout);
	bufr->add(bufr, S->gid, sizeof(S->gid));
	bufr->print(bufr);

	fputs("\nPLATFORM INFO:\n", stdout);
	bufr->reset(bufr);
	if ( !bufr->add(bufr, S->platform_info.cpu_svn, \
			sizeof(S->platform_info.cpu_svn)) )
		ERR(goto done);
	fputs("\tcpu svn: ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\tpve svn: %u\n", S->platform_info.pve_svn);
	fprintf(stdout, "\tpce svn: %u\n", S->platform_info.pce_svn);
	fprintf(stdout, "\tpce id:  %u\n", S->platform_info.pce_id);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, (void *) S->platform_info.fmsp, \
			sizeof(S->platform_info.fmsp)) )
		ERR(goto done);
	fputs("\tFMSP:    ", stdout);
	bufr->print(bufr);


 done:
	WHACK(bufr);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for the SRDEepid object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SRDEepid, this))

{
	STATE(S);


	WHACK(S->epid);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SRDEepid object.
 *
 * \return	A pointer to the initialized SRDEepid.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SRDEepid NAAAIM_SRDEepid_Init(void)

{
	Origin root;

	SRDEepid this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SRDEepid);
	retn.state_size   = sizeof(struct NAAAIM_SRDEepid_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SRDEepid_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->load = load;
	this->save = save;

	this->add_epid		= add_epid;
	this->add_platform_info = add_platform_info;

	this->get_epid = get_epid;

	this->dump  = dump;
	this->whack = whack;

	return this;
}
