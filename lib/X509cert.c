/** \file
 * This contains the implementation of an object that is used to
 * manage and manipulate X.509 certificates.
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
#include <string.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "X509cert.h"


/* State definition macro. */
#define STATE(var) CO(X509cert_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_X509cert_OBJID)
#error Object identifier not defined.
#endif


/** X509cert private state information. */
struct NAAAIM_X509cert_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Flag to indicate that time should not be checked. */
	_Bool check_time;

	/* Object to hold certificates added to certificate store. */
	Buffer certs;

	/* Certificate store. */
	X509_STORE *store;

	/* Certificate verification context. */
	X509_STORE_CTX *context;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_X509cert_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(X509cert_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_X509cert_OBJID;

	S->poisoned   = false;
	S->check_time = true;

	S->certs   = NULL;
	S->store   = NULL;
	S->context = NULL;

	return;
}


/**
 * External public method.
 *
 * This method initializes a certificate store and adds a certificate to
 * the store.  The model is to add certificates to the store that
 * lead back to a trust root.  When the certificate chain is complete
 * a call can be made to the ->verify method to determine whether or
 * not the certificate stack is trusted.
 *
 * \param this		The object which a certificate is to be
 *			added to.
 *
 * \param certificate	A pointer to the object containing the
 *			certificate to be added.
 *
 * \return		A boolean value is used to indicate the
 *			success or failure of building the certificate
 *			stack.  A false value indicates that a failure
 *			occurred and the certificate stack is in an
 *			indeterminate state.  A true value indicates
 *			the certificiate stack has been updated.
 */

static _Bool add(CO(X509cert, this), CO(Buffer, certificate))

{
	STATE(S);

	_Bool retn = false;

	BIO *mb = NULL;

	X509 *cert = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( certificate == NULL )
		ERR(goto done);
	if ( certificate->poisoned(certificate) )
		ERR(goto done);


	/* Initialize the certificate store if needed. */
	if ( S->store == NULL ) {
		if ( (S->store = X509_STORE_new()) == NULL )
			ERR(goto done);
	}
	if ( S->certs == NULL ) {
		INIT(HurdLib, Buffer, S->certs, ERR(goto done));
	}


	/* Add the certificate. */
	mb = BIO_new_mem_buf(certificate->get(certificate), \
			     certificate->size(certificate));
	if ( (cert = PEM_read_bio_X509(mb, NULL, 0, NULL)) == NULL )
		ERR(goto done);

	if ( X509_STORE_add_cert(S->store, cert) <= 0 )
		ERR(goto done);
	if ( !S->certs->add(S->certs, (unsigned char *) &cert, sizeof(cert)) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	if ( mb != NULL)
		BIO_free(mb);

	return retn;
}


/**
 * External public method.
 *
 * This method verifies a certificate against a stack of certificates
 * that have been previously set up as a trusted root.
 *
 * \param this		The object which is to verify the certificate.
 *
 * \param certificate	A pointer to the certificate that is to be
 *			verified.
 *
 * \param status	A pointer to the flag variable that will be
 *			updated with the verification state of the
 *			certificate.
 *
 * \return		A boolean value is used to indicate the
 *			success or failure of the verification process.
 *			A false value indicates that a failure
 *			occurred and the status of the status variable
 *			is not deterministic.  A true value indicates
 *			the certificate verification has completed
 *			and the status variable indicates the
 *			verification status of the certificate.
 */

static _Bool verify(CO(X509cert, this), CO(Buffer, certificate), _Bool *status)

{
	STATE(S);

	_Bool retn = false;

	int verify_retn;

	BIO *mb = NULL;

	X509 *cert = NULL;

	X509_VERIFY_PARAM *param = NULL;


	/* Verify object state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->store == NULL )
		ERR(goto done);
	if ( certificate == NULL )
		ERR(goto done);
	if ( certificate->poisoned(certificate) )
		ERR(goto done);


	/* Load the certificate. */
	mb = BIO_new_mem_buf(certificate->get(certificate), \
			     certificate->size(certificate));
	if ( (cert = PEM_read_bio_X509(mb, NULL, 0, NULL)) == NULL )
		ERR(goto done);


	/* Create a verification context if needed and then initialize it. */
	if ( S->context == NULL ) {
		if ( (S->context = X509_STORE_CTX_new()) == NULL )
			ERR(goto done);
	}
	if ( X509_STORE_CTX_init(S->context, S->store, cert, NULL) != 1 )
		ERR(goto done);


	/* Turn off certificate time checking if specified. */
	if ( !S->check_time ) {
		if ( (param = X509_STORE_CTX_get0_param(S->context)) == NULL )
			ERR(goto done);
		X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
	}


	/* Verify the certificate store. */
	if ( (verify_retn = X509_verify_cert(S->context)) < 0 )
		ERR(goto done);

	retn	= true;
	*status = verify_retn;


 done:
	if ( !retn )
		S->poisoned = true;

	if ( mb != NULL )
		BIO_free(mb);
	if ( cert != NULL )
		X509_free(cert);

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor method for setting whether or
 * not time checking should be carried out during certification
 * validation.
 *
 * \param this		A pointer to the object whose time checking
 *			characteristics are to be modified.
 *
 * \param action	The state that time checking is to be set to.
 */

static void time_check(CO(X509cert, this), const _Bool action)

{
	STATE(S);

	S->check_time = action;
	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a X509cert object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(X509cert, this))

{
	STATE(S);

	unsigned int lp;

	X509 *cert = NULL;


	/* Free the certificate stack. */
	if ( S->certs != NULL ) {
		for (lp= 0; lp < (S->certs->size(S->certs) / sizeof(cert)); \
			     ++lp) {
			memcpy(&cert, S->certs->get(S->certs) + \
			       (lp * sizeof(void *)), sizeof(void *));
			X509_free(cert);
		}
		WHACK(S->certs);
	}

	if ( S->store != NULL )
		X509_STORE_free(S->store);
	if ( S->context != NULL )
		X509_STORE_CTX_free(S->context);


	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a X509cert object.
 *
 * \return	A pointer to the initialized X509cert.  A null value
 *		indicates an error was encountered in object generation.
 */

extern X509cert NAAAIM_X509cert_Init(void)

{
	Origin root;

	X509cert this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_X509cert);
	retn.state_size   = sizeof(struct NAAAIM_X509cert_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_X509cert_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */

	/* Method initialization. */
	this->add    = add;
	this->verify = verify;

	this->time_check = time_check;

	this->whack = whack;

	return this;
}
