/** \file
 *
 */

/**************************************************************************
 * Copyright (c) 2025, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Location of a file containing the Elasticsearch password. */
#define TSEM_ES_PWD_FILE "/opt/Quixote/etc/es.pwd"


/* Include files. */
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "Origin.h"
#include "HurdLib.h"
#include "Buffer.h"
#include "String.h"
#include "File.h"

#include "NAAAIM.h"
#include "ESclient.h"

#include "curl/curl.h"


/* State extraction macro. */
#define STATE(var) CO(ESclient_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_ESclient_OBJID)
#error Object identifier not defined.
#endif


/** ESclient private state information. */
struct NAAAIM_ESclient_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object state. */
	_Bool poisoned;

	/* The libcurl context object. */
	CURL *ctxt;

	/* The list of headers used for a request. */
	struct curl_slist *hdrs;

	/* Object used to accumulate output. */
	Buffer output;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_ESclient_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(ESclient_State, S))



{
	INIT_STATE(S, NAAAIM, ESclient);
	return;
}


/**
 * Internal private function.
 *
 * This method implements setting of the password that will be used to
 * authenticate to the endpoint.  This method is called if a NULL
 * password is passed to the ESclient->init method.
 *
 * If the TSEM_ES_PWD environment variable is set the value of the
 * environment variable is used.  If this value is not set the password
 * is read from the following file:
 *
 * /opt/Quixote/etc/es.pwd
 *
 * \param pwd	A character pointer to a null-terminated buffer containing
 *		the password that was specifically configured.  If this
 *		value is NULL it will trigger the search for a password in
 *		alternate locations.
 *
 * \param auth	The object containing the authentication information to
 *	        which the password will be appended.
 *
 * \return	A boolean return value is used to indicate success or
 *		failure of password initialization.  A true value is used
 *		to indicate success while a false value indicates the
 *		password was not successfully set.
 */

static _Bool _set_password(CO(char *, pwd), CO(String, auth))

{
	_Bool retn = false;

	char *p;

	File pwd_file = NULL;


	/* Use specific password if provided. */
	if ( pwd != NULL ) {
		if ( !auth->add(auth, pwd) )
			ERR(goto done);
		return true;
	}

	/* Check for an environment variable override. */
	if ( (p = getenv("TSEM_ES_PWD")) != NULL ) {
		if ( !auth->add(auth, p) )
			ERR(goto done);
		return true;
	}

	/* Look for a file based password. */
	INIT(HurdLib, File, pwd_file, ERR(goto done));
	if ( !pwd_file->open_ro(pwd_file, TSEM_ES_PWD_FILE) )
		ERR(goto done);
	if ( !pwd_file->read_String(pwd_file, auth) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(pwd_file);

	return retn;
}


/*
 * Private helper function.
 *
 * This function is the callback routine for the command that is executed.
 * If an output object has been set the output that is generated is
 * added to the output object.
 */

static size_t _output_cb(void *data, size_t size, size_t nmemb, void *output)

{
	unsigned char *p = data;

	size_t retn = size * nmemb;

	Buffer bufr = output;


	if ( bufr == NULL )
		return retn;

	if ( !bufr->add(bufr, p, size) )
		return 0;
	return retn;
}


/**
 * External public method.
 *
 * This method initializes the object for connecting to an ElasticSearch
 * endpoint
 *
 * \param this		The object that will be initialized.
 *
 * \param host		A pointer to a null-terminated character buffer
 *			containing the name of the host to connect to.
 *
 * \param index		The name of the index that will be updated using
 *			this object.
 *
 * \param user		The name of the user that will be used to
 *			authenticate the connection.
 *
 * \param pwd		The password to be used.  If the password is
 *			NULL a protocol will be followed that will attempt
 *			to obtain the password from an environment
 *			variable or a file.
 *
 * \param bufr		The Buffer object that will be used to hold the
 *			output of commands that are executed.  A NULL
 *			value will result in command output being
 *			suppressed.  The supplied object will be under
 *			the control of the caller and will not be
 *			destroyed by the destructor for the this
 *			object.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		initialization succeeded.  A false value indicates the
 *		initialized failed and the object cannot be used.  A
 *		true value indicates the object is prepared to inject
 *		event descriptions into the specifed Elasticsearch
 *		instance.
 */

static _Bool init(CO(ESclient, this), CO(char *, host), CO(char *, index), \
		  CO(char *, user), CO(char *, pwd), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	String authinfo = NULL;


	/* Check object state. */
	if ( S->poisoned )
		ERR(goto done);

	/* Create the library context object. */
	if ( (S->ctxt = curl_easy_init()) == NULL )
		ERR(goto done);

	/* Set the endpoint name. */
	INIT(HurdLib, String, authinfo, ERR(goto done));

	if ( !authinfo->add_sprintf(authinfo, "https://%s:9200/%s/_doc", \
				host, index) )
		ERR(goto done);

	if ( curl_easy_setopt(S->ctxt, CURLOPT_URL, \
			      authinfo->get(authinfo)) != CURLE_OK )
		ERR(goto done);

	/* Set the authentication information .*/
	authinfo->reset(authinfo);
	if ( !authinfo->add_sprintf(authinfo, "%s:", user) )
		ERR(goto done);

	if ( !_set_password(pwd, authinfo) )
		ERR(goto done);

	if ( curl_easy_setopt(S->ctxt, CURLOPT_USERPWD, \
			       authinfo->get(authinfo)) != CURLE_OK )
		ERR(goto done);

	/* Set the boilerplate definitions. */
	if ( curl_easy_setopt(S->ctxt, CURLOPT_NOPROGRESS, 1L) != CURLE_OK )
		ERR(goto done);
	if ( curl_easy_setopt(S->ctxt, CURLOPT_USERAGENT, "curl/8.13.0") !=
	     CURLE_OK )
		ERR(goto done);
	if ( curl_easy_setopt(S->ctxt, CURLOPT_SSL_VERIFYPEER, 0L) != \
	     CURLE_OK )
		ERR(goto done);
	if ( curl_easy_setopt(S->ctxt, CURLOPT_SSL_VERIFYHOST, 0L) != \
	     CURLE_OK )
		ERR(goto done);
	if ( curl_easy_setopt(S->ctxt, CURLOPT_FTP_SKIP_PASV_IP, 1L) != \
	     CURLE_OK )
		ERR(goto done);
	if ( curl_easy_setopt(S->ctxt, CURLOPT_TCP_KEEPALIVE, 1L) != CURLE_OK )
		ERR(goto done);
	if ( curl_easy_setopt(S->ctxt, CURLOPT_HTTPHEADER, S->hdrs) != \
	     CURLE_OK )
		ERR(goto done);

	/* Set the application type. */
	S->hdrs = curl_slist_append(NULL, "Content-Type: application/json");
	if ( S->hdrs == NULL )
		ERR(goto done);

	if ( curl_easy_setopt(S->ctxt, CURLOPT_HTTPHEADER, S->hdrs) != \
	     CURLE_OK )
		ERR(goto done);

	/* Setup the callback function and object. */
	if ( curl_easy_setopt(S->ctxt, CURLOPT_WRITEFUNCTION, _output_cb) != \
	     CURLE_OK)
		ERR(goto done);
	if ( curl_easy_setopt(S->ctxt, CURLOPT_WRITEDATA, bufr) != CURLE_OK )
		ERR(goto done);

	retn = true;


 done:
	WHACK(authinfo);

	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method injects a document into the endpoint configured as the
 * destination endpoint for the object.
 *
 * \param this		The object that will be used for the update.
 *
 * \param str		A pointer to the object containing the value to
 *			be injected into the index.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		injectino of the value succeeded.  A false value indicates
 *		the injection failed and the object cannot be used until
 *		it is reset.  A true value indicates the value was
 *		successfully loaded into the endpoint.
 */

static _Bool inject(CO(ESclient, this), CO(String, str))

{
	STATE(S);

	_Bool retn = false;


	/* Check object state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->ctxt == NULL )
		ERR(goto done);

	/* Set the size of the update and the payload. */
	if ( curl_easy_setopt(S->ctxt, CURLOPT_POSTFIELDSIZE_LARGE, \
			      str->size(str)) != CURLE_OK )
		ERR(goto done);

	if ( curl_easy_setopt(S->ctxt, CURLOPT_POSTFIELDS, str->get(str)) \
	     != CURLE_OK)
		ERR(goto done);

	/* Request the transcation. */
	if ( curl_easy_perform(S->ctxt) != CURLE_OK )
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
 * This method implements a destructor for a ESclient object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(ESclient, this))

{
	STATE(S);


	curl_easy_cleanup(S->ctxt);
	curl_slist_free_all(S->hdrs);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a ESclient object.
 *
 * \return	A pointer to the initialized ESclient.  A null value
 *		indicates an error was encountered in object generation.
 */

extern ESclient NAAAIM_ESclient_Init(void)

{
	Origin root;

	ESclient this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_ESclient);
	retn.state_size   = sizeof(struct NAAAIM_ESclient_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_ESclient_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->init   = init;
	this->inject = inject;

	this->whack = whack;

	return this;
}
