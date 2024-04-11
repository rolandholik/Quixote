/** \file
 * This file implements methods which allow the publication of event
 * strings to an MQTT broker.
 */

/**************************************************************************
 * Copyright (c) 2023 Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include <mosquitto.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "MQTTduct.h"

/* State extraction macro. */
#define STATE(var) CO(MQTTduct_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_MQTTduct_OBJID)
#error Object identifier not defined.
#endif


/** MQTTduct private state information. */
struct NAAAIM_MQTTduct_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* MQTT error code. */
	int error;

	/* Object status. */
	enum {not_defined, connected, publisher} type;

	/* mosquitto context and topic. */
	struct mosquitto *ctx;
	String topic;
	unsigned int count;

	/* Broker port and hostname .*/
	String port;
	String broker;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Duct_State
 * structure which holds state information for each instantiated object.
 * The object is started out in poisoned state to catch any attempt
 * to use the object without initializing it.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(MQTTduct_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_MQTTduct_OBJID;


	S->poisoned = false;

	S->error = 0;

	S->type	= not_defined;

	S->ctx	 = NULL;
	S->topic = NULL;
	S->count = 0;

	S->port	  = NULL;
	S->broker = NULL;

	mosquitto_lib_init();

	return;
}


/**
 * Internal private function.
 *
 * This method is a helper function for the _init_client_publisher method.
 * It's purpose is to receive verification that a connection to the
 * specified broker has been completed.
 *
 * \param ctx	A pointer to the mosquitto library context that is
 *		being used for the connection.
 *
 * \param obj	A pointer to the MQTTduct object that is invoking the
 *		connection.
 *
 * \param code	An error code defining the reason for the connection
 *		failure.
 *
 * \return	No return value is defined.
 */

static void _connect_callback(struct mosquitto *ctx, void *obj, int code)

{
	MQTTduct_State S = obj;


	if ( code != 0 ) {
		S->error    = code;
		S->poisoned = true;
	}

	S->type = connected;

	return;
}


/**
 * Internal private function.
 *
 * This method is a helper function for the _init_client_publisher method.
 * It's purpose is to receive verification that a message has been
 * published to the broker.
 *
 * \param ctx	A pointer to the mosquitto library context that is
 *		being used for the connection.
 *
 * \param obj	A pointer to the MQTTduct object that is invoking the
 *		connection.
 *
 * \param id	The id of the message that was published.
 *
 * \return	No return value is defined.
 */

static void _publish_callback(struct mosquitto *ctx, void *obj, int code)

{
	MQTTduct_State S = obj;

	--S->count;
	return;
}


/**
 * Internal private method.
 *
 * This method implements initialization of a connection to a broker.
 *
 * \param this		A pointer to the state information for the
 *			publishing client.
 *
 * \param broker	A pointer to a null-terminated buffer containing
 *			the hostname of the broker the client is to
 *			publish to.
 *
 * \param topic		A pointer to a null-terminated buffer containing
 *			the topic name to publish to.
 *
 * \param user		A pointer to a null-terminated buffer containing
 *			the username to be used for authenticating the
 *			connection.  A NULL value is used to indicate
 *			anonymous access.
 *
 * \param pwd		A pointer to a null-terminated buffer containing
 *			the password to be used in combination with the
 *			username for authentication.  A NULL value
 *			indicates that no password is available.
 *
 * \return	A boolean return value is used to indicate success or
 *		failure of broker initialization.  A true value is used
 *		to indicate success.
 */

static _Bool init_publisher(CO(MQTTduct, this), CO(char *, broker), int port, \
			    CO(char *, topic), CO(char *, user),	      \
			    CO(char *, pwd))

{
	STATE(S);

	_Bool retn = false;


	/* Save the topic. */
	if ( !S->topic->add(S->topic, topic) )
		ERR(goto done);

	/* Create a communications context for the object. */
	if ( (S->ctx = mosquitto_new(NULL, true, S)) == NULL )
		ERR(goto done);

	if ( (user != NULL) && (pwd != NULL) ) {
		S->error = mosquitto_username_pw_set(S->ctx, user, pwd);
		if ( S->error != MOSQ_ERR_SUCCESS )
			ERR(goto done);
	}

	/* Setup the connection. */
	mosquitto_connect_callback_set(S->ctx, _connect_callback);
	mosquitto_publish_callback_set(S->ctx, _publish_callback);

	port = port == 0 ? 1883 : port;
	S->error = mosquitto_connect(S->ctx, broker, port, 60);
	if ( S->error != MOSQ_ERR_SUCCESS )
		ERR(goto done);

	/* Wait for the broker connection. */
	S->error = mosquitto_loop_start(S->ctx);
	if ( S->error != MOSQ_ERR_SUCCESS )
		ERR(goto done);

	while ( S->type != connected )
		sleep(1);

	S->type = publisher;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements sending the contents of a specified String object
 * over the connection represented by the calling object.
 *
 * \param this	The object over which the String is to be sent.
 *
 * \return	A boolean value is used to indicate whether or the
 *		write was successful.  A true value indicates the
 *		transmission was successful.
 */

static _Bool send_String(CO(MQTTduct, this), CO(String, str))

{
	STATE(S);

	_Bool retn = false;

	if ( S->poisoned )
		ERR(goto done);
	if ( (str == NULL) || str->poisoned(str))
		ERR(goto done);

	if ( (S->error = mosquitto_publish(S->ctx, NULL,		     \
					   S->topic->get(S->topic),	     \
					   str->size(str), str->get(str), 0, \
					   false)) != MOSQ_ERR_SUCCESS )
		ERR(goto done);
	++S->count;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements resetting of a duct object.  Its primary use
 * is in a server object to reset the accepted file descriptor.
 *
 * \param this	The object which is to be reset.
 *
 * \return	No return value is defined.
 */

static void reset(CO(MQTTduct, this))

{
	STATE(S);

	/* Verify that the transmission queue is empty. */
	while ( S->count > 0 )
		sleep(1);

	S->error = 0;
	S->poisoned = false;
	S->type = not_defined;

	S->topic->reset(S->topic);

	mosquitto_destroy(S->ctx);
	S->ctx = NULL;
	S->count = 0;


	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a MQTTduct object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(MQTTduct, this))

{
	STATE(S);


	/* Reset the connection. */
	this->reset(this);

	/* Free client library resources. */
	mosquitto_lib_cleanup();

	/* Destroy internal resources. */
	S->topic->whack(S->topic);

	/* Destroy the object. */
	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a Duct object.
 *
 * \return	A pointer to the initialized Duct.  A null value
 *		indicates an error was encountered in object generation.
 */

extern MQTTduct NAAAIM_MQTTduct_Init(void)

{
	Origin root;

	MQTTduct this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_MQTTduct);
	retn.state_size   = sizeof(struct NAAAIM_MQTTduct_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_MQTTduct_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, String, this->state->topic, goto fail);

	/* Method initialization. */
	this->init_publisher = init_publisher;

	this->send_String = send_String;

	this->reset = reset;
	this->whack = whack;

	return this;


fail:
	WHACK(this->state->topic);

	root->whack(root, this, this->state);
	return NULL;
}
