/** \file
 * This file provides the method implementations for an object which
 * implements the execution of commands against an HTTP server.
 *
 * In order to expedite development of this object the initial
 * development strategy is to use this object as a wrapper around the
 * wget command.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */

/* Macro to clear an array object. */
#define GWHACK(type, var) {			\
	size_t i=var->size(var) / sizeof(type);	\
	type *o=(type *) var->get(var);		\
	while ( i-- ) {				\
		(*o)->whack((*o));		\
		o+=1;				\
	}					\
}


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "HTTP.h"

/* Object state extraction macro. */
#define STATE(var) CO(HTTP_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_HTTP_OBJID)
#error Object identifier not defined.
#endif


/** HTTP private state information. */
struct NAAAIM_HTTP_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Command-line arguements and pointers. */
	Buffer args;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_HTTP_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(HTTP_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_HTTP_OBJID;

	S->poisoned  = false;

	return;
}


/**
 * External public method.
 *
 * This method implements a method for adding an arguement to the
 * set of command-line arguements which will be passed to the wget
 * utility.
 *
 * \param this		A pointer to the object which will execute
 *			the HTTP request.
 *
 * \param arg		A pointer to the null-terminated character
 *			buffer containing the command-line arguement
 *			to be added.
 *
 * \return	If an error is encountered while adding the
 *		command-line arguement a false value is returned.  A
 *		true value indicates the arguement was successfully
 *		added.
 */

static _Bool add_arg(CO(HTTP, this), CO(char *, arg))

{
	STATE(S);

	_Bool retn = false;

	String entry;


	/* Validate object. */
	if ( S->poisoned )
		ERR(goto done);


	/* Add the pointer to the current arguement list. */
	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, arg) )
		ERR(goto done);

	if ( !S->args->add(S->args, (void *) &entry, sizeof(entry)) )
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
 * This method implements a method for issueing a POST command to
 * a server with capturing of the message body of the server.
 *
 * \param this		A pointer to the object which will execute
 *			the the POST command.
 *
 * \param url		A pointer to a null-terminated buffer
 *			containing the URL which the post is to be
 *			directed to.
 *
 * \param input		A pointer to the buffer containing the data
 *			that is to be posted to the server.
 *
 * \param output	A pointer to the buffer that will contain the
 *			results of the post command.
 *
 * \return	If an error is encountered while executing the command
 *		a false value is returned.  A true value indicates the
 *		command was successfully processed.  It is important
 *		to note that a successful response does not
 *		necessarily imply that the output buffer will contain
 *		any data.
 */

static _Bool post(CO(HTTP, this), CO(char *, url), CO(Buffer, input), \
		  CO(Buffer, output))

{
	STATE(S);

	_Bool retn = false;

	int rc,
	    status;

	size_t cnt;

	char *arg,
	     *in_file  = NULL,
	     *out_file = NULL,
	     *cmd      = "wget",
	     *O_arg    = "-O",
	     *post_arg = "--post-file";

	pid_t pid;

	File postfile = NULL;

	Buffer post_args = NULL,
	       exec_args = NULL;

	String *pentry,
		entry = NULL;


	/* Validate object and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( input->poisoned(input) )
		ERR(goto done);
	if ( output->poisoned(output) )
		ERR(goto done);


	/* Create the input file. */
	if ( (in_file = tempnam(NULL, "HTTPi")) == NULL )
		ERR(goto done);

	INIT(HurdLib, File, postfile, ERR(goto done));
	if ( !postfile->open_rw(postfile, in_file) )
		ERR(goto done);
	if ( !postfile->write_Buffer(postfile, input) )
		ERR(goto done);

	/* Create the arguement list.*/
	INIT(HurdLib, Buffer, post_args, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, post_arg) )
		ERR(goto done);
	if ( !post_args->add(post_args, (void *) &entry, sizeof(String)) )
		ERR(goto done);

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, in_file) )
		ERR(goto done);
	if ( !post_args->add(post_args, (void *) &entry, sizeof(String)) )
		ERR(goto done);

	/* Setup the output file arguements. */
	if ( (out_file = tempnam(NULL, "HTTPo")) == NULL )
		ERR(goto done);

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, O_arg) )
		ERR(goto done);
	if ( !post_args->add(post_args, (void *) &entry, sizeof(String)) )
		ERR(goto done);

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, out_file) )
	     ERR(goto done);
	if ( !post_args->add(post_args, (void *) &entry, sizeof(String)) )
		ERR(goto done);


	/* Setup the URL arguement and null. */
	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, url) )
		ERR(goto done);
	if ( !post_args->add(post_args, (void *) &entry, sizeof(String)) )
		ERR(goto done);


	/* Create the execv() arguement list. */
	INIT(HurdLib, Buffer, exec_args, ERR(goto done));
	if ( !exec_args->add(exec_args, (void *) &cmd, sizeof(String)) )
		ERR(goto done);

	if ( S->args->size(S->args) > 0 ) {
		cnt = S->args->size(S->args) / sizeof(String);
		pentry = (String *) S->args->get(S->args);
		while ( cnt-- ) {
			entry = *pentry;
			arg = entry->get(entry);
			exec_args->add(exec_args, (void *) &arg, \
				       sizeof(char *));
			++pentry;
		}
		if ( exec_args->poisoned(exec_args) )
			ERR(goto done);
	}

	/* Add arguements specific to this post. */
	cnt = post_args->size(post_args) / sizeof(String *);
	pentry = (String *) post_args->get(post_args);
	while ( cnt-- ) {
		entry = *pentry;
		arg = entry->get(entry);
		exec_args->add(exec_args, (void *) &arg, \
			       sizeof(char *));
		++pentry;
	}
	if ( exec_args->poisoned(exec_args) )
		ERR(goto done);

	/* Add the null arguement. */
	entry = NULL;
	if ( !exec_args->add(exec_args, (void *) &entry, sizeof(char *)) )
		ERR(goto done);


	/* Fork and exec the command. */
	if ( (pid = fork()) == -1 )
		ERR(goto done);

	/* Child. */
	if ( pid == 0 ) {
		execvp(cmd, (char * const *) exec_args->get(exec_args));
		_exit(1);
	}

	/* Parent. */
	if ( pid != waitpid(pid, &status, 0) )
		ERR(goto done);
	if ( WIFEXITED(status) ) {
		if ( (rc = WEXITSTATUS(status)) != 0 ) {
			fprintf(stderr, "wget exit code: %d\n", rc);
			ERR(goto done);
		}
	}


	/* Load the output. */
	postfile->reset(postfile);
	if ( !postfile->open_ro(postfile, out_file) )
		ERR(goto done);
	if ( !postfile->slurp(postfile, output) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	unlink(in_file);
	free(in_file);

	unlink(out_file);
	free(out_file);

	WHACK(postfile);

	GWHACK(String, post_args);
	WHACK(post_args);

	WHACK(exec_args);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for the HTTP object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(HTTP, this))

{
	STATE(S);


	GWHACK(String, S->args);
	WHACK(S->args);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a HTTP object.
 *
 * \return	A pointer to the initialized HTTP.  A null value
 *		indicates an error was encountered in object generation.
 */

extern HTTP NAAAIM_HTTP_Init(void)

{
	Origin root;

	HTTP this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_HTTP);
	retn.state_size   = sizeof(struct NAAAIM_HTTP_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_HTTP_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->args, goto err);

	/* Method initialization. */
	this->post = post;

	this->add_arg = add_arg;

	this->whack = whack;

	return this;


 err:
	return NULL;
}
