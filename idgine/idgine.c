/** \file
 *
 * This file implements the identity generation daemon.  This daemon
 * is responsible for loading the identity tree root and then listens
 * for requests to generate identities.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#if 0
#define IDENTITY_ROOT "/etc/conf/idroot.conf"
#else
#define IDENTITY_ROOT "./idroot.conf"
#endif


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <Config.h>
#include <String.h>

#include <SHA256.h>
#include <OrgID.h>

#include "Identity.h"
#include "IDengine.h"


/* Static variable definitions. */

/* The organizational identity. */
static OrgID OrganizationID = NULL;

/* The organizational identity configuration. */
static Config IDconfig = NULL;

/* Structure to hold indicators as to which signal was generated. */
struct {
	_Bool sigusr1;
	_Bool sigint;
} Signals;


/**
 * Private function.
 *
 * This function implements the signal handler for the utility.  It
 * sets the signal type in the signals structure.
 *
 * \param signal	The number of the signal which caused the
 *			handler to execute.
 */

void signal_handler(int signal)

{
	switch ( signal ) {
		case SIGUSR1:
			Signals.sigusr1 = true;
			break;
		case SIGINT:
			Signals.sigint = true;
			break;
	}

	return;
}


/**
 * Private function.
 *
 * This function is responsible for checking for the presence of
 * a device identity on the root filesystem and loading it into
 * NVram if it is authentic.
 *
 * \return		A false value indicates the identity root
 *			was no properly initialized.  A true value
 *			indicates the identity state was properly
 *			initialized.
 */

static _Bool load_identity_root(void)

{
	_Bool retn = false;

	char *anonymizer,
	     *identifier;


	if ( !IDconfig->parse(IDconfig, IDENTITY_ROOT) )
		goto done;

	IDconfig->set_section(IDconfig, "Default");
	if ( (identifier = IDconfig->get(IDconfig, "identifier")) == NULL )
		goto done;
	if ( (anonymizer = IDconfig->get(IDconfig, "anonymizer")) == NULL )
		goto done;
	if ( !OrganizationID->create(OrganizationID, anonymizer, identifier) )
		goto done;

	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This funciton is responsible for creation of the identity with
 * parameters provided by the caller.
 *
 * \param type		The type of the identity, ie. user, service
 *			or device which is to be created.
 *
 * \param name		The name of the identity which is to be
 *			created.
 *
 * \param identifier	The identifier which is to be used to generate
 *			the identity.
 *
 * \param identity	The Identity object containing the generated
 *			identity.
 *
 * \return		A false value is used to indicated that an
 *			error was encountered while generating the
 *			identity.  A true value indicates the identity
 *			is valied.
 */

static _Bool create_identity(const IDengine_identity type, CO(String, name), \
			     CO(String, identifier), CO(Identity, identity))

{
	_Bool retn = false;

	char *anon;

	String anonymizer = NULL;


	/*
	 * Set the section based on the name of the identity and
	 * then fetch the anonymizer for that identity.
	 */
	if ( !IDconfig->set_section(IDconfig, name->get(name)) )
		goto done;
	if ( (anon = IDconfig->get(IDconfig, "anonymizer")) == NULL )
		goto done;

	INIT(HurdLib, String, anonymizer, goto done);
	if ( !anonymizer->add(anonymizer, anon) )
		goto done;

	/* Call the identity generation. */
	if ( !identity->create(identity, OrganizationID, anonymizer, \
			       identifier) )
		goto done;

	retn = true;


 done:
	WHACK(anonymizer);

	return retn;
}
		

/**
 * Private function.
 *
 * This function is responsible for implementing the identity generation
 * processing loop.  This function pauses waiting for a SIGUSR1 signal.
 * When it receives a signal it reads the identity request structure
 * for the type of identity to be generated, the name of the identity
 * to be created and the identifier which is to be used for generating
 * the identity.
 *
 * These parameters are used to generate the identity rooted within
 * the identity heirarchy of the organization.  This value is returned
 * via IPC to the client.
 *
 * \return		No return value is specified.
 */

static void identity_generator(void)

{
	struct sigaction signal_action;

	String name = NULL,
	       identifier = NULL;

	IDengine_identity idtype;

	IDengine idengine = NULL;

	Identity identity = NULL;


	INIT(HurdLib, String, name, goto done);
	INIT(HurdLib, String, identifier, goto done);
	INIT(NAAAIM, Identity, identity, goto done);

	INIT(NAAAIM, IDengine, idengine, goto done);
	if ( !idengine->setup(idengine) )
		goto done;

	signal_action.sa_handler = signal_handler;
	if ( sigaction(SIGUSR1, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGINT, &signal_action, NULL) == -1 )
		goto done;

	while ( 1 ) {
		pause();
		if ( Signals.sigint )
			goto done;

		if ( !idengine->get_id_info(idengine, &idtype, name, \
					    identifier) )
			continue;

		fputs("Processing identity request.\n", stderr);
		fprintf(stdout, "type=%d\n", idtype);
		fputs("name=", stderr);
		name->print(name);
		fputs("identifier=", stderr);
		identifier->print(identifier);

		if ( create_identity(idtype, name, identifier, identity) )
		     idengine->set_identity(idengine, identity);

		name->reset(name);
		identifier->reset(identifier);
		identity->reset(identity);

		Signals.sigint = false;
	}


 done:
	WHACK(name);
	WHACK(identifier);
	WHACK(idengine);
	WHACK(identity);

	return;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;


	/* Initialize static objects and load the identity root. */
	INIT(HurdLib, Config, IDconfig, goto done);
	INIT(NAAAIM, OrgID, OrganizationID, goto done);

	if ( !load_identity_root() ) {
		fputs("Error initializing identity root.\n", stderr);
		goto done;
	}
	fputs("Organization ID:\n", stdout);
	OrganizationID->print(OrganizationID);


	/* Run the identity generator loop. */
	identity_generator();
	retn = 0;


 done:
	WHACK(IDconfig);
	WHACK(OrganizationID);

	return retn;
}
