/** \file
 *
 * This file implements a utility for managing a cboot instance.  This
 * utility connects to a cboot instance through a UNIX domain socket
 * created in the following location:
 *
 * /var/run/cboot.PIDNUM
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* The location of the identity verifiers for the ISOidentity enclave. */
#define VERIFIERS "/opt/IDfusion/etc/verifiers/ISOidentity/*.ivy"


/* Include files. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <glob.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/un.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <Duct.h>
#include <Buffer.h>
#include <LocalDuct.h>
#include <IDtoken.h>
#include <ISOmanager.h>

#include <SGX.h>
#include <SGXquote.h>

#include "cboot.h"


/**
 * The following enumeration type specifies whether or not the
 * management engine should be contact through an SGX POSSUM connection
 * or via a local UNIX domain connection.
 */
 enum {
	 internal,
	 sgx,
	 measure
} Mode = internal;


/**
 * Private function.
 *
 * This function implements loading of loading identifier verifiers
 * that will be used to specify the set of counter-parties that are
 * permitted access to the management thread of an SGX ISOidentity
 * modeling engine.
 *
 * If the identity verifier arguement is a NULL pointer this function
 * will attempt to load all verifiers from the following directory:
 *
 * /opt/IDfusion/etc/verifiers/ISOidentity
 *
 * \param enclave	The object representing the enclave that the
 *			identity verifiers were to be loaded into.
 *
 * \param infile	The object that will be used for doing I/O to
 *			the identity verifiers.
 *
 * \param verifier	A character pointer to the name of the file
 *			containing the specific identity verifier
 *			to use.  Otherwise the default set is
 *			loaded per the discussion above.
 *
 * \return		A boolean value is used to indicate the status
 *			of the verifier load.  A false value indicates
 *			an error was encounter while a true value
 *			indicates all of the identity verifiers were
 *			loaded.
 */

static _Bool add_verifiers(CO(ISOmanager, enclave), CO(File, infile), \
			   CO(char *, verifier))

{
	_Bool retn = false;

	glob_t identities;

	uint16_t lp;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	/* Load the specified verifier. */
	if ( verifier != NULL ) {
		infile->open_ro(infile, verifier);
		if ( !infile->slurp(infile, bufr) )
			ERR(goto done);

		if ( !enclave->add_verifier(enclave, bufr) )
			ERR(goto done);

		retn = true;
		goto done;
	}


	/* Load a verifier list. */
	if ( glob(VERIFIERS, 0, NULL, &identities) != 0 )
		ERR(goto done);
	if ( identities.gl_pathc == 0 )
		ERR(goto done);

	for (lp= 0; lp < identities.gl_pathc; ++lp) {
		infile->open_ro(infile, identities.gl_pathv[lp]);
		if ( !infile->slurp(infile, bufr) )
			ERR(goto done);

		if ( !enclave->add_verifier(enclave, bufr) )
			ERR(goto done);

		bufr->reset(bufr);
		infile->reset(infile);
	}

	retn = true;


 done:
	WHACK(bufr);

	return retn;
}


/**
 * Private function.
 *
 * This function implements the receipt of a trajectory list from
 * the canister management daemon.  The protocol used is for the
 * management daemon to send the number of points in the trajectory
 * followed by each point in ASCII form.
 *
 * \param mgmt		The socket object used to communicate with
 *			the canister management instance.
 *
 * \param cmdbufr	The object used to process the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate the
 *			status of processing processing the trajectory
 *			list.  A false value indicates an error occurred
 *			while a true value indicates the response was
 *			properly processed.
 */

static _Bool receive_trajectory(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	fprintf(stderr, "Trajectory size: %u\n", cnt);


	/* Output each point. */
	while ( cnt ) {
		cmdbufr->reset(cmdbufr);
		if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", cmdbufr->get(cmdbufr));
		--cnt;
	}

	cmdbufr->reset(cmdbufr);
	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the receipt of a forenscis list from
 * the canister management daemon.  The protocol used is for the
 * management daemon to send the number of events in the forensics
 * patch followed by each event in ASCII form.
 *
 * \param mgmt		The socket object used to communicate with
 *			the canister management instance.
 *
 * \param cmdbufr	The object used to process the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate the
 *			status of processing processing the forensics
 *			list.  A false value indicates an error occurred
 *			while a true value indicates the response was
 *			properly processed.
 */

static _Bool receive_forensics(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	fprintf(stderr, "Forensics size: %u\n", cnt);


	/* Output each point. */
	while ( cnt ) {
		cmdbufr->reset(cmdbufr);
		if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", cmdbufr->get(cmdbufr));
		--cnt;
	}

	cmdbufr->reset(cmdbufr);
	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the receipt of a contour list from
 * the canister management daemon.  The protocol used is for the
 * management daemon to send the number of points in the behavioral
 * field followed by point in ASCII hexadecimal form.
 *
 * \param mgmt		The socket object used to communicate with
 *			the canister management instance.
 *
 * \param cmdbufr	The object used to process the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate the
 *			status of processing processing the contour
 *			list.  A false value indicates an error occurred
 *			while a true value indicates the response was
 *			properly processed.
 */

static _Bool receive_contours(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	fprintf(stderr, "Contour size: %u\n", cnt);


	/* Output each point. */
	while ( cnt ) {
		cmdbufr->reset(cmdbufr);
		if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", cmdbufr->get(cmdbufr));
		--cnt;
	}

	cmdbufr->reset(cmdbufr);
	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements receipt and processing of the command
 * which was executed on the canister management daemon.
 *
 * \param mgmt		The socket object used to communicate with
 *			the canister management instance.
 *
 * \param cmdbufr	The object used to hold the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate an
 *			error was encountered while processing receipt
 *			of the command.  A false value indicates an
 *			error occurred while a true value indicates the
 *			response was properly processed.
 */

static _Bool receive_command(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr), \
			     int cmdnum)

{
	_Bool retn = false;


	switch ( cmdnum ) {
		case show_measurement:
			if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
				ERR(goto done);
			cmdbufr->print(cmdbufr);
			cmdbufr->reset(cmdbufr);
			retn = true;
			break;

		case show_trajectory:
			retn = receive_trajectory(mgmt, cmdbufr);
			break;

		case show_forensics:
			retn = receive_forensics(mgmt, cmdbufr);
			break;

		case show_contours:
			retn = receive_contours(mgmt, cmdbufr);
			break;
	}

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the parsing of the supplied command and
 * the translation of this command to a binary expression of the
 * command.  The binary command is sent over the command socket and
 * the socket is read for the command response.
 *
 * \param mgmt		The socket object used to communicate with
 *			the canister management instance.
 *
 * \param cmd		A character point to the null-terminated buffer
 *			containing the ASCII version of the command.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not processing of commands should continue.  A
 *			false value indicates the processing of commands
 *			should be terminated while a true value indicates
 *			an additional command cycle should be processed.
 */

static _Bool process_command(CO(LocalDuct, mgmt), CO(char *, cmd))

{
	_Bool retn = false;

	int lp,
	    cmdnum = 0;

	struct cboot_cmd_definition *cp = cboot_cmd_list;

	Buffer cmdbufr = NULL;


	/* Locate the command. */
	for (lp= 0; cp[lp].syntax != NULL; ++lp) {
		if ( strcmp(cp[lp].syntax, cmd) == 0 )
			cmdnum = cp[lp].command;
	}
	if ( cmdnum == 0 ) {
		fprintf(stdout, "Unknown command: %s\n", cmd);
		fflush(stdout);
		retn = true;
		goto done;
	}

	/* Send the command over the management socket. */
	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	cmdbufr->add(cmdbufr, (unsigned char *) &cmdnum, sizeof(cmdnum));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);

	cmdbufr->reset(cmdbufr);
	if ( !receive_command(mgmt, cmdbufr, cmdnum) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(cmdbufr);
	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool debug	    = false,
	      debug_enclave = true;

	char *p,
	     *canister	   = NULL,
	     *id_token	   = NULL,
	     *verifier	   = NULL,
	     *spid_fname   = SPID_FILENAME,
	     *token	   = "ISOmanager.token",
	     *hostname	   = "localhost",
	     *enclave_name = "ISOmanager.signed.so",
	     sockname[UNIX_PATH_MAX],
	     inbufr[1024];

	int opt,
	    retn = 1;

	FILE *idfile = NULL;

	Buffer id_bufr = NULL,
	       cmdbufr = NULL;

	String spid = NULL;

	LocalDuct mgmt = NULL;

	IDtoken idt = NULL;

	File infile = NULL;

	ISOmanager enclave = NULL;


	while ( (opt = getopt(argc, argv, "MSdpe:h:i:n:s:t:v:")) != EOF )
		switch ( opt ) {
			case 'M':
				Mode = measure;
				break;
			case 'S':
				Mode = sgx;
				break;

			case 'd':
				debug = true;
				break;
			case 'p':
				debug_enclave = false;
				break;

			case 'e':
				enclave_name = optarg;
				break;
			case 'h':
				hostname = optarg;
				break;
			case 'i':
				id_token = optarg;
				break;
			case 'n':
				canister = optarg;
				break;
			case 's':
				spid_fname = optarg;
				break;
			case 't':
				token = optarg;
				break;
			case 'v':
				verifier = optarg;
				break;
		}


	/* Run measurement mode. */
	if ( Mode == measure ) {
		INIT(NAAAIM, ISOmanager, enclave, ERR(goto done));
		if ( !enclave->load_enclave(enclave, enclave_name, token, \
					    debug_enclave) )
			ERR(goto done);

		INIT(HurdLib, Buffer, id_bufr, ERR(goto done));
		if ( !enclave->generate_identity(enclave, id_bufr) )
			ERR(goto done);
		id_bufr->print(id_bufr);

		goto done;
	}


	/* Setup for SGX based modeling. */
	if ( Mode == sgx ) {
		/* Load the identity token. */
		INIT(NAAAIM, IDtoken, idt, goto done);
		if ( (idfile = fopen(id_token, "r")) == NULL ) {
			fputs("Cannot open identity token file.\n", stderr);
			goto done;
		}
		if ( !idt->parse(idt, idfile) ) {
			fputs("Enable to parse identity token.\n", stderr);
			goto done;
		}

		INIT(HurdLib, Buffer, id_bufr, ERR(goto done));
		if ( !idt->encode(idt, id_bufr) ) {
			fputs("Error encoding identity token.\n", stderr);
			goto done;
		}

		/* Setup the SPID key. */
		INIT(HurdLib, String, spid, ERR(goto done));
		INIT(HurdLib, File, infile, ERR(goto done));

		if ( !infile->open_ro(infile, spid_fname) )
			ERR(goto done);
		if ( !infile->read_String(infile, spid) )
			ERR(goto done);

		if ( spid->size(spid) != 32 ) {
			fputs("Invalid SPID size: ", stdout);
			spid->print(spid);
			goto done;
		}

		/* Initialize enclave. */
		INIT(NAAAIM, ISOmanager, enclave, ERR(goto done));
		if ( !enclave->load_enclave(enclave, enclave_name, token, \
					    debug) ) {
			fputs("Manager enclave initialization failure.\n", \
			      stderr);
			goto done;
		}

		if ( debug )
			enclave->debug(enclave, true);

		/* Load the identifier verifiers. */
		infile->reset(infile);
		if ( !add_verifiers(enclave, infile, verifier) ) {
			fputs("Unable to load identity verifiers.\n", stderr);
			goto done;
		}

		/* Connect to the enclave. */
		if ( !enclave->connect(enclave, hostname, 11990, \
				       spid->get(spid), id_bufr) ) {
			fputs("Unable to connect to model manager.\n", \
			      stderr);
			goto done;
		}

		goto done;
	}

	if ( canister == NULL ) {
		fputs("No canister name specified.\n", stderr);
		goto done;
	}


	/* Setup the management socket. */
	if ( snprintf(sockname, sizeof(sockname), "%s.%s", SOCKNAME, canister)
	     >= sizeof(sockname) ) {
		fputs("Socket name overflow.\n", stderr);
		goto done;
	}

	if ( (mgmt = NAAAIM_LocalDuct_Init()) == NULL ) {
		fputs("Error creating management socket.\n", stderr);
		goto done;
	}

	if ( !mgmt->init_client(mgmt) ) {
		fputs("Cannot set socket client mode.\n", stderr);
		goto done;
	}

	if ( !mgmt->init_port(mgmt, sockname) ) {
		fputs("Cannot initialize management port.\n", stderr);
		goto done;
	}


	/* Command loop. */
	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	while ( 1 ) {
		memset(inbufr, '\0', sizeof(inbufr));

		fputs("Cboot cmd>", stderr);
		if ( fgets(inbufr, sizeof(inbufr), stdin) == NULL )
			goto done;
		if ( (p = strchr(inbufr, '\n')) != NULL )
			*p = '\0';
		if ( strcmp(inbufr, "quit") == 0 ) {
			goto done;
		}

		if ( !process_command(mgmt, inbufr) )
			goto done;

	}


 done:
	if ( idfile != NULL )
		fclose(idfile);

	WHACK(id_bufr);
	WHACK(cmdbufr);
	WHACK(spid);
	WHACK(mgmt);
	WHACK(idt);
	WHACK(infile);
	WHACK(enclave);

	return retn;
}
