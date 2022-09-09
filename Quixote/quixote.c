/** \file
 *
 * This file implements a utility for running and managing software
 * stacks in a kernel disciplined security domain.  After creating an
 * independent measurement domain the utility forks and then executes
 * the boot of a software 'cartridge' in a subordinate process.
 *
 * The domain is managed through a UNIX domain socket that is created
 * in one of the the following locations:
 *
 * /var/lib/Quixote/mgmt/cartridges
 *
 * /var/lib/Quixote/mgmt/processes
 *
 * Depending on whether or not a runc based cartridge or a simple
 * process was run by the utility.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#define MEASUREMENT_FILE "/sys/kernel/security/tsem/measurement"
#define STATE_FILE	 "/sys/kernel/security/tsem/state"
#define TRAJECTORY_FILE	 "/sys/kernel/security/tsem/trajectory"
#define POINTS_FILE	 "/sys/kernel/security/tsem/points"
#define FORENSICS_FILE	 "/sys/kernel/security/tsem/forensics"
#define SEAL_FILE	 "/sys/kernel/security/tsem/sealed"
#define MAP_FILE	 "/sys/kernel/security/tsem/map"

#define READ_SIDE  0
#define WRITE_SIDE 1

#define _GNU_SOURCE


/* Include files. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <limits.h>
#include <sched.h>
#include <glob.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/un.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "quixote.h"
#include "sancho-cmd.h"

#include "NAAAIM.h"
#include "TTYduct.h"
#include "LocalDuct.h"
#include "SHA256.h"
#include "Base64.h"
#include "RSAkey.h"
#include "TSEMcontrol.h"

#include "SecurityPoint.h"
#include "SecurityEvent.h"


/**
 * Variable used to indicate that debugging is enabled and to provide
 * the filehandle to be used for debugging.
 */
static FILE *Debug = NULL;

/**
 * The control object for the model.
 */
static TSEMcontrol Control = NULL;

/**
 * The process id of the cartridge monitor process.
 */
static pid_t Cartridge_pid;

/**
 * The seal status of the domain.  This variable is set by a
 * seal event for the domain.  Updates which are not in the
 * security state will cause disciplining requests to be generated
 * for the process initiating the event.
 */
static _Bool Sealed = false;

/**
 * The following variable holds booleans which describe signals
 * which were received.
 */
struct {
	_Bool sigint;
	_Bool sigterm;
	_Bool sighup;
	_Bool sigquit;
	_Bool stop;

	_Bool sigchild;
} Signals;

/**
 * The following enumeration type specifies whether or not
 * the measurements are being managed internally or by an SGX enclave.
 */
 enum {
	 show_mode,
	 process_mode,
	 cartridge_mode,
} Mode = cartridge_mode;

/** The numerical definitions for the security model load commands. */
enum {
	model_cmd_comment=1,
	model_cmd_key,
	model_cmd_aggregate,
	model_cmd_state,
	model_cmd_pseudonym,
	model_cmd_seal,
	model_cmd_signature,
	model_cmd_end
} security_load_commands;

/** The structure used to equate strings to numerical load commands. */
struct security_load_definition {
	int command;
	char *syntax;
	_Bool has_arg;
};

/** The list of security load commands. */
struct security_load_definition Security_cmd_list[] = {
	{model_cmd_comment,	"#",		false},
	{model_cmd_key,		"key ",		true},
	{model_cmd_aggregate,	"aggregate ",	true},
	{model_cmd_state,	"state ",	true},
	{model_cmd_pseudonym,	"pseudonym ",	true},
	{model_cmd_seal,	"seal",		false},
	{model_cmd_signature,	"signature ",	true},
	{model_cmd_end,		"end",		false}
};


/**
 * Private function.
 *
 * This function implements the signal handler for the utility.  It
 * sets the signal type in the Signals structure.
 *
 * \param signal	The number of the signal which caused the
 *			handler to execute.
 */

void signal_handler(int signal, siginfo_t *siginfo, void *private)

{
	if ( Debug )
		fprintf(Debug, "%s(%d): signal = %d\n", __func__, getpid(), \
			signal);

	switch ( signal ) {
		case SIGINT:
			Signals.stop = true;
			return;
		case SIGTERM:
			Signals.sigterm = true;
			return;
		case SIGHUP:
			Signals.stop = true;
			return;
		case SIGQUIT:
			Signals.stop = true;
			return;
		case SIGCHLD:
			Signals.sigchild = true;
			return;
	}

	return;
}


/**
 * Private function.
 *
 * This function implements checking for whether or not the cartridge
 * process has terminated.
 *
 * \param cartridge_pid	The pid of the cartridge.
 *
 *
 * \return		A boolean value is used to indicate whether
 *			or not the designed process has exited.  A
 *			false value indicates it has not while a
 *			true value indicates it has.
 */

static _Bool child_exited(const pid_t cartridge)

{
	int status;


	if ( waitpid(cartridge, &status, WNOHANG) != cartridge )
		return false;

	return true;
}


/**
 * Private function.
 *
 * This function sets up the UNIX domain management socket.
 *
 * \param mgmt		The object that will be used to handle management
 *			requests.
 *
 * \param cartridge	A null terminated string containing the name of
 *			the cartridge process to be managed.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not setup of the management socket was
 *			successful.  A true value indicates the setup
 *			was successful while a false value indicates the
 *			setup failed.
 */

static _Bool setup_management(CO(LocalDuct, mgmt), const char *cartridge)

{
	_Bool rc,
	      retn = false;

	mode_t mask;

	String sockpath = NULL;


	/* Initialize socket server mode. */
	if ( !mgmt->init_server(mgmt) ) {
		fputs("Cannot set management server mode.\n", stderr);
		goto done;
	}


	/* Create the appropriate path to the socket location. */
	INIT(HurdLib, String, sockpath, ERR(goto done));

	switch ( Mode ) {
		case show_mode:
			break;

		case process_mode:
			sockpath->add(sockpath, QUIXOTE_PROCESS_MGMT_DIR);
			if ( !sockpath->add_sprintf(sockpath, "/pid-%u", \
						    getpid()) )
				ERR(goto done);
			break;

		case cartridge_mode:
			sockpath->add(sockpath, QUIXOTE_CARTRIDGE_MGMT_DIR);
			sockpath->add(sockpath, "/");
			if ( !sockpath->add(sockpath, cartridge) )
				ERR(goto done);
			break;
	}


	/* Create socket in desginated path. */
	if ( Debug )
		fprintf(Debug, "Opening management socket: %s\n", \
			sockpath->get(sockpath));

	mask = umask(0x2);
	rc = mgmt->init_port(mgmt, sockpath->get(sockpath));
	umask(mask);

	if ( !rc ) {

		fprintf(stderr, "Cannot initialize socket: %s.\n", \
			sockpath->get(sockpath));
		goto done;
	}

	retn = true;


 done:
	WHACK(sockpath);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for returning the current forensics
 * list to the caller.  The protocol used is to send the number of
 * elements in the list followed by each point in the forensics
 * path as an ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to hold the
 *			information which will be transmitted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool send_forensics(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	size_t cnt = 0;

	String es = NULL;

	File ef = NULL;


	/* Hande a sealed model. */
	if ( Sealed ) {
		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);

		retn = true;
		goto done;
	}


	/*
	 * Compute the number of lines in the trajectory.
	 */
	INIT(HurdLib, String, es, ERR(goto done));

	INIT(HurdLib, File, ef, ERR(goto done));
	if ( !ef->open_ro(ef, FORENSICS_FILE) )
		ERR(goto done);

	while ( ef->read_String(ef, es) ) {
		++cnt;
		es->reset(es);
	}

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent forensics size: %zu\n", cnt);


	/* Send each trajectory point. */
	ef->reset(ef);
	if ( !ef->open_ro(ef, FORENSICS_FILE) )
		ERR(goto done);

	while ( cnt-- ) {
		es->reset(es);
		ef->read_String(ef, es);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (void *) es->get(es), es->size(es) + 1);
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
	}

	retn = true;


 done:
	WHACK(es);
	WHACK(ef);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for returning the current security state
 * points to the caller.  The protocol used is to send the number of
 * elements in the map followed by each state in the model as a hexadecimal
 * ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to hold the
 *			information which will be transmitted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool send_points(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	size_t cnt = 0;

	String es = NULL;

	File ef = NULL;


	/* Hande a sealed model. */
	if ( Sealed ) {
		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);

		retn = true;
		goto done;
	}


	/*
	 * Compute the number of lines in the trajectory.
	 */
	INIT(HurdLib, String, es, ERR(goto done));

	INIT(HurdLib, File, ef, ERR(goto done));
	if ( !ef->open_ro(ef, POINTS_FILE) )
		ERR(goto done);

	while ( ef->read_String(ef, es) ) {
		++cnt;
		es->reset(es);
	}

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent points size: %zu\n", cnt);


	/* Send each trajectory point. */
	ef->reset(ef);
	if ( !ef->open_ro(ef, POINTS_FILE) )
		ERR(goto done);

	while ( cnt-- ) {
		es->reset(es);
		ef->read_String(ef, es);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (void *) es->get(es), es->size(es) + 1);
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
	}

	retn = true;


 done:
	WHACK(es);
	WHACK(ef);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for returning the current security event
 * trajectory list to the caller.  The protocol used is to send the number
 * of elements in the list followed by each point as an ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to hold the
 *			information which will be transmitted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
v */

static _Bool send_trajectory(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	size_t cnt = 0;

	String es = NULL;

	File ef = NULL;


	/* Hande a sealed model. */
	if ( Sealed ) {
		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);

		retn = true;
		goto done;
	}


	/*
	 * Compute the number of lines in the trajectory.
	 */
	INIT(HurdLib, String, es, ERR(goto done));

	INIT(HurdLib, File, ef, ERR(goto done));
	if ( !ef->open_ro(ef, TRAJECTORY_FILE) )
		ERR(goto done);

	while ( ef->read_String(ef, es) ) {
		++cnt;
		es->reset(es);
	}

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent trajectory size: %zu\n", cnt);


	/* Send each trajectory point. */
	ef->reset(ef);
	if ( !ef->open_ro(ef, TRAJECTORY_FILE) )
		ERR(goto done);

	while ( cnt-- ) {
		es->reset(es);
		ef->read_String(ef, es);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (void *) es->get(es), es->size(es) + 1);
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
	}

	retn = true;


 done:
	WHACK(es);
	WHACK(ef);

	return retn;
}


/**
 * Private function.
 *
 * This function writes the directive needed to seal the security
 * domain to the 'sealed' pseudo-file.
 *
 * \param bufr		The object that will be used to hold the value
 *			to be written to the file.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the write to the seal file has been
 *			successfully executed.  A false value indicates
 *			failure while a true value indicates success.
 */

static _Bool seal(CO(Buffer, bufr))

{
	_Bool retn = false;

	File sf = NULL;

	static const unsigned char one[] = "1\n";


	INIT(HurdLib, File, sf, ERR(goto done));
	if ( !sf->open_wo(sf, SEAL_FILE) )
		ERR(goto done);

	bufr->reset(bufr);
	bufr->add(bufr, one, sizeof(one) - 1);

	if ( !sf->write_Buffer(sf, bufr) )
		ERR(goto done);

	retn   = true;
	Sealed = true;


 done:
	WHACK(sf);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for sealing a security domain.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to seal the
 *			buffer and return the status information.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool seal_domain(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	static const unsigned char ok[] = "OK";


	/* Seal the domain. */
	if ( !Sealed ) {
		cmdbufr->reset(cmdbufr);
		if ( !seal(cmdbufr) )
			ERR(goto done);
	}

	/* Send response to caller. */
	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, ok, sizeof(ok));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for returning the current security state
 * event map to the caller.  This map can be used to define the desired
 * security state by feeding this map into the quixote utility with the
 * -m command-line switch.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to hold the
 *			information which will be transmitted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates an error was encountered while sending
 *			the event list while a true value indicates the
 *			event list was succesfully sent.
 */

static _Bool send_map(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	uint8_t aggregate[NAAAIM_IDSIZE];


	/* Send the domain aggregate. */
	memset(aggregate, '\0', sizeof(aggregate));
	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, aggregate, sizeof(aggregate));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);


	/* Send each point in the model. */
	retn = send_points(mgmt, cmdbufr);


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the processing of a management command from
 * the quixote-console utility.
 *
 * \param mgmt		The socket object used to communicate with
 *			the security domain management instance.
 *
 * \param cmdbufr	The object containing the command to be
 *			processed.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool process_command(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	char *cmd;

	int *cp;

	uint8_t sealed[NAAAIM_IDSIZE] = {0};

	String estr = NULL;

	File efile = NULL;


	/* Validate management command. */
	if ( cmdbufr->size(cmdbufr) != sizeof(int) )
		ERR(goto done);

	cp = (int *) cmdbufr->get(cmdbufr);
	if ( (*cp < 1) || (*cp > sancho_cmds_max) )
		ERR(goto done);
	cmd = Sancho_cmd_list[*cp - 1].syntax;

	if ( Debug )
		fprintf(Debug, "%u: Processing management cmd: %s\n", \
			getpid(), cmd);


	/* Process management command. */
	INIT(HurdLib, String, estr, ERR(goto done));
	INIT(HurdLib, File, efile, ERR(goto done));

	switch ( *cp ) {
		case show_measurement:
			cmdbufr->reset(cmdbufr);

			if ( Sealed ) {
				if ( !cmdbufr->add(cmdbufr, sealed, \
						   sizeof(sealed)) )
					ERR(goto done);
				if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
					ERR(goto done);
				retn = true;
				goto done;
			}

			if ( !efile->open_ro(efile, MEASUREMENT_FILE) )
				ERR(goto done);
			if ( !efile->read_String(efile, estr) )
				ERR(goto done);
			if ( !cmdbufr->add_hexstring(cmdbufr, \
						     estr->get(estr)) )
				ERR(goto done);
			if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
				ERR(goto done);
			retn = true;
			break;

		case show_state:
			cmdbufr->reset(cmdbufr);

			if ( Sealed ) {
				if ( Debug )
					fputs("Processing sealed.\n", Debug);
				if ( !cmdbufr->add(cmdbufr, sealed, \
						   sizeof(sealed)) )
					ERR(goto done);
				if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
					ERR(goto done);
				retn = true;
				goto done;
			}

			if ( !efile->open_ro(efile, STATE_FILE) )
				ERR(goto done);
			if ( !efile->read_String(efile, estr) )
				ERR(goto done);
			if ( !cmdbufr->add_hexstring(cmdbufr, \
						     estr->get(estr)) )
				ERR(goto done);
			if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
				ERR(goto done);
			retn = true;
			break;

		case show_trajectory:
			retn = send_trajectory(mgmt, cmdbufr);
			break;

		case show_forensics:
			retn = send_forensics(mgmt, cmdbufr);
			break;

		case show_points:
			retn = send_points(mgmt, cmdbufr);
			break;

		case seal_event:
			retn = seal_domain(mgmt, cmdbufr);
			break;

		case show_map:
			retn = send_map(mgmt, cmdbufr);
			break;
	}


 done:
	WHACK(estr);
	WHACK(efile);

	return retn;
}


/**
 * Private function.
 *
 * This function carries out the addition of a state value to the
 * current security model.
 *
 * \param bufr		A pointer to the character buffer containing
 *			the hexadecimally encoded state value.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not addition of the state value succeeded.  A
 *			false value indicates the addition of the
 *			state failed while a true value indicates
 *			the state injection had succeeded.
 */

static _Bool add_state(CO(char *, inbufr))

{
	_Bool retn = false;

	Buffer bufr = NULL;

	File sf = NULL;


	/* Sanity check buffer. */
	if ( Debug )
		fprintf(Debug, "adding state: %s\n", inbufr);
	if ( strlen(inbufr) != (NAAAIM_IDSIZE * 2) )
		ERR(goto done);


	/* Write the hexadecimal point value to the pseudo-file. */
	INIT(HurdLib, File, sf, ERR(goto done));
	if ( !sf->open_wo(sf, MAP_FILE) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	bufr->add(bufr, (void *) inbufr, NAAAIM_IDSIZE * 2);
	bufr->add(bufr, (void *) "\n", 1);

	if ( !sf->write_Buffer(sf, bufr) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(sf);

	return retn;
}


/**
 * Internal private function.
 *
 * This function encapsulates the addition of a line from a model file
 * to the Buffer object that will be hashed to generate the signature
 * for the model.
 *
 * \param bufr		The state information for the model object.
 *
 * \param line		The object containing the line to add to the
 *			file.
 *
 * \return	A boolean value is used to indicate the status of the
 *		addition of the line.  A false value indicates the
 *		addition failed while a true value indicates the
 *		contents of the line had been added to the buffer.
 */

static _Bool _add_entry(CO(Buffer, bufr), CO(String, line))

{
	_Bool retn = false;


	if ( bufr == NULL )
		return true;

	if ( !bufr->add(bufr, (void *) line->get(line), line->size(line) + 1) )
		ERR(goto done);

	retn = true;


 done:
	return retn;

}


/**
 * Internal private function.
 *
 * This function carries out the validation of a signed security model.
 *
 * \param key		The object containing
 *			model over which the signature is generated.
 *
 * \param sigdata	The object containing the contents of the
 *			security model in a form suitable for computing
 *			the hash signature.
 *
 * \param sig		The Base64 encoded signature.
 *
 * \param valid		A pointer to the boolean value that will be
 *			loaded with the result of the signature
 *			validation.
 *
 * \return	A boolean value is used to indicate the status of the
 *		computation of the signature.  A false value indicates
 *		an error was encountered while computing the signature.
 *		A true value indicates the signature was calculated
 *		and the variable pointed to by the status variable
 *		contains the status of the signature.
 */

static _Bool _verify_model(CO(Buffer, key), CO(Buffer, sigdata), char * sig, \
			   _Bool *valid)

{
	_Bool retn = false;

	Buffer signature = NULL;

	String str = NULL;

	Base64 base64 = NULL;

	RSAkey rsakey = NULL;


	/* Load the key that was provided. */
	INIT(HurdLib, String, str, ERR(goto done));
	if ( !str->add(str, (char *) key->get(key)) )
		ERR(goto done);

	INIT(NAAAIM, Base64, base64, ERR(goto done));
	key->reset(key);
	if ( !base64->decode(base64, str, key) )
		ERR(goto done);

	INIT(NAAAIM, RSAkey, rsakey, ERR(goto done));
	if ( !rsakey->load_public(rsakey, key) )
		ERR(goto done);


	/* Decode and verify the signature. */
	str->reset(str);
	if ( !str->add(str, sig) )
		ERR(goto done);

	INIT(HurdLib, Buffer, signature, ERR(goto done));
	if ( !base64->decode(base64, str, signature) )
		ERR(goto done);

	if ( !rsakey->verify(rsakey, signature, sigdata, valid) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(signature);
	WHACK(str);
	WHACK(base64);
	WHACK(rsakey);

	return retn;

}


/**
 * Internal public functioin.
 *
 * This method implements the initialization of an in-kernel security
 * model.
 *
 * \param entry		An object that contains the description of the
 *			entry that is to be entered into the security
 *			model.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the entry was successfully loaded into the kernel.
 *		A false value indicates a failure occurred while
 *		a true value indicates the security model was
 *		successfully updated.
 */

static _Bool load(CO(String, entry))

{
	_Bool retn	= false,
	      sig_valid = false;

	char *arg = NULL;

	struct security_load_definition *dp;

	Buffer bufr = NULL;

	static _Bool loading = false;

	static Buffer key     = NULL,
		      sigdata = NULL;


	/* Locate the load command being requested. */
	for (dp= Security_cmd_list; dp->command <= model_cmd_end; ++dp) {
		if ( strncmp(dp->syntax, entry->get(entry), \
			     strlen(dp->syntax)) == 0 )
			break;
	}
	if ( dp->command > model_cmd_end )
		ERR(goto done);

	if ( (dp->command != model_cmd_signature) && !loading )
		loading = true;


	/* Get the start of command argument. */
	if ( dp->has_arg ) {
		arg = entry->get(entry) + strlen(dp->syntax);
		if ( *arg == '\0' )
			ERR(goto done);
	}


	/* Implement the command. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	switch ( dp->command ) {
		case model_cmd_comment:
			if ( !_add_entry(sigdata, entry) )
				ERR(goto done);
			break;

		case model_cmd_key:
			INIT(HurdLib, Buffer, sigdata, ERR(goto done));

			if ( !_add_entry(sigdata, entry) )
				ERR(goto done);

			if ( key != NULL )
				ERR(goto done);
			INIT(HurdLib, Buffer, key, ERR(goto done));
			if ( !key->add(key, (void *) arg, strlen(arg) + 1) )
				ERR(goto done);
			break;

		case model_cmd_aggregate:
			if ( !_add_entry(sigdata, entry) )
				ERR(goto done);
			break;

		case model_cmd_state:
			if ( !_add_entry(sigdata, entry) )
				ERR(goto done);

			if ( !bufr->add_hexstring(bufr, arg) )
				ERR(goto done);
			if ( !add_state(arg) )
				ERR(goto done);
			break;

		case model_cmd_pseudonym:
			if ( !_add_entry(sigdata, entry) )
				ERR(goto done);
			break;

		case model_cmd_seal:
			if ( !_add_entry(sigdata, entry) )
				ERR(goto done);

			seal(bufr);
			break;

		case model_cmd_signature:
			if ( (sigdata == NULL) || (key == NULL) )
				ERR(goto done);

			retn = _verify_model(key, sigdata, arg, &sig_valid);
			WHACK(key);
			WHACK(sigdata);

			if ( !retn )
				ERR(goto done);
			if ( !sig_valid ) {
				retn = false;
				ERR(goto done);
			}
			break;

		case model_cmd_end:
			if ( !_add_entry(sigdata, entry) )
				ERR(goto done);

			loading = false;
			break;
	}

	retn = true;


 done:
	WHACK(bufr);

	return retn;
}


/**
 * Private function.
 *
 * This function implements the initialization of a security model from
 * a file.
 *
 * \param model		The object that will be used to read the security
 *			model file.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the model was loaded.  A false value
 *			indicates the load of the model failed while
 *			a true value indicates the model was successfully
 *			loaded.
 */

static _Bool load_model(CO(File, model))

{
	_Bool retn = false;

	String str = NULL;


	/* Open the security map file. */
	INIT(HurdLib, String, str, ERR(goto done));


	/* Loop over the contents of the map.. */
	while ( model->read_String(model, str) ) {
		if ( Debug )
			fprintf(Debug, "Model entry: %s\n", str->get(str));

		if ( !load(str) )
			ERR(goto done);
		str->reset(str);
	}

	retn = true;


 done:
	WHACK(str);

	return retn;
}


/**
 * Private function.
 *
 * This function creates an independent security event domain that
 * is modeled by an in kernel Trusted Modeling Agent implementation.
 *
 *
 * \param enforce	A flag variable used to indicate whether or not
 *			the security model should be placed in
 *			enforcement mode.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the creation of the security event domain
 *			was successful.  A false value indicates setup of
 *			the domain was unsuccessful while a true
 *			value indicates the domain was setup and is
 *			ready to be modeled.
 */

static _Bool setup_namespace(_Bool enforce)

{
	_Bool retn = false;


	/* Create an independent security event model. */
	if ( !Control->internal(Control) )
		ERR(goto done);

	if ( enforce ) {
		if ( !Control->enforce(Control) )
			ERR(goto done);
	}


	/* Drop the ability to modify the security event model. */
	if ( cap_drop_bound(CAP_TRUST) != 0 )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements Quixote show mode.  This mode displays the
 * set of software security cartridges that are currently deployed
 * on the host.
 *
 * \param root	A pointer to the buffer containing the magazine root
 *		directory.
 *
 * \return	No return value is defined.
 */

static void show_magazine(CO(char *, root))

{
	char *p;

	int retn = 1;

	uint16_t lp;

	glob_t cartridges;

	String str = NULL;


	/* Generate the list of cartridges. */
	INIT(HurdLib, String, str, ERR(goto done));
	str->add(str, root);
	if ( !str->add(str, "/*") )
		ERR(goto done);

	if ( glob(str->get(str), 0, NULL, &cartridges) != 0 ) {
		fprintf(stderr, "Failed read of cartridge directory: %s\n", \
			root);
		goto done;
	}
	if ( cartridges.gl_pathc == 0 ) {
		fputs("No cartridges found:\n", stderr);
		goto done;
	}


	/* Iterate through and print the cartridges found .*/
	fprintf(stdout, "%s:\n", root);
	for (lp= 0; lp < cartridges.gl_pathc; ++lp) {
		str->reset(str);
		if ( !str->add(str, cartridges.gl_pathv[lp]) ) {
			fputs("Error processing cartridge list\n", stderr);
			goto done;
		}

		p = str->get(str);
		if ( (p = strrchr(str->get(str), '/')) == NULL )
			p = str->get(str);
		else
			++p;
		fprintf(stdout, "\t%s\n", p);
	}

	retn = 0;


 done:
	globfree(&cartridges);
	WHACK(str);

	exit(retn);
}


/**
 * Private function.
 *
 * This function is responsible for launching a software cartridge
 * in an independent measurement domain.  A pipe is established
 * between the parent process and the child that is used to return
 * the namespace specific events for injection into the security
 * co-processor.
 *
 * \param root		A pointer to the buffer containing the root
 *			directory to be used to display the cartridges.
 *
 * \param map		A pointer to the file descriptor that contains
 *			security state directives to be loaded into
 *			the domain.  This value will be null if a
 *			state map has not been specified.
 *
 * \param mgmt_read	A file descriptor to the read end of the pipe
 *			from which management commands will be received.
 *
 * \param mgmt_write	The file descriptor to the write end of the pipe
 *			over which the results of the management command
 *			will be sent.
 *
 * \param enforce	A flag used to indicate whether or not the
 *			security domain should be placed in enforcement
 *			mode.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the launch.  A false value indicates an error was
 *		encountered while a true value indicates the cartridge
 *		was successfully launched.
 */

static _Bool fire_cartridge(CO(char *, cartridge), CO(File, map), \
			    int *endpoint, _Bool enforce)

{
	_Bool retn = false;

	char *bundle = NULL;

	String cartridge_dir = NULL;


	/* Create the name of the bundle directory if in cartridge mode . */
	if ( Mode == cartridge_mode ) {
		INIT(HurdLib, String, cartridge_dir, ERR(goto done));
		cartridge_dir->add(cartridge_dir, QUIXOTE_MAGAZINE);
		cartridge_dir->add(cartridge_dir, "/");
		if ( !cartridge_dir->add(cartridge_dir, cartridge) )
			ERR(goto done);
		bundle = cartridge_dir->get(cartridge_dir);
	}


	/* Create a subordinate cartridge process. */
	if ( !setup_namespace(enforce) )
		exit(1);

	if ( Debug )
		fprintf(Debug, "Monitor process: %d\n", getpid());


	/* Load the state map if one has been specified. */
	if ( map != NULL ) {
		if ( !load_model(map) )
			ERR(goto done);
	}


	/* Fork again to run the cartridge. */
	Cartridge_pid = fork();
	if ( Cartridge_pid == -1 )
		exit(1);

	/* Child process - run the cartridge. */
	if ( Cartridge_pid == 0 ) {
		if ( Mode == cartridge_mode ) {
			execlp("runc", "runc", "run", "-b", bundle, \
			       cartridge, NULL);
			fputs("Cartridge execution failed.\n", stderr);
			exit(1);
		}

		if ( Mode == process_mode ) {
			if ( geteuid() != getuid() ) {
				if ( Debug )
					fprintf(Debug, "Changing to real " \
						"id: \%u\n",  getuid());
				if ( setuid(getuid()) != 0 ) {
					fputs("Cannot change uid.\n", stderr);
					exit(1);
				}
			}

			if ( Debug )
				fputs("Executing cartridge process.\n", Debug);
			execlp("bash", "bash", "-i", NULL);
			fputs("Cartridge process execution failed.\n", stderr);
			exit(1);
		}
	}


	/* Parent process - return and monitor child. */
	retn = true;


 done:
	WHACK(cartridge_dir);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for issueing the runc command needed
 * to terminate a software cartridge.  The function waits until the
 * process spawned to execute the runc process terminates.
 *
 * \param name		A pointer to a character buffer containing the
 *			name of the software cartridge.
 *
 * \param wait		A boolean flag used to indicate whether or
 *			not the runc kill process should be waited for.
 *
 * \return	No return value is defined.
 */

static void kill_cartridge(const char *cartridge, const _Bool wait)

{
	int status;

	static pid_t kill_process = 0;


	/* Signal the monitor process to shutdown the cartridge process. */
	if ( Mode == process_mode ) {
		if ( Debug )
			fprintf(Debug, "%u sending SIGHUP to %u.\n", \
				getpid(), Cartridge_pid);
		kill(Cartridge_pid, SIGTERM);
		return;
	}


	/* Check to see if runc kill has finished. */
	if ( kill_process ) {
		waitpid(kill_process, &status, WNOHANG);
		if ( !WIFEXITED(status) )
			return;

		if ( Debug )
			fprintf(Debug, "Cartridge kill status: %d\n", \
				WEXITSTATUS(status));
		if ( WEXITSTATUS(status) == 0 ) {
			kill_process = 0;
			return;
		}
	}


	/* Fork a process to use runc to send the termination signal. */
	kill_process = fork();
	if ( kill_process == -1 )
		return;

	/* Child process - execute runc in kill mode. */
	if ( kill_process == 0 ) {
		if ( Debug )
			fputs("Killing runc cartridge.\n", Debug);
		execlp("runc", "runc", "kill", cartridge, "SIGKILL", \
		       NULL);
		exit(1);
	}

	/* Parent process - wait for the kill process to complete. */
	if ( wait )
		waitpid(kill_process, &status, 0);

	return;
}



/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool enforce	= false,
	      connected = false;

	char *debug	= NULL,
	     *map	= NULL,
	     *cartridge	= NULL;

	int opt,
	    fd	 = 0,
	    retn = 1;

	struct pollfd poll_data[1];

	struct sigaction signal_action;

	Buffer cmdbufr = NULL;

	LocalDuct mgmt = NULL;

	File state  = NULL,
	     infile = NULL;


	while ( (opt = getopt(argc, argv, "CPSec:d:m:")) != EOF )
		switch ( opt ) {
			case 'C':
				Mode = cartridge_mode;
				break;
			case 'P':
				Mode = process_mode;
				break;
			case 'S':
				Mode = show_mode;
				break;
			case 'e':
				enforce = true;
				break;

			case 'c':
				cartridge = optarg;
				break;
			case 'd':
				debug = optarg;
				break;
			case 'm':
				map = optarg;
				break;
		}


	/* Execute cartridge display mode. */
	if ( Mode == show_mode )
		show_magazine(QUIXOTE_MAGAZINE);

	if ( (Mode == cartridge_mode) && (cartridge == NULL) ) {
		fputs("No software cartridge specified.\n", stderr);
		goto done;
	}


	/* Handle a debug invocation. */
	if ( debug ) {
		if ( (Debug = fopen(debug, "w+")) == NULL ) {
			fputs("Cannot open debug file.\n", stderr);
			goto done;
		}
		setlinebuf(Debug);
	}


	/* Setup signal handlers. */
	if ( sigemptyset(&signal_action.sa_mask) == -1 )
		ERR(goto done);

	signal_action.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
	signal_action.sa_sigaction = signal_handler;
	if ( sigaction(SIGINT, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGTERM, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGHUP, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGQUIT, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGSEGV, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGFPE, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGILL, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGBUS, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGTRAP, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGCHLD, &signal_action, NULL) == -1 )
		goto done;


	/* Load and seal a behavior map if specified. */
	if ( map != NULL ) {
		INIT(HurdLib, File, state, ERR(goto done));

		if ( !state->open_ro(state, map) )
			ERR(goto done);
		if ( Debug )
			fprintf(Debug, "Opened state map: %s\n", map);
	}


	/* Initialize the security model controller. */
	INIT(NAAAIM, TSEMcontrol, Control, ERR(goto done));


	/* Setup the management socket. */
	INIT(NAAAIM, LocalDuct, mgmt, ERR(goto done));
	if ( !setup_management(mgmt, cartridge) )
		ERR(goto done);


	/* Launch the software cartridge. */
	if ( Debug )
		fprintf(Debug, "Primary process: %d\n", getpid());

	if ( !fire_cartridge(cartridge, state, &fd, enforce) )
		ERR(goto done);

	if ( !mgmt->get_socket(mgmt, &poll_data[0].fd) ) {
		fputs("Error setting up polling data.\n", stderr);
		goto done;
	}
	poll_data[0].events = POLLIN;


	/* Dispatch loop. */
	if ( Debug ) {
		fprintf(Debug, "%d: Calling event loop\n", getpid());
		fprintf(Debug, "descriptor 1: %d,\n", poll_data[0].fd);
	}

	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	opt = 0;
	while ( 1 ) {
		if ( Debug )
			fprintf(Debug, "\n%d: Poll cycle: %d\n", getpid(), \
				++opt);

		retn = poll(poll_data, 1, -1);
		if ( retn < 0 ) {
			if ( Signals.stop || Signals.sigterm ) {
				if ( Debug )
					fputs("Quixote terminated.\n", Debug);
				kill_cartridge(cartridge, true);
				goto done;
			}
			if ( Signals.sigchild ) {
				if ( !child_exited(Cartridge_pid) )
					continue;
				fputs("Cartridge process terminated.\n", \
				      stdout);
				goto done;
			}
		}

		if ( Debug )
			fprintf(Debug, "Events: %d, Mgmt poll=%0x\n", retn, \
				poll_data[0].revents);

		if ( poll_data[0].revents & POLLIN ) {
			if ( !connected ) {
				if ( Debug )
					fputs("Have socket connection.\n", \
					      Debug);

				if ( !mgmt->accept_connection(mgmt) )
					ERR(goto done);
				if ( !mgmt->get_fd(mgmt, &poll_data[0].fd) )
					ERR(goto done);
				connected = true;
				continue;
			}
			if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
				continue;
			if ( mgmt->eof(mgmt) ) {
				if ( Debug )
					fputs("Terminating management.\n", \
					      Debug);
				mgmt->reset(mgmt);
				if ( !mgmt->get_socket(mgmt, \
						       &poll_data[0].fd) )
					ERR(goto done);
				connected = false;
				continue;
			}

			if ( !process_command(mgmt, cmdbufr) )
				ERR(goto done);
			cmdbufr->reset(cmdbufr);
		}
	}


 done:
	WHACK(Control);
	WHACK(cmdbufr);
	WHACK(mgmt);
	WHACK(state);
	WHACK(infile);

	if ( fd > 0 )
		close(fd);

	return retn;
}
