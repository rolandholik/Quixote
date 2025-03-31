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

#define MODEL_DIR	 	"/sys/kernel/security/tsem/internal_tma/model0/"

#define MEASUREMENT		MODEL_DIR"measurement"
#define STATE			MODEL_DIR"state"
#define TRAJECTORY		MODEL_DIR"trajectory"
#define TRAJECTORY_COUNTS	MODEL_DIR"trajectory_counts"
#define TRAJECTORY_COEFFICIENTS MODEL_DIR"trajectory_coefficients"
#define FORENSICS	 	MODEL_DIR"forensics"
#define FORENSICS_COUNTS	MODEL_DIR"forensics_counts"
#define FORENSICS_COEFFICIENTS	MODEL_DIR"forensics_coefficients"

#define AGGREGATE	        "/sys/kernel/security/tsem/aggregate"

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
#include <Process.h>

#include "quixote.h"
#include "sancho-cmd.h"

#include "NAAAIM.h"
#include "TTYduct.h"
#include "LocalDuct.h"
#include "SHA256.h"
#include "Base64.h"
#include "RSAkey.h"
#include "TSEMcontrol.h"
#include "TSEMevent.h"
#include "TSEMworkload.h"

#include "SecurityPoint.h"
#include "SecurityEvent.h"


/**
 * Variable used to indicate that debugging is enabled and to provide
 * the filehandle to be used for debugging.
 */
static FILE *Debug = NULL;

/**
 * The object representing the workload under management.
 */
static TSEMworkload Workload = NULL;

/**
 * The control object for the model.
 */
static TSEMcontrol Control = NULL;

/**
 * The seal status of the domain.  This variable is set by a
 * seal event for the domain.  Updates which are not in the
 * security state will cause disciplining requests to be generated
 * for the process initiating the event.
 */
static _Bool Sealed = false;

/**
 * This variable is used to indicate whether or not the process
 * monitoring the modeled process stack should wait after the
 * child exits so that a complete security map of the process,
 * including its exit can be obtained.
 */
static _Bool Pause = false;

/**
 * This variable is used to indicate whether a trajectory map or
 * a security model is to be output.
 */
static _Bool Trajectory = false;

/**
 * The name of the hash function to be used for the namespace.
 */
static char *Digest = NULL;

/**
 * A string defining the size of the atomic magazine to be
 * allocated for a namespace.
 */
static unsigned long Magazine_Size = 0;

/**
 * The alternate TSEM model that is to be used.
 */
static char *TSEM_model = NULL;

/**
 * The following enumeration type specifies whether or not
 * the measurements are being managed internally or by an SGX enclave.
 */
 enum {
	 show_mode,
	 process_mode,
	 container_mode,
	 execute_mode
} Mode = container_mode;

/** The numerical definitions for the security model load commands. */
enum {
	model_cmd_comment=1,
	model_cmd_key,
	model_cmd_base,
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
	{model_cmd_base,	"base ",	true},
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
		case execute_mode:
			sockpath->add_sprintf(sockpath, "%s/pid-", \
					      QUIXOTE_PROCESS_MGMT_DIR);
			if ( cartridge != NULL ) {
				if ( !sockpath->add(sockpath, cartridge) )
					ERR(goto done);
			} else {
				if ( !sockpath->add_sprintf(sockpath, "%u", \
							    getpid()) )
					ERR(goto done);
			}
			break;

		case container_mode:
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
 * Internal private function.
 *
 * This function is responsible for sending a line of command output to
 * the console.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param bufr		The object containing the command output that
 *			is to be sent.
 *
 * \param retn		A pointer to the boolean variable that will
 *			be loaded with the error return status that
 *			will be returned to the caller.
 *
 * \return		A boolean value is used to indicate whether or
 *			not output should be terminated.  A false value
 *			indicates that this invocation should be the
 *			last output that is to be set.  A true return
 *			value indicates that the next cycle of output
 *			should be attempted.
 */

static _Bool _send_output(CO(LocalDuct, mgmt), CO(Buffer, bufr), _Bool *retn)

{
	*retn = false;

	if ( !mgmt->send_Buffer(mgmt, bufr) )
		ERR(return false);

	if ( mgmt->eof(mgmt) ) {
		*retn = true;
		if ( Debug )
			fprintf(Debug, "%d: Received end of connection.\n", \
				getpid());
		return false;
	}

	return true;
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

	TSEMevent event = NULL;


	/*
	 * Compute the number of lines in the trajectory.
	 */
	INIT(HurdLib, String, es, ERR(goto done));
	INIT(NAAAIM, TSEMevent, event, ERR(goto done));

	INIT(HurdLib, File, ef, ERR(goto done));
	if ( !ef->open_ro(ef, FORENSICS) )
		ERR(goto done);

	while ( ef->read_String(ef, es) ) {
		++cnt;
		es->reset(es);
	}

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !_send_output(mgmt, cmdbufr, &retn) )
		goto done;
	if ( Debug )
		fprintf(Debug, "Sent forensics size: %zu\n", cnt);


	/* Send each trajectory point. */
	ef->reset(ef);
	if ( !ef->open_ro(ef, FORENSICS) )
		ERR(goto done);

	while ( cnt-- ) {
		es->reset(es);
		ef->read_String(ef, es);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (void *) es->get(es), es->size(es) + 1);
		if ( !_send_output(mgmt, cmdbufr, &retn) )
			goto done;
	}

	retn = true;


 done:
	WHACK(es);
	WHACK(ef);
	WHACK(event);

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
 * \param type		A pointer to a null-terminated buffer containing
 *			the name of the file.
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

static _Bool send_coefficients(CO(LocalDuct, mgmt), CO(char *, type), \
			       CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	size_t cnt = 0;

	String es = NULL;

	File ef = NULL;


	/*
	 * Compute the number of lines in the trajectory.
	 */
	INIT(HurdLib, String, es, ERR(goto done));

	INIT(HurdLib, File, ef, ERR(goto done));
	if ( !ef->open_ro(ef, type) )
		ERR(goto done);

	while ( ef->read_String(ef, es) ) {
		++cnt;
		es->reset(es);
	}

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !_send_output(mgmt, cmdbufr, &retn) )
		goto done;
	if ( Debug )
		fprintf(Debug, "%d: Sent points size: %zu\n", getpid(), cnt);


	/* Send each trajectory point. */
	ef->reset(ef);
	if ( !ef->open_ro(ef, type) )
		ERR(goto done);

	while ( cnt-- ) {
		es->reset(es);
		ef->read_String(ef, es);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (void *) es->get(es), es->size(es) + 1);
		if ( !_send_output(mgmt, cmdbufr, &retn) )
			goto done;
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
 */

static _Bool send_trajectory(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	size_t cnt = 0;

	String es = NULL;

	File ef = NULL;

	TSEMevent event = NULL;


	/*
	 * Compute the number of lines in the trajectory.
	 */
	INIT(HurdLib, String, es, ERR(goto done));
	INIT(NAAAIM, TSEMevent, event, ERR(goto done));

	INIT(HurdLib, File, ef, ERR(goto done));
	if ( !ef->open_ro(ef, TRAJECTORY) )
		ERR(goto done);

	while ( ef->read_String(ef, es) ) {
		++cnt;
		es->reset(es);
	}

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !_send_output(mgmt, cmdbufr, &retn) )
		goto done;
	if ( Debug )
		fprintf(Debug, "Sent trajectory size: %zu\n", cnt);


	/* Send each trajectory point. */
	ef->reset(ef);
	if ( !ef->open_ro(ef, TRAJECTORY) )
		ERR(goto done);

	while ( cnt-- ) {
		es->reset(es);
		ef->read_String(ef, es);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (void *) es->get(es), es->size(es) + 1);
		if ( !_send_output(mgmt, cmdbufr, &retn) )
			goto done;
		event->reset(event);
	}

	retn = true;


 done:
	WHACK(es);
	WHACK(ef);
	WHACK(event);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for returning a list of security event
 * counts to the management console.  This is a generic function that
 * returns either valid or forensics counts.  The protocol used is to
 * send the number of elements in the list followed by each count as
 * an ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param type		A pointer to the character buffer containing
 *			the name of the file containing the counts
 *			to be sent.
 *
 * \param cmdbufr	The object which will be used to hold the
 *			information that will be transmitted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
v */

static _Bool send_counts(CO(LocalDuct, mgmt), CO(char *, type), \
			 CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	size_t cnt = 0;

	String es = NULL;

	File ef = NULL;


	/*
	 * Compute the number of lines in the trajectory.
	 */
	INIT(HurdLib, String, es, ERR(goto done));

	INIT(HurdLib, File, ef, ERR(goto done));
	if ( !ef->open_ro(ef, type) )
		ERR(goto done);

	while ( ef->read_String(ef, es) ) {
		++cnt;
		es->reset(es);
	}

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !_send_output(mgmt, cmdbufr, &retn) )
		goto done;
	if ( Debug )
		fprintf(Debug, "Sent count size: %zu\n", cnt);


	/* Send each trajectory point. */
	ef->reset(ef);
	if ( !ef->open_ro(ef, type) )
		ERR(goto done);

	while ( cnt-- ) {
		es->reset(es);
		ef->read_String(ef, es);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (void *) es->get(es), es->size(es) + 1);
		if ( !_send_output(mgmt, cmdbufr, &retn) )
			goto done;
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
		if ( !Control->seal(Control) )
			ERR(goto done);
	}

	/* Send response to caller. */
	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, ok, sizeof(ok));
	if ( !_send_output(mgmt, cmdbufr, &retn) )
		goto done;

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

	String as = NULL;

	File af = NULL;


	/* Read and send the platform aggregate value. */
	INIT(HurdLib, String, as, ERR(goto done));

	INIT(HurdLib, File, af, ERR(goto done));
	if ( !af->open_ro(af, AGGREGATE) )
		ERR(goto done);
	if ( !af->read_String(af, as) )
		ERR(goto done);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add_hexstring(cmdbufr, (void *) as->get(as));
	if ( !_send_output(mgmt, cmdbufr, &retn) )
		goto done;

	/* Send each point in the model. */
	retn = send_coefficients(mgmt, TRAJECTORY_COEFFICIENTS, cmdbufr);


 done:
	WHACK(as);
	WHACK(af);

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

			if ( !efile->open_ro(efile, MEASUREMENT) )
				ERR(goto done);
			if ( !efile->read_String(efile, estr) )
				ERR(goto done);
			if ( !cmdbufr->add_hexstring(cmdbufr, \
						     estr->get(estr)) )
				ERR(goto done);
			if ( !_send_output(mgmt, cmdbufr, &retn) )
				goto done;
			retn = true;
			break;

		case show_state:
			cmdbufr->reset(cmdbufr);

			if ( !efile->open_ro(efile, STATE) )
				ERR(goto done);
			if ( !efile->read_String(efile, estr) )
				ERR(goto done);
			if ( !cmdbufr->add_hexstring(cmdbufr, \
						     estr->get(estr)) )
				ERR(goto done);
			if ( !_send_output(mgmt, cmdbufr, &retn) )
				goto done;
			retn = true;
			break;

		case show_trajectory:
			retn = send_trajectory(mgmt, cmdbufr);
			break;

		case show_counts:
			retn = send_counts(mgmt, TRAJECTORY_COUNTS, cmdbufr);
			break;

		case show_coefficients:
			retn = send_coefficients(mgmt,			  \
						 TRAJECTORY_COEFFICIENTS, \
						 cmdbufr);
			break;

		case show_forensics:
			retn = send_forensics(mgmt, cmdbufr);
			break;

		case show_forensics_counts:
			retn = send_counts(mgmt, FORENSICS_COUNTS, \
					   cmdbufr);
			break;

		case show_forensics_coefficients:
			retn = send_coefficients(mgmt,			 \
						 FORENSICS_COEFFICIENTS, \
						 cmdbufr);
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

		case model_cmd_base:
			if ( !_add_entry(sigdata, entry) )
				ERR(goto done);

			if ( Debug != NULL )
				fprintf(Debug, "%s: Adding base: %s\n", \
					__func__, arg);
			if ( !bufr->add(bufr, (void *) arg, strlen(arg) + 1) )
				ERR(goto done);
			if ( !Control->set_base(Control, bufr) )
				ERR(goto done);
			break;

		case model_cmd_state:
			if ( !_add_entry(sigdata, entry) )
				ERR(goto done);

			if ( Debug != NULL )
				fprintf(Debug, "%s: Adding state: %s\n", \
					__func__, arg);
			if ( !bufr->add(bufr, (void *) arg, strlen(arg) + 1) )
				ERR(goto done);
			if ( !Control->add_state(Control, bufr) )
				ERR(goto done);
			break;

		case model_cmd_pseudonym:
			if ( !_add_entry(sigdata, entry) )
				ERR(goto done);

			if ( Debug != NULL )
				fprintf(Debug, "%s: Adding pseudonym: %s\n", \
					__func__, arg);
			if ( !bufr->add(bufr, (void *) arg, strlen(arg) + 1) )
				ERR(goto done);
			if ( !Control->pseudonym(Control, bufr) )
				ERR(goto done);
			break;

		case model_cmd_seal:
			if ( !_add_entry(sigdata, entry) )
				ERR(goto done);

			if ( !Control->seal(Control) )
				ERR(goto done);
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
 * \param model_file	The name of the file that contains the security
 *			model that is to be enforced.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the model was loaded.  A false value
 *			indicates the load of the model failed while
 *			a true value indicates the model was successfully
 *			loaded.
 */

static _Bool load_model(const char *model_file)

{
	_Bool retn = false;

	String str = NULL;

	File model = NULL;


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
 * This function is responsible for receiving a security model from a
 * terminated domain and writing the model to the designated output file.
 *
 * \param filename	A null terminated buffer containing the
 *			name of the output file.
 *
 * \param fd		The file descriptor that the map is to be
 *			read from.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the receipt and out of the model.  A false value indicates
 *		an error was encountered while a true value indicates the
 *		model was received and written.
 */

static _Bool output_trajectory(CO(char *, filename))

{
	_Bool retn = false;

	String ts = NULL;

	File ef	     = NULL,
	     outfile = NULL;


	/* Open the output file. */
	INIT(HurdLib, File, outfile, ERR(goto done));
	truncate(filename, 0);
	if ( !outfile->open_rw(outfile, filename) )
		ERR(goto done);

	/* Open the trajectory event file. */
	INIT(HurdLib, File, ef, ERR(goto done));
	if ( !ef->open_ro(ef, TRAJECTORY) )
		ERR(goto done);

	/* Write each trajectory point. */
	INIT(HurdLib, String, ts, ERR(goto done));
	while ( ef->read_String(ef, ts) ) {
		if ( !ts->add(ts, "\n") )
			ERR(goto done);
		if ( !outfile->write_String(outfile, ts) )
			ERR(goto done);
		ts->reset(ts);
	}
	retn = true;


 done:
	WHACK(ts);
	WHACK(ef);
	WHACK(outfile);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for receiving a security state map
 * from a terminated domain and writing the map to the designated
 * output file.
 *
 * \param filename	A null terminated buffer containing the
 *			name of the output file.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the receipt and out of the model.  A false value indicates
 *		an error was encountered while a true value indicates the
 *		model was received and written.
 */

static _Bool output_model(CO(char *, filename))

{
	_Bool retn = false;

	static const char *aggregate_tag = "aggregate ",
			  *state_tag = "state ",
			  *seal_tag = "seal\n",
			  *end_tag = "end\n";

	String str = NULL;

	File ef	     = NULL,
	     outfile = NULL;


	INIT(HurdLib, String, str, ERR(goto done));

	/* Open output file. */
	INIT(HurdLib, File, outfile, ERR(goto done));
	truncate(filename, 0);
	if ( !outfile->open_rw(outfile, filename) )
		ERR(goto done);

	/* Send aggregate. */
	INIT(HurdLib, File, ef, ERR(goto done))
	if ( !ef->open_ro(ef, AGGREGATE) )
		ERR(goto done);
	str->add(str, aggregate_tag);
	if ( !ef->read_String(ef, str) )
		ERR(goto done);
	if ( !str->add(str, "\n") )
		ERR(goto done);
	if ( !outfile->write_String(outfile, str) )
		ERR(goto done);

	/* Send the coefficients. */
	ef->reset(ef);
	if ( !ef->open_ro(ef, TRAJECTORY_COEFFICIENTS) )
		ERR(goto done);

	str->reset(str);
	if ( !str->add(str, state_tag) )
		ERR(goto done);

	while ( ef->read_String(ef, str) ) {
		if ( !str->add(str, "\n") )
			ERR(goto done);
		if ( !outfile->write_String(outfile, str) )
			ERR(goto done);
		str->reset(str);
		if ( !str->add(str, state_tag) )
			ERR(goto done);
	}

	/* Send the closing commands. */
	str->reset(str);
	if ( !str->add(str, seal_tag) )
		ERR(goto done);
	if ( !outfile->write_String(outfile, str) )
		ERR(goto done);

	str->reset(str);
	if ( !str->add(str, end_tag) )
		ERR(goto done);
	if ( !outfile->write_String(outfile, str) )
		ERR(goto done);


 done:
	WHACK(str);
	WHACK(ef);
	WHACK(outfile);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for launching a workload in an
 * independent measurement domain.  A pipe is established between the
 * parent process and the child that is used to return the namespace
 * specific events for injection into the security co-processor.
 *
 * \param workload	The object that is managing the workload.
 *
 * \param container	A pointer to a null-terminated character buffer
 *			containing the name of the container that is
 *			being executed.
 *
 * \param outfile	A pointer to a null-terminated array
 *			containing the name of the output file that
 *			is to be generated.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the workload.  A false value indicates an error was
 *		encountered while a true value indicates the workload
 *		was successfuly executed.
 */

static _Bool run_workload(CO(TSEMworkload, workload), CO(char *, container), \
			  CO(char *, outfile))

{
	_Bool retn = false;

	LocalDuct mgmt = NULL;


	/* Setup the management socket. */
	INIT(NAAAIM, LocalDuct, mgmt, ERR(goto done));
	if ( !setup_management(mgmt, container) )
		ERR(goto done);

	if ( !workload->run_workload(workload) )
		ERR(goto done);

	if ( !workload->run_monitor(workload, mgmt, NULL, process_command) )
		ERR(goto done);

	if ( outfile != NULL ) {
		truncate(outfile, 0);
		if ( Trajectory )
			retn = output_trajectory(outfile);
		else
			retn = output_model(outfile);
	}

	retn = true;


 done:
	WHACK(mgmt);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool enforce		= false,
	      current_namespace = false;

	char *debug	    = NULL,
	     *outfile	    = NULL,
	     *model	    = NULL,
	     *container	    = NULL,
	     *magazine_size = NULL;

	int opt,
	    retn = 1;


	while ( (opt = getopt(argc, argv, "CPSXetuM:c:d:h:m:n:o:")) != EOF )
		switch ( opt ) {
			case 'C':
				Mode = container_mode;
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
			case 't':
				Trajectory = true;
				break;
			case 'u':
				current_namespace = true;
				break;
			case 'X':
				Mode = execute_mode;
				break;

			case 'M':
				TSEM_model = optarg;
				break;

			case 'c':
				container = optarg;
				break;
			case 'd':
				debug = optarg;
				break;
			case 'h':
				Digest = optarg;
				break;
			case 'm':
				model = optarg;
				break;
			case 'n':
				magazine_size = optarg;
				break;
			case 'o':
				Pause   = true;
				outfile = optarg;
				break;
		}

	/* Execute cartridge display mode. */
	if ( Mode == show_mode )
		show_magazine(QUIXOTE_MAGAZINE);

	if ( (Mode == container_mode) && (container == NULL) ) {
		fputs("No software container specified.\n", stderr);
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

	/* Verify the magazine size if specified. */
	if ( magazine_size != NULL ) {
		Magazine_Size = strtoul(magazine_size, NULL, 0);
		if ( (errno == EINVAL) || (errno == ERANGE) ) {
			fputs("Invalid magazine size.\n", stderr);
			goto done;
		}
	}

	/* Load and seal a security model if specified. */
	if ( model != NULL ) {
		if ( Debug )
			fprintf(Debug, "Loading security model: %s\n", model);

		if ( !load_model(model) ) {
			fputs("Cannot initialize security model.\n", stderr);
			goto done;
		}
	}

	/* Initialize the security model controller. */
	INIT(NAAAIM, TSEMcontrol, Control, ERR(goto done));

	INIT(NAAAIM, TSEMworkload, Workload, ERR(goto done));
	Workload->set_debug(Workload, Debug);
	if ( !Workload->configure_internal(Workload, TSEM_model, Digest,     \
					   magazine_size, current_namespace, \
					   enforce) )
		ERR(goto done);

	switch ( Mode ) {
		case container_mode:
			if ( !Workload->set_container_mode(Workload, 	     \
							   QUIXOTE_MAGAZINE, \
							   container) )
				ERR(goto done);
			break;

		case execute_mode:
			Workload->set_execute_mode(Workload, argc, argv);
			break;

		default:
			break;
	}

	/* Run the workload. */
	if ( Debug )
		fprintf(Debug, "Launch process: %d\n", getpid());
	if ( !run_workload(Workload, container, outfile) )
		ERR(goto done);

	if ( outfile != NULL ) {
		if ( Trajectory )
			fputs("Wrote execution trajectory to: ", stdout);
		else
			fputs("Wrote security model to: ", stdout);
		fprintf(stdout, "%s\n", outfile);
	}

	retn = 0;


 done:
	WHACK(Control);
	WHACK(Workload);

	return retn;
}
