/** \file
 * This file implements the system setup utility.  The purpose of
 * this utility is to check for the presence of a qualified hardware
 * key and if present initiate the process of generating a new
 * device configuration.
 */

/**************************************************************************
 * (C)Copyright 2015, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define CONFIG "./config.enc"
#define CONFIG_PROMPT "Enter device configuration code: "

#define KEYSIZE 2048


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <RSAkey.h>
#include <SmartCard.h>
#include <IPC.h>

#include "MGMTsupvr.h"


/**
 * Internal function.
 *
 * This function is responsible for acquiring access to a hardware key
 * token.  This function implicitly assumes the model of a hardware
 * key token such as the Yubikey where the token itself is considered
 * to be a reader.
 *
 * This function takes no arguements.
 *
 * \return	A boolean value is used to indicate when a reader is
 *		available.  A true value indicates a reader is
 *		available and has a token available for operation.  A
 *		false value indicates that a reader is not available.
 *		This may be triggered by a condition such as a
 *		card infrastructure error.
 */

static _Bool get_reader(void)

{
	_Bool retn = false;

	int cnt = 0;

	SmartCard card = NULL;


	INIT(NAAAIM, SmartCard, card, goto done);

	if ( !card->get_readers(card, &cnt) )
		ERR(goto done);
	if ( cnt > 0 ) {
		retn = true;
		goto done;
	}
	if ( !card->wait_for_reader(card, &cnt) )
		ERR(goto done);

	retn = true;

 done:
	WHACK(card);
	return retn;
}


/**
 * Internal function.
 *
 * This function is responsible for releasing access to a hardware key
 * token.  This function implicitly assumes the model of a hardware
 * key token such as the Yubikey where the token itself is considered
 * to be a reader.
 *
 * This function takes no arguements.
 *
 * \return	A false value indicates an error was encountered while
 *		querying the status of the reader.  A true value
 *		indicates the reader count is zero.
 */

static _Bool release_reader(void)

{
	_Bool retn = false;

	int cnt = 0;

	SmartCard card = NULL;


	INIT(NAAAIM, SmartCard, card, goto done);

	while ( 1 ) {
		if ( !card->get_readers(card, &cnt) )
			ERR(goto done);
		if ( cnt == 0 ) {
			retn = true;
			goto done;
		}
		sleep(5);
	}

 done:
	WHACK(card);
	return retn;
}


/**
 * Internal private function.
 *
 * This function is responsible for decrypting the platform
 * configuration token supplied by the caller.
 *
 * \param file		A character pointer to the buffer containing
 *			the name of the platform management token to
 *			be decrypted.
 *
 * \param prompt	A character pointer to a buffer containing
 *			the prompt which is to be used to unlock
 *			the platform configuration token key.
 *
 * \param mgmt		The object which will hold the encryption
 *			vector and key.
 *
 * \return	If an error has been encountered during the loading
 *		of the platform configuration keys a false value is
 *		returned.  If acquisition of the keys are successfull
 *		a true value is returned.
 */

static _Bool _decrypt_platform_token(CO(char *, file), CO(char*, prompt), \
				     CO(MGMTsupvr, mgmt))

{
	_Bool retn = false;

	const char *engine_cmds[] = {
		"SO_PATH", "/usr/local/musl/lib/engines/engine_pkcs11.so", \
		"ID", "pkcs11",					    	   \
		"LIST_ADD", "1",				    	   \
		"LOAD", NULL,					    	   \
		"MODULE_PATH", "/usr/local/lib/opensc-pkcs11.so",   	   \
		NULL, NULL
	};


	if ( (mgmt == NULL) || mgmt->poisoned(mgmt) )
		ERR(goto done);

	if ( !mgmt->load_key(mgmt, "01:02", engine_cmds, prompt) )
		ERR(goto done);
	retn = true;

 done:
	return retn;
}


/**
 * Internal function.
 *
 * This function is responsible for driving the generation of a
 * configuration filesystem.  Since it appears as if the OpenSSL
 * pkcs11 engine retains some type of state which prevents more then a
 * single key operation to be conducted in the context of a single
 * process this process is designed to be called from the context of a
 * subordinate process to the primary primary process.
 *
 * This function expects no input variables.
 *
 * \return	If an error has been encountered during the platform
 *		check for configuration a false value is returned.  It
 *		should be noted that failing to decrypt the
 *		configuration token is not an error.  If the
 *		configuration process has been succssful a true value
 *		is returned.
 */

static _Bool do_configuration(void)

{
	_Bool retn = false;

	int fd,
	    status;

	pid_t pid;

	MGMTsupvr mgmt = NULL;


	/* Spawn a child process to decrypt configuration token. */
	pid = fork();
	if ( pid == -1 )
		ERR(goto done);

	/* Child. */
	if ( pid == 0 ) {
		status = 1;
#if 0
		if ( (fd = open("/dev/null", O_RDWR)) == -1 )
			goto out;
		if ( dup2(fd, STDERR_FILENO) == -1 )
			goto out;
#endif

		status = 2;
		INIT(NAAAIM, MGMTsupvr, mgmt, goto out);
		if ( !_decrypt_platform_token(CONFIG, CONFIG_PROMPT, mgmt) )
			goto out;

		mgmt->dump(mgmt);
		status = 0;

	out:
		_exit(status);
	}

	/* Parent - wait for child termination. */
	if ( waitpid(pid, &status, 0) != pid )
		ERR(goto done);
	if ( !WIFEXITED(status) )
		ERR(goto done);
	if ( WEXITSTATUS(status) == 2 )
		ERR(goto done);
	if ( WEXITSTATUS(status) == 1 ) {
		retn = true;
		goto done;
	}

	retn = true;

 done:
	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;


	while ( 1 ) {
		fputs("Insert key to activate.\n", stdout);
		fflush(stdout);
		if ( !get_reader() ) {
			sleep(10);
			continue;
		}
		if ( !do_configuration() ) {
			ERR(goto done);
		}
		else {
			fputs("Configuration completed - remove key.\n", \
			      stderr);
			if ( !release_reader() )
				ERR(goto done);
		}
	}

 done:
	return retn;
}
