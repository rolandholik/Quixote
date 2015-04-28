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
 * \param token		The object which the configuration token will
 *			be loaded into.
 *
 * \param prompt	A character pointer to a buffer containing
 *			the prompt which is to be used to unlock
 *			the platform configuration token key.
 *
 * \return	If an error has been encountered during the platform
 *		check for configuration a false value is returned.  It
 *		should be noted that failing to decrypt the
 *		configuration token is not an error.  If the
 *		configuration process has been succssful a true value
 *		is returned.
 */

static _Bool _decrypt_platform_token(CO(char *, file), CO(char*, prompt), \
				     CO(Buffer, token))

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

	RSAkey rsakey = NULL;

	File token_file = NULL;


	if ( (token == NULL) || token->poisoned(token) )
		ERR(goto done);

	INIT(HurdLib, File, token_file, goto done);
	if ( !token_file->open_ro(token_file, CONFIG) )
		ERR(goto done);
	if ( !token_file->slurp(token_file, token) )
		ERR(goto done);


	INIT(NAAAIM, RSAkey, rsakey, goto done);
	if ( !rsakey->init_engine(rsakey, engine_cmds) )
		ERR(goto done);
	if ( !rsakey->load_private_key(rsakey, "01:02", prompt) ) {
		token->reset(token);
		retn = true;
		goto done;
	}
	if ( !rsakey->decrypt(rsakey, token) ) {
		token->reset(token);
		retn = true;
		goto done;
	}

	retn = true;


 done:
	WHACK(rsakey);
	WHACK(token_file);

	return retn;
}


/**
 * Internal function.
 *
 * This function is responsible for attempting to decrypt the
 * configuration token to verify whether or not platform configuration
 * is being requested.  It appears as if the OpenSSL pkcs11 engine
 * retains some type of state which prevents more then a single key
 * operations to be conducted in the context of a single process.  As
 * a result this function forks a subordinate process to decrypt
 * the platform configuration token in order to prevent the long
 * running supervisor process from being poisoned.
 *
 * If a hardware key has been presented which is capable of decrypting
 * the configuration token the configuration processing tool is called.
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

static _Bool check_for_configuration(void)

{
	_Bool retn = false;

	int fd,
	    status;

	pid_t pid;

	Buffer token = NULL;

	IPC ipc = NULL;


	INIT(HurdLib, Buffer, token, goto done);

	/* Create a shared memory area to hold the decrypted token. */
	INIT(NAAAIM, IPC, ipc, goto done);
	if ( !ipc->create(ipc, "mgmt-super_config", KEYSIZE / 8) )
		ERR(goto done);


	/* Spawn a child process to decrypt configuration token. */
	pid = fork();
	if ( pid == -1 )
		ERR(goto done);

	/* Child. */
	if ( pid == 0 ) {
		if ( (fd = open("/dev/null", O_RDWR)) == -1 )
			_exit(2);
		if ( dup2(fd, STDERR_FILENO) == -1 )
			_exit(2);

		if ( !_decrypt_platform_token(CONFIG, CONFIG_PROMPT, token) ) {
			WHACK(token);
			_exit(2);
		}
		if ( token->size(token) == 0 ) {
			WHACK(token);
			_exit(1);
		}

		if ( !ipc->copy(ipc, token->get(token), token->size(token), \
				0) )
			_exit(2);
		WHACK(ipc);
		_exit(0);
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

	/* Do provisioning. */
	if ( !token->add(token, ipc->get(ipc), KEYSIZE / 8) )
		ERR(goto done);
	fputs("Using key contents for provisioning:\n", stderr);
	token->hprint(token);
	
	retn = true;


 done:
	WHACK(token);
	fputs("Destroying IPC.\n", stderr);
	WHACK(ipc);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;


	while ( 1 ) {
		if ( !get_reader() ) {
			sleep(10);
			continue;
		}
		if ( !check_for_configuration() ) {
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
