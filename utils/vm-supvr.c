/** \file
 * This file implements the Windows virtual machine control utility.
 * The purpose of this utility is to run the background daemons needed
 * to support a Xen based Windows virtualization environment which is
 * started by authenticating the initiating user with a two-factor
 * Yubikey transaction.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Local defines. */
#define CONFIG "/etc/conf/config.enc"
#define CONFIG_PROMPT "Enter authentication code: >"

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


/* Process identifiers for the daemons. */
static pid_t Devmgr_pid	= 0,
	     Pcscd_pid	= 0;


/**
 * Internal function.
 *
 * This function is responsible for starting the device manager daemon
 * and the pcscd daemon which are needed to support the Yubikey
 * authentications needed to start Windows.
 *
 * This function takes no arguements.
 *
 * \return	A boolean value is used to indicate the daemons have
 *		been properly started.  A true value indicates the
 *		daemons are running while a false value indicates
 *		one or the other failed.
 */

static _Bool start_daemons(void)

{
	_Bool retn = false;

	int fd;


	/* Spawn a child process for the device manager. */
	Devmgr_pid = fork();
	if ( Devmgr_pid == -1 )
		ERR(goto done);

	/* Child. */
	if ( Devmgr_pid == 0 ) {
		if ( (fd = open("/dev/null", O_RDWR)) == -1 )
			goto out1;
		if ( dup2(fd, STDERR_FILENO) == -1 )
			goto out1;
		execl("/usr/local/sbin/device-supvr", "device-supvr", NULL);
	out1:
		_exit(1);
	}


	/* Spawn a child process for the card manager. */
	Pcscd_pid = fork();
	if ( Pcscd_pid == -1 )
		ERR(goto done);

	/* Child. */
	if ( Pcscd_pid == 0 ) {
		if ( (fd = open("/dev/null", O_RDWR)) == -1 )
			goto out2;
		if ( dup2(fd, STDERR_FILENO) == -1 )
			goto out2;
		if ( dup2(fd, STDOUT_FILENO) == -1 )
			goto out2;
		execl("/usr/local/sbin/pcscd", "pcscd", "-f", NULL);
	out2:
		_exit(1);
	}

	retn = true;


 done:
	return retn;
}


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
 * This function is responsible for verifying the status of the Yubikey
 * which triggers the Windows start.
 *
 * This function expects no input variables.
 *
 * \return	If an error has been encountered during the 2-factor
 *		authentication a false value is returned.
 *		If the verification has been successful a true value is
 *		returned.
 */

static _Bool verify_key(void)

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
		if ( (fd = open("/dev/null", O_RDWR)) == -1 )
			goto out;
		if ( dup2(fd, STDERR_FILENO) == -1 )
			goto out;

		status = 2;
		INIT(NAAAIM, MGMTsupvr, mgmt, goto out);
		if ( !_decrypt_platform_token(CONFIG, CONFIG_PROMPT, mgmt) )
			goto out;
		status = 0;

	out:
		_exit(status);
	}

	/* Parent - wait for child termination. */
	if ( waitpid(pid, &status, 0) != pid )
		ERR(goto done);
	if ( !WIFEXITED(status) )
		ERR(goto done);
	if ( WEXITSTATUS(status) == 0 )
		retn = true;

 done:
	return retn;
}


/**
 * Internal function.
 *
 * This function is responsible for starting the virtual Windows
 * instance.
 *
 * This function expects no input variables.
 *
 * \return	If an error occurred during the start of the virtual
 *		Windows instance a false value is returned.  If
 *		the verification has been successful a true value is
 *		returned.
 */

static _Bool start_vm(void)

{
	_Bool retn = true;


	if ( system("/usr/local/bin/vgt-vm /etc/conf/Windows.xen "
		    "0000:00:1d.0 ehci-pci") != 0 )
		retn = false;

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool need_logo = true;

	int retn = 1;


	if ( !start_daemons() ) 
		ERR(goto done);
	sleep(3);


	while ( 1 ) {
		if ( need_logo ) {
			fputs("\x1b\x5b\x48\x1b\x5b\x4a", stdout);
			fputs("\x1b\x5b\x32\x3b\x35\x34\x48", stdout);
			fputs("\x1b\x5b\x31\x6d", stdout);
			fputs("Enjellic\x1b\x5b\x33\x31\x6d " \
			      "IDFSS", stdout);
			fputs("\x1b\x5b\x30\x3b\x31\x30\x6d", stdout);
			fputs("\n\nInsert key to activate: >", stdout);
			fflush(stdout);
		}

		if ( !get_reader() ) {
			sleep(10);
			continue;
		}

		fputc('\n', stdout);
		fputs(CONFIG_PROMPT, stdout);
		fflush(stdout);

		if ( verify_key() ) {
			fputs("\nAuthentication valid, remove key to start.\n",
			      stdout);
			fflush(stdout);
			if ( !release_reader() )
				ERR(goto done);
			start_vm();

			need_logo = true;
			continue;
		}

		fputs("\nFailed authentication code - retry.\n",
		      stdout);
		fflush(stdout);
		need_logo = false;
		sleep(3);
	}

 done:
	kill(Devmgr_pid, SIGTERM);
	kill(Pcscd_pid, SIGTERM);

	return retn;
}
