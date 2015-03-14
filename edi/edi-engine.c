/** \file
 * This file implements a server daemon which receives ASN1 encoded
 * EDI transactions and processes those transactions by either
 * decrypting or encrypting them with the identity specified in the
 * encoded request.
 */

/**************************************************************************
 * (C)Copyright 2015, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local defines. */
#define BIRTHDATE 1425679137
#define IV_SIZE	  16


/* Include files. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Config.h>
#include <Buffer.h>
#include <String.h>

#include <Duct.h>
#include <IDtoken.h>
#include <OTEDKS.h>
#include <IDmgr.h>
#include <SHA256.h>
#include <AES256_cbc.h>
#include <SHA256_hmac.h>

#include "edi.h"
#include "EDIpacket.h"


/* Variables static to this module. */
static pid_t process_table[100];


/**
 * Private function.
 *
 * This function initializes the process table.
 */

static void init_process_table(void)

{
	auto unsigned int lp;


	for (lp= 0; lp < sizeof(process_table)/sizeof(pid_t); ++lp)
		process_table[lp] = 0;
	return;
}


/**
 * Private function.
 *
 * This function adds an entry to the process state table.  It will
 * locate an empy slot in the table and place the PID of the dispatched
 * process in that slot.
 *
 * \param pid	The process ID to be placed in the table.
 */

static void add_process(pid_t pid)

{
	auto unsigned int lp;


	for (lp= 0; lp < sizeof(process_table)/sizeof(pid_t); ++lp)
		if ( process_table[lp] == 0 ) {
			process_table[lp] = pid;
			return;
		}
	return;
}


/**
 * Private function.
 *
 * This function reaps any available processes and updates its slot in
 * the process table.
 */

static void update_process_table(void)

{
	auto unsigned int lp;

	auto int pid,
		 status;


	while ( (pid = waitpid(-1, &status, WNOHANG)) > 0 )
		for (lp= 0; lp < sizeof(process_table)/sizeof(pid_t); ++lp)
			if ( process_table[lp] == pid ) {
				process_table[lp] = 0;
				fprintf(stdout, "%d terminated", pid);
				if ( !WIFEXITED(status) ) {
					fputs(" abnormally.\n", stdout);
					continue;
				}
				fprintf(stdout, ", status=%d\n", \
					WEXITSTATUS(status));
			}
	return;
}


/**
 * Private function.
 *
 * This function is called to setup the shared session state key
 * which is mediated with the remote engine.
 *
 * \param client	The network connection object with the
 *			engine client.
 *
 * \param hash		The hash object which will be initialized
 *			with the shared key.
 *
 * \return		A false value is returned if an error occurs
 *			during setup of the session key.  A true
 *			value means the session key has been
 *			successively established.
 */

static _Bool setup_session(CO(Duct, client), CO(EDIpacket, edi), \
			   CO(Buffer, bufr), CO(SHA256, hash))

{
	_Bool retn = false;


	/* Receive EDI transaction packet which encodes the shared key. */
	if ( !client->receive_Buffer(client, bufr) )
		goto done;

	edi->decode_payload(edi, bufr);
	if ( edi->get_type(edi) != EDIpacket_key )
		goto done;
	bufr->reset(bufr);
	if ( !edi->get_payload(edi, bufr) )
		goto done;
	fprintf(stderr, "%d[%s]: Shared secret:\n", getpid(), __func__);
	bufr->hprint(bufr);

	/* Hash the shared key. */
	hash->add(hash, bufr);
	if ( !hash->compute(hash) )
		goto done;

	retn = true;


 done:
	edi->reset(edi);
	bufr->reset(bufr);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for generating a OTEDKS initialization
 * vector and key and using this key to encrypt the payload contents
 * of an EDI transaction.
 *
 * \param service	The object containing the name of the identity
 * 			whose identity will be used for the encryption
 *			key.
 *
 * \param edi		The EDI transaction which is to be
 *			encrypted.
 *
 * \param hash		The hash object which will be used as the
 *			key to the HMAC which will be used to
 *			generate the encryption key.
 *
 * \return		If an error occurs during the encryption of
 *			the EDI transaction a false value is returned.
 *			A true value indicates the supplied Buffer objects
 *			contain valid material.
 */

static _Bool encrypt_edi(CO(String, service), CO(EDIpacket, edi), \
			 CO(SHA256, hash))

{
	_Bool retn = false;

	time_t authtime = time(NULL);

	Buffer idkey   = NULL,
	       idhash  = NULL,
	       payload = NULL;

	IDmgr idmgr = NULL;

	OTEDKS otedks = NULL;

	AES256_cbc cipher = NULL;

	SHA256_hmac hmac = NULL;


	INIT(HurdLib, Buffer, idkey, goto done);
	INIT(HurdLib, Buffer, idhash, goto done);
	INIT(HurdLib, Buffer, payload, goto done);

	INIT(NAAAIM, IDmgr, idmgr, goto done);
	if ( !idmgr->attach(idmgr) ) {
		fputs("Error attaching to identity manager.\n", stderr);
		goto done;
	}
	if ( !idmgr->get_id_key(idmgr, service, idhash, idkey) ) {
		fputs("Error obtaining key information.\n", stderr);
		goto done;
	}

	if ( (otedks = NAAAIM_OTEDKS_Init(BIRTHDATE)) == NULL )
		goto done;
	if ( !otedks->compute(otedks, authtime, idkey, idhash) )
		goto done;

	/* Generate a session specific initialization vector. */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(hash->get_Buffer(hash))) == NULL )
		goto done;
	hmac->add_Buffer(hmac, otedks->get_iv(otedks));
	if ( !hmac->compute(hmac) )
		goto done;
	idhash->reset(idhash);
	if ( !idhash->add(idhash, hmac->get(hmac), IV_SIZE) )
		goto done;

	/* Generate a session specific encryption key. */
	hmac->reset(hmac);
	hmac->add_Buffer(hmac, otedks->get_key(otedks));
	if ( !hmac->compute(hmac) )
		goto done;
	idkey->reset(idkey);
	if ( !idkey->add_Buffer(idkey, hmac->get_Buffer(hmac)) )
		goto done;

	if ( !edi->get_payload(edi, payload) )
		goto done;
	edi->reset(edi);
	edi->set_authtime(edi, authtime);
	edi->set_type(edi, EDIpacket_encrypted);

	fprintf(stderr, "%d[%s]: authtime=%d\n", getpid(), __func__, \
		(int) authtime);
	fprintf(stderr, "%d[%s]: iv:\n", getpid(), __func__);
	idhash->print(idhash);
	fprintf(stderr, "%d[%s]: key:\n", getpid(), __func__);
	idkey->print(idkey);

	cipher = NAAAIM_AES256_cbc_Init_encrypt(idkey, idhash);
	if ( cipher == NULL )
		goto done;
	if ( !cipher->encrypt(cipher, payload) )
		goto done;

	if ( !edi->set_payload(edi, cipher->get_Buffer(cipher)) )
		goto done;

	retn = true;


 done:
	WHACK(idkey);
	WHACK(idhash);
	WHACK(payload);
	WHACK(idmgr);
	WHACK(otedks);
	WHACK(cipher);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for generating a OTEDKS initialization
 * vector and key and using this key to decrypt the payload contents
 * of an EDI transaction.
 *
 * \param service	The object containing the name of the identity
 * 			whose identity will be used to generate the
 *			decryption key.
 *
 * \param edi		The EDI transaction which is to be decrypted.
 *
 * \param hash		The hash object which will be used as the
 *			key to the HMAC which will be used to
 *			generate the decryption key.
 *
 * \return		If an error occurs during the decryption of
 *			the EDI transaction a false value is returned.
 *			A true value indicates the supplied Buffer objects
 *			contain valid material.
 */

static _Bool decrypt_edi(CO(String, service), CO(EDIpacket, edi), \
			 CO(SHA256, hash))

{
	_Bool retn = false;

	Buffer idkey   = NULL,
	       idhash  = NULL,
	       payload = NULL;

	IDmgr idmgr = NULL;

	OTEDKS otedks = NULL;

	AES256_cbc cipher = NULL;

	SHA256_hmac hmac = NULL;


	INIT(HurdLib, Buffer, idkey, goto done);
	INIT(HurdLib, Buffer, idhash, goto done);
	INIT(HurdLib, Buffer, payload, goto done);

	INIT(NAAAIM, IDmgr, idmgr, goto done);
	if ( !idmgr->attach(idmgr) ) {
		fputs("Error attaching to identity manager.\n", stderr);
		goto done;
	}
	if ( !idmgr->get_id_key(idmgr, service, idhash, idkey) ) {
		fputs("Error obtaining key information.\n", stderr);
		goto done;
	}

#if 0
	fprintf(stderr, "%s: EDI packet:\n", __func__);
	edi->print(edi);
#endif

	if ( (otedks = NAAAIM_OTEDKS_Init(BIRTHDATE)) == NULL )
		goto done;
	if ( !otedks->compute(otedks, edi->get_authtime(edi), idkey, idhash) )
		goto done;
	fprintf(stderr, "%d[%s]: authtime=%d\n", getpid(), __func__, \
		(int) edi->get_authtime(edi));

	/* Generate a session specific initialization vector. */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(hash->get_Buffer(hash))) == NULL )
		goto done;
	hmac->add_Buffer(hmac, otedks->get_iv(otedks));
	if ( !hmac->compute(hmac) )
		goto done;
	idhash->reset(idhash);
	if ( !idhash->add(idhash, hmac->get(hmac), IV_SIZE) )
		goto done;

	/* Generate a session specific encryption key. */
	hmac->reset(hmac);
	hmac->add_Buffer(hmac, otedks->get_key(otedks));
	if ( !hmac->compute(hmac) )
		goto done;
	idkey->reset(idkey);
	if ( !idkey->add_Buffer(idkey, hmac->get_Buffer(hmac)) )
		goto done;

	if ( !edi->get_payload(edi, payload) )
		goto done;
	edi->reset(edi);
	edi->set_type(edi, EDIpacket_decrypted);

	fprintf(stderr, "%d[%s]: iv:\n", getpid(), __func__);
	idhash->print(idhash);
	fprintf(stderr, "%d[%s]: key:\n", getpid(), __func__);
	idkey->print(idkey);

	cipher = NAAAIM_AES256_cbc_Init_decrypt(idkey, idhash);
	if ( cipher == NULL )
		goto done;
	if ( !cipher->decrypt(cipher, payload) )
		goto done;

	if ( !edi->set_payload(edi, cipher->get_Buffer(cipher)) )
		goto done;

	retn = true;


 done:
	WHACK(idkey);
	WHACK(idhash);
	WHACK(payload);
	WHACK(idmgr);
	WHACK(otedks);
	WHACK(cipher);
	WHACK(hmac);

	return retn;
}


/**
 * Private function.
 *
 * This function is called to handle a connection for an identity
 * generation request.
 *
 * \param duct	The network connection object being used to handle
 *		the identity generation request.
 *
 * \return	No return value is defined.
 */

static void handle_connection(CO(Duct,duct))

{
	pid_t id;

	Buffer bufr = NULL;

	String svc = NULL;

	EDIpacket edi = NULL;

	SHA256 hash = NULL;


	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(NAAAIM, EDIpacket, edi, goto done);
	INIT(NAAAIM, SHA256, hash, goto done);
	if ( (svc = HurdLib_String_Init_cstr("service1")) == NULL )
		goto done;

	id = getpid();
	fprintf(stdout, "\n.%d: EDI engine connection, client=%s.\n", id, \
		duct->get_client(duct));

	if ( !setup_session(duct, edi, bufr, hash) )
		goto done;

	/* Process incoming transactions in a loop. */
	while ( 1 ) {
		if ( !duct->receive_Buffer(duct, bufr) )
			goto done;

		fprintf(stderr, "\n%d: Processing EDI request:\n", id);
		if ( !edi->decode_payload(edi, bufr) ) {
			fputs("Failed to decode buffer.\n", stderr);
			goto done;
		}
		fprintf(stderr, "%d: Using hash:\n", id);
		hash->print(hash);

		if ( edi->get_type(edi) == EDIpacket_decrypted ) {
			if ( !encrypt_edi(svc, edi, hash) ) {
				fputs("Failed to encrypt buffer.\n", stderr);
				goto done;
			}
		} else if ( edi->get_type(edi) == EDIpacket_encrypted ) {
			if ( !decrypt_edi(svc, edi, hash) ) {
				fputs("Failed to decrypt buffer.\n", stderr);
				goto done;
			}
		}

		bufr->reset(bufr);
		if ( !edi->encode_payload(edi, bufr) )
			goto done;

#if 0
		fputs("Returning payload:\n", stderr);
		edi->print(edi);
#endif
		if ( !duct->send_Buffer(duct, bufr) )
			goto done;

		bufr->reset(bufr);
		edi->reset(edi);
		hash->rehash(hash, 1);
	}


 done:
	WHACK(bufr);
	WHACK(svc);
	WHACK(edi);
	WHACK(hash);

	return;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	char *host = NULL,
	     *err  = NULL;

	int opt,
	    retn = 1;

	pid_t pid = 0;

	Duct duct = NULL;


	fputs("EDI engine started.\n", stdout);
	fflush(stdout);

	while ( (opt = getopt(argc, argv, "h:")) != EOF )
		switch ( opt ) {
			case 'h':
				host = optarg;
				break;
		}

	/* Arguement verification. */
	if ( host == NULL ) {
		fputs("No hostname specified.\n", stderr);
		goto done;
	}

	/* Initialize process table. */
	init_process_table();

	/* Initialize the network port and wait for connections. */
	INIT(NAAAIM, Duct, duct, goto done);

	if ( !duct->init_server(duct) ) {
		fputs("Cannot set server mode.\n", stderr);
		goto done;
	}

	if ( !duct->set_server(duct, host) ) {
		err = "Cannot set server name.";
		goto done;
	}

	if ( !duct->init_port(duct, NULL, ENGINE_PORT) ) {
		fputs("Cannot initialize port.\n", stderr);
		goto done;
	}

	while ( 1 ) {
		if ( !duct->accept_connection(duct) ) {
			err = "Error on connection accept.";
			goto done;
		}

		pid = fork();
		if ( pid == -1 ) {
			err = "Connection fork failure.";
			goto done;
		}
		if ( pid == 0 ) {
			handle_connection(duct);
			_exit(0);
		}

		add_process(pid);
		update_process_table();
		duct->reset(duct);
	}


 done:
	if ( err != NULL )
		fprintf(stderr, "!%s\n", err);

	if ( duct != NULL ) {
	     if ( !duct->whack_connection(duct) )
		     fputs("Error closing duct connection.\n", stderr);
	     duct->whack(duct);
	}

	if ( pid == 0 )
		fputs(".Client terminated.\n", stdout);

	return retn;
}
