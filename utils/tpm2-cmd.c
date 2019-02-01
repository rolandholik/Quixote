/** \file
 * This file implements a utility to execute TPM2 commands which are
 * specified as command-line arguements to the application.
 */

/**************************************************************************
 * (C)Copyright 2016, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <ibmtss/tss.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>
#include <TPM2cmd.h>

#include <NAAAIM.h>
#include <RandomBuffer.h>


extern int main(int argc, char *argv[])

{
	int retn = 1,
	    index;

	Buffer bufr   = NULL,
	       key    = NULL,
	       uuid   = NULL,
	       pcrref = NULL,
	       nonce  = NULL;

	TPM2cmd tpmcmd = NULL;

	File quote = NULL;

	RandomBuffer rbufr = NULL;


	if ( argv[1] == NULL ) {
		fputs("No TPM2 command specified.\n", stdout);
		goto done;
	}

	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(HurdLib, Buffer, key, goto done);
	INIT(NAAAIM, TPM2cmd, tpmcmd, goto done);


	if ( strcmp(argv[1], "hash") == 0 ) {
		if ( argv[2] == NULL ) {
			fputs("No hash input specified.\n", stderr);
			goto done;
		}

		if ( !bufr->add(bufr, (unsigned char *) argv[2], \
				strlen(argv[2])) )
		     ERR(goto done);
		if ( !tpmcmd->hash(tpmcmd, bufr) ) {
			fputs("Failed hash operation.\n", stderr);
			goto done;
		}

		fputs("hash: ", stdout);
		bufr->print(bufr);

		retn = 0;
		goto done;
	}

	if ( strcmp(argv[1], "pcrread") == 0 ) {
		if ( argv[2] == NULL ) {
			fputs("No PCR register specified.\n", stderr);
			goto done;
		}
		index = strtol(argv[2], NULL, 10);
                if ( errno == ERANGE )
                        goto done;
                if ( index < 0 )
                        goto done;

		if ( !tpmcmd->pcr_read(tpmcmd, index, bufr) ) {
			fputs("Failed PCR read.\n", stderr);
			goto done;
		}

		fprintf(stdout, "PCR-%02d: ", index);
		bufr->print(bufr);

		retn = 0;
		goto done;
	}

	if ( strcmp(argv[1], "lspcr") == 0 ) {
		size_t lp;


		for(index=0; index < IMPLEMENTATION_PCR; ++index) {
			if ( !tpmcmd->pcr_read(tpmcmd, index, bufr) ) {
				fputs("Failed PCR read.\n", stderr);
				goto done;
			}

			fprintf(stdout, "PCR-%02d: ", index);
			for (lp= 0; lp < bufr->size(bufr); ++lp)
				fprintf(stdout, "%02X ", \
					*(bufr->get(bufr) + lp));
			fputc('\n', stdout);
			bufr->reset(bufr);
		}

		retn = 0;
		goto done;
	}

	if ( strcmp(argv[1], "pcrextend") == 0 ) {
		if ( argv[2] == NULL ) {
			fputs("No PCR register specified.\n", stderr);
			goto done;
		}
		index = strtol(argv[2], NULL, 10);
                if ( errno == ERANGE )
                        goto done;
                if ( index < 0 )
                        goto done;

		if ( argv[3] == NULL ) {
			fputs("No extension string specified.\n", stderr);
			goto done;
		}
		if ( !bufr->add(bufr, (unsigned char *) argv[3], \
				strlen(argv[3])) )
			goto done;

		if ( !tpmcmd->pcr_extend(tpmcmd, index, bufr) ) {
			fputs("Failed extend.\n", stderr);
			goto done;
		}
		fprintf(stdout, "Extended PCR-%02d: ", index);
		bufr->print(bufr);

		retn = 0;
		goto done;
	}


	if ( strcmp(argv[1], "nvdefine") == 0 ) {
		uint32_t size = 0,
			 auth = 0;

		Buffer pwd = NULL;

		if ( argv[2] == NULL ) {
			fputs("No NVram index specified.\n", stderr);
			goto done;
		}
		index = strtol(argv[2], NULL, 0);
                if ( errno == ERANGE )
                        goto done;
                if ( index < 0 )
                        goto done;

		if ( argc == 3 ) {
			fputs("No NVram size specified.\n", stderr);
			goto done;
		}
		size = strtol(argv[3], NULL, 0);
                if ( errno == ERANGE )
                        goto done;
                if ( size < 0 )
                        goto done;

		if ( argc == 5 ) {
			if ( !key->add(key, (unsigned char *) argv[4], \
				       strlen(argv[4])) )
				goto done;
			if ( !key->add(key, (unsigned char *) "\0", 1) )
				goto done;
			pwd = key;
		}


		/* Standard attributes. */
#if 1
		auth  = TPMA_NVA_NO_DA;
		auth |= TPMA_NVA_AUTHREAD;
		auth |= TPMA_NVA_AUTHWRITE;
#endif

		/* Platform owner attributes. */
#if 0
		fputs("Setting PO attributes.\n", stderr);
		auth  = TPMA_NVA_NO_DA;
		auth |= TPMA_NVA_OWNERWRITE;
		auth |= TPMA_NVA_POLICYWRITE;
		auth |= TPMA_NVA_AUTHREAD;
#endif

		/* AUX attributes. */
#if 0
		fputs("Setting AUX attributes.\n", stderr);
		auth  = TPMA_NVA_NO_DA;

		auth |= TPMA_NVA_POLICYWRITE;
		auth |= TPMA_NVA_POLICY_DELETE;
		auth |= TPMA_NVA_WRITE_STCLEAR;

		auth |= TPMA_NVA_AUTHREAD;

		auth |= TPMA_NVA_PLATFORMCREATE;
#endif

		if ( !tpmcmd->nv_define(tpmcmd, index, size, auth, pwd, \
					NULL) )
			goto done;

		retn = 0;
		goto done;
	}


	if ( strcmp(argv[1], "nvread") == 0 ) {
		if ( argv[2] == NULL ) {
			fputs("No NVram index specified.\n", stderr);
			goto done;
		}
		index = strtol(argv[2], NULL, 0);
                if ( errno == ERANGE )
                        goto done;
                if ( index < 0 )
                        goto done;

		if ( !tpmcmd->nv_read(tpmcmd, index, bufr) )
			goto done;
		fprintf(stdout, "Contents of NVram index: 0x%x/%d\n", index, \
			index);
		bufr->hprint(bufr);

		retn = 0;
		goto done;
	}


	if ( strcmp(argv[1], "nvwrite") == 0 ) {
		if ( argv[2] == NULL ) {
			fputs("No NVram index specified.\n", stderr);
			goto done;
		}
		index = strtol(argv[2], NULL, 0);
                if ( errno == ERANGE )
                        goto done;
                if ( index < 0 )
                        goto done;

		if ( argc == 3 ) {
			fputs("No NVram password specifed.\n", stderr);
			goto done;
		}
		if ( !key->add(key, (unsigned char *) argv[3], \
			       strlen(argv[3])) )
			goto done;
		if ( !key->add(key, (unsigned char *) "\0", 1) )
			goto done;

		if ( argc == 4 ) {
			fputs("No NVram write string specified.\n", stderr);
			goto done;
		}
		if ( !bufr->add(bufr, (unsigned char *) argv[4], \
				strlen(argv[4])) )
			goto done;


		if ( !tpmcmd->nv_write(tpmcmd, index, bufr, NULL/*key*/) )
			goto done;
		fprintf(stdout, "Wrote NVram index: 0x%x/%d\n", index, \
			index);

		retn = 0;
		goto done;
	}


	if ( strcmp(argv[1], "nvremove") == 0 ) {
		index = strtol(argv[2], NULL, 0);
                if ( errno == ERANGE )
                        goto done;
                if ( index < 0 )
                        goto done;

		if ( argc == 3 ) {
			fputs("No NVram password specifed.\n", stderr);
			goto done;
		}
		if ( !key->add(key, (unsigned char *) argv[3], \
			       strlen(argv[3])) )
			goto done;
		if ( !key->add(key, (unsigned char *) "\0", 1) )
			goto done;

		if ( !tpmcmd->nv_remove(tpmcmd, index, key) ) {
			fputs("Failed to remove NVram area.\n", stderr);
			goto done;
		}
		fprintf(stdout, "Removed NVram area %0x\n", index);

		retn = 0;
		goto done;
	}


#if 0
	if ( strcmp(argv[1], "quote") == 0 ) {
		INIT(NAAAIM, RandomBuffer, rbufr, goto done);

		INIT(HurdLib, File, quote, goto done);
		if ( argc < 3 ) {
			fputs("No aik uuid specified.\n", stderr);
			fputs("Usage: tpm-cmd quote uuid [quote] [nonce]\n", \
			      stderr);
			goto done;
		}
		quote->open_ro(quote, argv[2]);
		if ( !quote->slurp(quote, key) ) {
			fputs("Error reading aid uuid.\n", stderr);
			goto done;
		}

		rbufr->generate(rbufr, 20);
		if ( !bufr->add_Buffer(bufr, rbufr->get_Buffer(rbufr)) ) {
			fputs("Unable to generate nonce.\n", stderr);
			goto done;
		}

		if ( !tpmcmd->pcrmask(tpmcmd, 10, 17, -1) ) {
			fputs("PCR masking failed.\n", stderr);
			goto done;
		}

		if ( !tpmcmd->quote(tpmcmd, key, bufr) ) {
			fputs("Quote failed.\n", stderr);
			goto done;
		}

		fputs("Quote:\n", stderr);
		bufr->hprint(bufr);
		if ( argc >= 4 ) {
			quote->reset(quote);
			if ( !quote->open_rw(quote, argv[3] ) ) {
				fputs("Cannot open quote output file.\n", \
				      stderr);
				goto done;
			}
			if ( !quote->write_Buffer(quote, bufr) ) {
				fputs("Error writing reference quote.\n", \
				      stderr);
				goto done;
			}
			fprintf(stdout, "Written to file: %s\n", argv[3]);
		}

		fputs("\nQuote nonce:\n", stderr);
		rbufr->get_Buffer(rbufr)->hprint(rbufr->get_Buffer(rbufr));
		if ( argc >= 5 ) {
			quote->reset(quote);
			if ( !quote->open_rw(quote, argv[4] ) ) {
				fputs("Cannot open quote nonce file.\n", \
				      stderr);
				goto done;
			}
			if ( !quote->write_Buffer(quote, \
						  rbufr->get_Buffer(rbufr)) ) {
				fputs("Error writing quote nonce.\n", \
				      stderr);
				goto done;
			}
			fprintf(stdout, "Quote nonce written to file: %s\n", \
				argv[4]);
		}

		retn = 0;
		goto done;
	}

	if ( strcmp(argv[1], "verify") == 0 ) {
		INIT(HurdLib, File, quote, goto done);

		if ( argc != 6 ) {
			fputs("Insufficient number of argements.\n", stderr);
			fputs("Usage: tpm-cmd pubkey pcrref nonce quote\n", \
			      stderr);
			goto done;
		}

		quote->open_ro(quote, argv[2]);
		if ( !quote->slurp(quote, key) ) {
			fputs("Error reading public key.\n", stderr);
			goto done;
		}

		INIT(HurdLib, Buffer, pcrref, goto done);
		quote->reset(quote);
		quote->open_ro(quote, argv[3]);
		if ( !quote->slurp(quote, pcrref) ) {
			fputs("Error reading PCR reference.\n", stderr);
			goto done;
		}

		INIT(HurdLib, Buffer, nonce, goto done);
		quote->reset(quote);
		quote->open_ro(quote, argv[4]);
		if ( !quote->slurp(quote, nonce) ) {
			fputs("Error reading quote nonce.\n", stderr);
			goto done;
		}

		quote->reset(quote);
		quote->open_ro(quote, argv[5]);
		if ( !quote->slurp(quote, bufr) ) {
			fputs("Error reading quote.\n", stderr);
			goto done;
		}

		if ( !tpmcmd->verify(tpmcmd, key, pcrref, nonce,
				     bufr) ) {
			fputs("Quote verification failed.\n", \
			      stderr);
			goto done;
		}
		else
			fputs("Machine status quote is valid.\n", stdout);

		retn = 0;
		goto done;
	}

	if ( strcmp(argv[1], "generate-quote") == 0 ) {
		INIT(NAAAIM, RandomBuffer, rbufr, goto done);

		INIT(HurdLib, File, quote, goto done);
		if ( argc < 3 ) {
			fputs("No aik uuid file specified.\n", stderr);
			fputs("Usage: tpm-cmd generate-quote uuid " \
			      "[refquote]\n", stderr);
			goto done;
		}
		quote->open_ro(quote, argv[2]);
		if ( !quote->slurp(quote, key) ) {
			fputs("Error reading aid uuid.\n", stderr);
			goto done;
		}

		rbufr->generate(rbufr, 20);
		if ( !bufr->add_Buffer(bufr, rbufr->get_Buffer(rbufr)) ) {
			fputs("Unable to generate nonce.\n", stderr);
			goto done;
		}

		if ( !tpmcmd->pcrmask(tpmcmd, 10, 17, -1) ) {
			fputs("PCR masking failed.\n", stderr);
			goto done;
		}

		if ( !tpmcmd->generate_quote(tpmcmd, key, bufr) ) {
			fputs("Generation of reference quote failed.\n", \
			      stderr);
			goto done;
		}

		fputs("Reference quote:\n", stderr);
		bufr->hprint(bufr);
		if ( argc >= 4 ) {
			quote->reset(quote);
			if ( !quote->open_rw(quote, argv[3]) ) {
				fputs("Cannot open quote output file.\n", \
				      stderr);
				goto done;
			}
			if ( !quote->write_Buffer(quote, bufr) ) {
				fputs("Error writing reference quote.\n", \
				      stderr);
				goto done;
			}
			fprintf(stdout, "Written to file: %s\n", argv[3]);
		}

		retn = 0;
		goto done;
	}

	if ( strcmp(argv[1], "generate-identity") == 0 ) {
		INIT(HurdLib, Buffer, pcrref, goto done);
		INIT(HurdLib, Buffer, uuid, goto done);
		INIT(HurdLib, File, quote, goto done);

		if ( argc < 3 ) {
			fputs("No password specified.\n", stderr);
			fputs("Usage: tpm-cmd pwd [pubkey] [idcert] " \
			      "[uuid]\n", stderr);
			goto done;
		}
		if ( !key->add(key, (unsigned char *) argv[2], \
			       strlen(argv[2])) )
			goto done;

		if ( !tpmcmd->generate_identity(tpmcmd, false, key, pcrref, \
						uuid, bufr) )
			goto done;

		fputs("key:\n", stdout);
		bufr->hprint(bufr);
		if ( argc >= 4 ) {
			quote->open_rw(quote, argv[3]);
			if ( !quote->write_Buffer(quote, bufr) ) {
				fputs("Unable to write public key file.\n", \
				      stderr);
				goto done;
			}
			fprintf(stdout, "Written to file: %s\n", argv[3]);
		}

		fputs("\ncertificate:\n", stdout);
		pcrref->hprint(pcrref);
		if ( argc >= 5 ) {
			quote->reset(quote);
			quote->open_rw(quote, argv[4]);
			if ( !quote->write_Buffer(quote, pcrref) ) {
				fputs("Unable to write certificate file.\n", \
				      stderr);
				goto done;
			}
			fprintf(stdout, "Written to file: %s\n", argv[4]);
		}

		fputs("\nuuid:\n", stdout);
		uuid->hprint(uuid);
		if ( argc >= 6 ) {
			quote->reset(quote);
			quote->open_rw(quote, argv[5]);
			if ( !quote->write_Buffer(quote, uuid) ) {
				fputs("Unable to write UUID.\n", stderr);
				goto done;
			}
			fprintf(stdout, "Written to file: %s\n", argv[5]);
		}

		retn = 0;
		goto done;
	}

	if ( strcmp(argv[1], "list-keys") == 0 ) {
		tpmcmd->list_keys(tpmcmd);

		retn = 0;
		goto done;
	}

	if ( strcmp(argv[1], "get-pubkey") == 0 ) {
		if ( argc != 3 ) {
			fputs("No key uuid specified.\n", stderr);
			goto done;
		}

		INIT(HurdLib, Buffer, uuid, goto done);
		if ( !uuid->add_hexstring(uuid, argv[2]) ) {
			fputs("Cannot set uuid.\n", stderr);
			goto done;
		}

		if ( !tpmcmd->get_pubkey(tpmcmd, uuid, key) ) {
			fputs("Unable to load public key.\n", stderr);
			goto done;
		}
		fputs("Public key for uuid: ", stdout);
		uuid->print(uuid);
		key->print(key);

		retn = 0;
		goto done;
	}
#endif
	if ( strcmp(argv[1], "get-time") == 0 ) {
		uint64_t current_time, clock_time;

		uint32_t reset, restart;

		_Bool safe;


		tpmcmd->get_time(tpmcmd, &current_time, &clock_time, &reset, \
				 &restart, &safe);

		/* Dump parameters for now. */
		fprintf(stdout, "Time: %lu\n", current_time);
		fputs("\nClock info:\n", stdout);
		fprintf(stdout, "\tclock: %lu\n", clock_time);
		fprintf(stdout, "\tresetCount: %u\n", reset);
		fprintf(stdout, "\trestartCount: %u\n", restart);
		fprintf(stdout, "\tsafe: %u\n", safe);

		retn = 0;
		goto done;
	}

	if ( strcmp(argv[1], "get-error") == 0 ) {
		if ( argc != 3 ) {
			fputs("No error code specified.\n", stderr);
			goto done;
		}

		index = strtol(argv[2], NULL, 0);
                if ( errno == ERANGE )
                        goto done;
                if ( index < 0 )
                        goto done;

		tpmcmd->get_error(tpmcmd, index);

		retn = 0;
		goto done;
	}

	fprintf(stderr, "Unknown command: %s\n", argv[1]);


 done:
	WHACK(bufr);
	WHACK(key);
	WHACK(pcrref);
	WHACK(uuid);
	WHACK(nonce);
	WHACK(tpmcmd);
	WHACK(quote);
	WHACK(rbufr);

	return retn;
}
