/** \file
 * This file implements the identity manager daemon.  This daemon is
 * responsible for loading the device identity and extending the
 * measurement statement of the platform with that identity.
 *
 * The manager daemon provides OTI services to clients which request
 * the generation of a one time encryption key based on the device
 * identity.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define IDENTITY "/mnt/boot/device.idt"
#define IDCOUNT 10

#define IDENTITY_NV_INDEX 0xbeaf
#define IDENTITY_PCR 15


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <glob.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <IDtoken.h>
#include <SHA256.h>
#include <IDmgr.h>
#include <TPMcmd.h>


/* Static variable definitions. */
struct {
	_Bool sigusr1;
	_Bool sigint;
} signals;


unsigned int IDcnt = 0;
struct {
	String name;
	IDtoken token;
} IDarray[IDCOUNT];


/**
 * Private function.
 *
 * This function is responsible for adding an entry into the IDarray
 * array.  This array associates the name of an identity with the
 * reduced version of an identity.
 *
 * \param name		The name of the identity to be stored.
 *
 * \param idtoken	The identity to be associated with the name.  The
 *			identity is in reduced form.
 *
 * \return		A false value is returned if storing of the
 *			identity fails.  If the identity is successfully
 *			storage a true value is returned.
 */

static _Bool save_identity(CO(String, name), CO(IDtoken, idtoken))

{
	/* Verify arguement status. */
	if ( (name == NULL) || name->poisoned(name) )
		return false;
	if ( idtoken == NULL )
		return false;

	/* Verify the identity array is not full. */
	if ( IDcnt == (IDCOUNT - 1) )
		return false;

	/* Save the name and the identity. */
	IDarray[IDcnt].name  = name;
	IDarray[IDcnt].token = idtoken;
	++IDcnt;

	return true;
}


/**
 * Private function.
 *
 * This function is responsible for finding an identity in the set of
 * arrays under management.
 *
 * \param name		The name of the identity to be located.
 *
 * \return		If the named identity is located it is returned
 *			to the caller.  If the identity is not found
 *			a NULL value is returned.
 */

static IDtoken find_identity(CO(String, name))

{
	unsigned int lp;

	String nm;


	if ( (name == NULL) || name->poisoned(name) )
		return NULL;

	for (lp= 0; lp < IDcnt; ++lp) {
		nm = IDarray[lp].name;
		if ( strcmp(name->get(name), nm->get(nm)) == 0 )
			return IDarray[lp].token;
	}

	return NULL;
}


/**
 * Private function.
 *
 * This function is responsible for freeing the objects which have
 * been stored in the identity array.
 *
 * \return	No return values have been defined.
 */

static IDtoken free_identities(void)

{
	unsigned int lp;


	for (lp= 0; lp < IDcnt; ++lp) {
		WHACK(IDarray[lp].name);
		WHACK(IDarray[lp].token);
	}

	return NULL;
}


/**
 * Private function.
 *
 * This function is responsible for checking for the presence of
 * a device identity on the root filesystem and loading it into
 * NVram if it is authentic.
 *
 * \param identity	The token which contains the implementation of
 *			the device's identity.
 *
 * \return		A false value indicates the identity was not
 *			properly initialized.  A true value indicates
 *			the machine identity state is properly initialized.
 */

static _Bool load_identity(CO(IDtoken, identity))

{
	_Bool retn = false;

	char *err = NULL;

	struct stat idfile;

	Buffer bufr = NULL;

	TPMcmd tpm = NULL;


	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(NAAAIM, TPMcmd, tpm, goto done);

	tpm->pcr_read(tpm, 10, bufr);
	tpm->pcr_extend(tpm, IDENTITY_PCR, bufr);

	bufr->reset(bufr);
	tpm->pcr_read(tpm, 17, bufr);
	tpm->pcr_extend(tpm, IDENTITY_PCR, bufr);

	bufr->reset(bufr);
	tpm->pcr_read(tpm, 18, bufr);
	if ( !tpm->pcr_extend(tpm, IDENTITY_PCR, bufr) ) {
		err = "Cannot pre-extend PCR identity register.";
		goto done;
	}


	/* Check to see if the load of an identity has been requested. */
	if ( stat(IDENTITY, &idfile) == -1 ) {
		if ( errno == ENOENT ) {
			retn = true;
			goto done;
		}
	}

	if ( system("/sbin/id-set " IDENTITY) != 0 )
		goto done;
	retn = true;


 done:
	WHACK(bufr);
	WHACK(tpm);

	if ( err != NULL ) {
		fprintf(stderr, "%s\n", err);
		return false;
	}

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for initializating the identity of
 * the device.
 *
 * This is done by doing the following extension into PCR 19:
 *
 *	PCR10 || PCR17 || PCR18 || IdentityImplementation
 *
 * \param identity	The token which contains the implementation of
 *			the device's identity.
 *
 * \return		A false value indicates the identity was not
 *			properly initialized.  A true value indicates
 *			the machine identity state is properly initialized.
 */

static _Bool initialize_device_identity(CO(IDtoken, identity))

{
	char *err = NULL;

	Buffer bufr = NULL;

	TPMcmd tpm = NULL;


	INIT(NAAAIM, TPMcmd, tpm, goto done);
	INIT(HurdLib, Buffer, bufr, goto done);
	
	if ( !tpm->nv_read(tpm, IDENTITY_NV_INDEX, bufr) ) {
		err = "Unable to read NVram.";
		goto done;
	}
	if ( !identity->decode(identity, bufr) ) {
		err = "unable to decode identity.";
		goto done;
	}

	bufr->add_Buffer(bufr, identity->get_element(identity, IDtoken_id));
	if ( !tpm->pcr_extend(tpm, IDENTITY_PCR, bufr) ) {
		err = "Cannot extend PCR identity register.";
		goto done;
	}

 done:
	WHACK(tpm);
	WHACK(bufr);

	if ( err != NULL ) {
		fprintf(stderr, "%s\n", err);
		return false;
	}
	return true;
}


/**
 * Private function.
 *
 * This function is responsible for loading and saving the device
 * identity.  The device identity is a special case since its
 * implementation is used to extend the attestation state of the
 * device.
 *
 * \return	A false value indicates the device identity was not
 *		properly loaded.  A true value indicates the identity
 *		was not loaded.
 */

static _Bool load_device_identity(void)

{
	_Bool retn = false;

	String name = NULL;

	IDtoken identity = NULL;


	INIT(NAAAIM, IDtoken, identity, goto done);

	if ( !load_identity(identity) )
		goto done;

	if ( !initialize_device_identity(identity) )
		goto done;

	if ( !identity->to_verifier(identity) )
		goto done;

	if ( (name = HurdLib_String_Init_cstr("device")) == NULL )
		goto done;
	if ( !save_identity(name, identity) )
		goto done;
	retn = true;


 done:
	if ( !retn ) {
		WHACK(name);
		WHACK(identity);
	}

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for loading any service identities
 * which are available on the configuration filesystem.  Any files
 * which have an .idt suffix are loaded into the identity manager.
 * The basename of the identity is used as the search name for the
 * identity.
 *
 * \return	A false value indicates an error was encountered while
 *		loading the cohort of identities.  A true value
 *		indicates the identities were successfully loaded.
 */

static _Bool load_service_identities(void)

{
	_Bool retn    = false,
	      globbed = false;

	char *p,
	     *fname;

	int gretn;

	unsigned int lp;

	glob_t identities;

	FILE *idfile = NULL;

	String name = NULL;

	IDtoken identity = NULL;


	if ( (gretn = glob("/etc/conf/identities/*.idt", 0, NULL, \
			   &identities)) != 0 ) {
		if ( gretn == GLOB_NOMATCH )
			retn = true;
		goto done;
	}
	globbed = true;

	for (lp= 0; lp < identities.gl_pathc; ++lp) {
		if ( (idfile = fopen(identities.gl_pathv[lp], "r")) == NULL )
			goto done;

		INIT(NAAAIM, IDtoken, identity, goto done);
		if ( !identity->parse(identity, idfile) )
			goto done;
		fclose(idfile);
		idfile = NULL;
		if ( unlink(identities.gl_pathv[lp]) != 0 ) {
			fputs("Failed device unlink.\n", stderr);
			goto done;
		}

		if ( !identity->to_verifier(identity) )
			goto done;

		INIT(HurdLib, String, name, goto done);
		if ( (fname = strrchr(identities.gl_pathv[lp], '/')) != NULL )
			++fname;
		else
			fname = identities.gl_pathv[lp];
		if ( (p = strchr(fname, '.')) != NULL )
			*p = '\0';
		if ( !name->add(name, fname) )
			goto done;

		if ( !save_identity(name, identity) )
			goto done;

		name	 = NULL;
		identity = NULL;
	}
	retn = true;


 done:
	if ( idfile != NULL )
		fclose(idfile);
	if ( globbed )
		globfree(&identities);

	WHACK(name);
	WHACK(identity);

	return retn;
}


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
			signals.sigusr1 = true;
			break;
		case SIGINT:
			signals.sigint = true;
			break;
	}

	return;
}
		


/**
 * Private function.
 *
 * This function is responsible for implementing the identity manager
 * processing loop.  This function loops endlessly waiting for a
 * SIGUSR1 signal.  When it receives a signal it reads the request
 * for generation of an OTI key from the idmgr shared memory array
 * and writes the result back into the output area.
 *
 * \return		No return value is specified.
 */

static void identity_manager(void)

{
	struct sigaction signal_action;

	String name = NULL;

	IDtoken identity,
		null = NULL;

	IDmgr idmgr = NULL;


	INIT(HurdLib, String, name, goto done);
	INIT(NAAAIM, IDtoken, null, goto done);

	INIT(NAAAIM, IDmgr, idmgr, goto done);
	if ( !idmgr->setup(idmgr) )
		goto done;

	if ( sigemptyset(&signal_action.sa_mask) == -1 )
		goto done;
	signal_action.sa_flags = 0;
	signal_action.sa_handler = signal_handler;

	if ( sigaction(SIGUSR1, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGINT, &signal_action, NULL) == -1 )
		goto done;

	while ( 1 ) {
		pause();
		if ( signals.sigint )
			goto done;

		idmgr->get_idname(idmgr, name);
		if ( (identity = find_identity(name)) == NULL )
			identity = null;

		switch ( idmgr->get_idtype(idmgr) ) {
			case IDmgr_none:
				break;
			case IDmgr_token:
				if ( !idmgr->set_idtoken(idmgr, identity) )
					goto done;
			case IDmgr_idhash:
				if ( !idmgr->set_id_key(idmgr, identity) )
					goto done;
		}

		signals.sigint = false;
		name->reset(name);
	}

 done:
	WHACK(name);
	WHACK(null);
	WHACK(idmgr);

	return;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;


	if ( !load_device_identity() )
		goto done;
	if ( !load_service_identities() )
		goto done;

	identity_manager();
	retn = 0;


 done:
	free_identities();

	return retn;
}
