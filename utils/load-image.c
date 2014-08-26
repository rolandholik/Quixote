/** \file
 * This file implements loading a block device from an encrypted
 * file system image.  The encrypted image is created with the
 * gen-root utility.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
/* Size of the header/trailer records in bytes. */
#define HEADER_SIZE	16
#define CHECKSUM_SIZE	32

/* Size of the encryption key. */
#define KEY_SIZE 32

/*
 * Offset into header of payload length, must be a value between 0 and
 * AES_BLOCKSIZE - sizeof(network long).
 */
#define FIELD_OFFSET 7


/* Include files. */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mount.h>
#include <errno.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <tpm_tspi.h>
#include <tpm_unseal.h>

#include "NAAAIM.h"
#include "AES256_cbc.h"
#include "SHA256_hmac.h"


/* Module specific static variables. */

/* Password. */
#if 0
static unsigned char Pwd[] = {
	0x59, 0x55, 0xd5, 0xf7, 0xf7, 0x40, 0x62, 0xb3, \
	0x00, 0xad, 0x3e, 0x16, 0xa3, 0x77, 0x95, 0x98, \
	0x5f, 0xcf, 0x9e, 0x81, 0x1f, 0x49, 0x6a, 0xb4, \
	0x77, 0xa4, 0xae, 0xce, 0xa0, 0x41, 0x24, 0xb4
};

static unsigned char Iv[] = {
	0x70, 0xa6, 0xba, 0x87, 0xdf, 0x1f, 0x32, 0x9e, \
	0x1f, 0x69, 0x50, 0xa6, 0x5f, 0x0c, 0x78, 0xf1
};
#endif


/**
 * Private function.
 *
 * This function is responsible for loading the encryption key and
 * initialization vector.
 *
 * \param fname		A pointer to a character buffer containing the
 *			name of the file containing the keys.
 *
 * \param iv		A Buffer object which will be loaded with the
 *			initialization vector.
 *
 * \param key		A Buffer object which will be loaded with the
 *			encryption key.
 *
 * \parm uid		The user identity under which the encrypted
 *			filesystem image is to be read if it is
 *			different then the current id.
 *
 * \return              A boolean return value is used to indicate
 *			whether or not the keys were successfully
 *			loaded.  A true value indicates success while
 *			a false value indicates a failure.
 */

static _Bool load_keys(CO(char *, fname), CO(Buffer, iv), CO(Buffer, key), \
		       uid_t uid)

{
	_Bool retn	 = false,
	      changed_id = false;

	File file;


	if ( getuid() != uid ) {
		if ( setreuid(uid, -1) == -1 )
			goto done;
		changed_id = true;
	}

	INIT(HurdLib, File, file, return false);
	file->open_ro(file, fname);
	file->read_Buffer(file, iv, HEADER_SIZE);
	file->read_Buffer(file, key, 0);

	retn = !file->poisoned(file) && !iv->poisoned(iv) && \
		!key->poisoned(key);

	if ( changed_id ) {
		if ( setreuid(geteuid(), -1) == -1 )
			retn = false;
	}


 done:
	WHACK(file);
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for extrcting the encryption and
 * initialization vectors from a TPM sealed key.
 *
 *
 * \param fname		A pointer to a character buffer containing the
 *			name of the file containing the TPM sealed
 *			keys.
 *
 * \param iv		A Buffer object which will be loaded with the
 *			initialization vector.
 *
 * \param key		A Buffer object which will be loaded with the
 *			encryption key.
 *
 * \parm uid		The user identity under which the encrypted
 *			filesystem image is to be read if it is
 *			different then the current id.
 *
 * \return              A boolean return value is used to indicate
 *			whether or not the keys were successfully
 *			loaded.  A true value indicates success while
 *			a false value indicates a failure.
 */

static _Bool load_tpm_keys(char * fname, CO(Buffer, iv), CO(Buffer, key), \
			   uid_t uid)

{
	_Bool retn	 = false,
	      changed_id = false;

	int tpm_retn,
	    key_size;

	unsigned char *key_data;


	if ( getuid() != uid ) {
		if ( setreuid(uid, -1) == -1 )
			goto done;
		changed_id = true;
	}

	tpm_retn = tpmUnsealFile(fname, &key_data, &key_size, true);
	if ( tpm_retn == 0 ) {
		iv->add(iv, key_data, HEADER_SIZE);
		key->add(key, key_data + HEADER_SIZE, KEY_SIZE);
		retn = true;
	}

	if ( changed_id ) {
		if ( setreuid(geteuid(), -1) == -1 )
			retn = false;
	}


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for loading the encrypted image into
 * a buffer supplied by the caller. 
 *
 * \param payload	A character pointer to the name of the file
 *			to be loaded.
 *
 * \param image		A Buffer object into which the encrypted
 *			filesystem image is to be loaded.
 *
 * \param iv		A Buffer object containing the initialization
 *			vector being used for the encryption.  This
 *			is used to shroud the image header.
 *
 * \param key		A Buffer object containing the key which will
 *			be used to authenticated the checksum on
 *			the image.
 *
 * \parm uid		The user identity under which the encrypted
 *			filesystem image is to be read if it is
 *			different then the current id.
 *
 * \return              A boolean return value is used to indicate
 *			whether or not the image was successfully
 *			loaded and authenticated.  A true value
 *			indicates success while a false value
 *			indicates a failure.
 */

static _Bool load_image(const char * const fname, CO(Buffer, image), \
			CO(Buffer, iv), CO(Buffer, key), uid_t uid)

{
	_Bool retn	 = false,
	      changed_id = false;

	unsigned char *ivp,
		      *hp;

	uint32_t size;

	size_t lp;

	off_t eof,
	      offset;

	File file = NULL;

	Buffer checksum = NULL;

	SHA256_hmac hmac = NULL;


	if ( getuid() != uid ) {
		if ( setreuid(uid, -1) == -1 )
			goto done;
		changed_id = true;
	}

	INIT(HurdLib, File, file, goto done);
	INIT(HurdLib, Buffer, checksum, goto done);

	if ( (hmac = NAAAIM_SHA256_hmac_Init(key)) == NULL )
		goto done;

	if ( !file->open_ro(file, fname) )
		goto done;

	file->read_Buffer(file, checksum, HEADER_SIZE);

	hp  = checksum->get(checksum);
	ivp = iv->get(iv);

	for(lp= 0; lp < iv->size(iv); ++lp)
		*(hp + lp) ^= *(ivp + lp);
	size = ntohl(*(uint32_t *)(checksum->get(checksum) + FIELD_OFFSET));
	for(lp= 0; lp < iv->size(iv); ++lp)
		*(hp + lp) ^= *(ivp + lp);

	eof = file->seek(file, -1);
	offset = eof - CHECKSUM_SIZE - size;
	offset = file->seek(file, offset);
	if ( !file->read_Buffer(file, image, size) ) {
		fputs("Failed read buffer.\n", stderr);
		goto done;
	}

	hmac->add_Buffer(hmac, checksum);
	hmac->add_Buffer(hmac, image);
	hmac->compute(hmac);

	checksum->reset(checksum);
	file->seek(file, eof - CHECKSUM_SIZE);
	file->read_Buffer(file, checksum, CHECKSUM_SIZE);
	if ( memcmp(hmac->get(hmac), \
		    checksum->get(checksum), CHECKSUM_SIZE) != 0 ) {
		fputs("Failed checksum.\n", stderr);
		goto done;
	}

	if ( !file->poisoned(file) && !image->poisoned(image) )
		retn = true;

 done:
	WHACK(file);
	WHACK(checksum);
	WHACK(hmac);

	if ( changed_id ) {
		if ( setreuid(geteuid(), -1) == -1 )
			retn = false;
	}

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible setting up and loading the decrypted
 * filesystem image into the new root device.
 *
 * \param device	A character buffer containing the name of the
 *			block device which is to hold the root
 *			filesystem.
 *
 * \param image		A pointer to a Buffer oject containing the
 *			filesystem image.
 *
 * \return              If the device is successfully setup and
 *			initialized a true value is returned.  Otherwise
 *			a false value is returned.
 */

static _Bool load_filesystem(CO(char *, fname), CO(Buffer, image))

{
	_Bool retn = false;

	File device = NULL;


	INIT(HurdLib, File, device, return false);

	if ( strncmp(fname, "/dev/hpd", 8) == 0 ) {
		Buffer fs;
		char cmd[11];
		size_t block_size;

		INIT(HurdLib, Buffer, fs, goto done);

		block_size = image->size(image) / (2 * 1024 * 1024);
		if ( (image->size(image) % (2 * 1024 * 1024)) != 0 )
			++block_size;
		block_size *= (2 * 1024 * 1024);
		if ( snprintf(cmd, sizeof(cmd), "%zu\n", block_size) >= \
		     sizeof(cmd) ) {
			WHACK(fs);
			goto done;
		}
		fs->add(fs, (unsigned char *) cmd, strlen(cmd));

		device->open_wo(device, "/sys/fs/hpd/create");
		device->write_Buffer(device, fs);
		WHACK(fs);

		if ( device->poisoned(device) )
			goto done;
		device->reset(device);
	}

	device->open_rw(device, fname);
	device->write_Buffer(device, image);
	if ( !device->poisoned(device) )
		retn = true;


 done:
	WHACK(device);
	return retn;
}
     
	
/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool tpm_key = false;

	int retn = false;

	char *boot_image = NULL,
	     *key_file	 = NULL,
	     *output	 = NULL,
	     *user	 = NULL;

	uid_t uid = getuid();

	File file = NULL;

	Buffer image	 = NULL,
	       decrypted = NULL,
	       iv	 = NULL,
	       key	 = NULL;

	AES256_cbc cipher = NULL;


	/* Get the root image and passwd file name. */
	while ( (retn = getopt(argc, argv, "k:r:to:u:")) != EOF )
		switch ( retn ) {
			case 'k':
				key_file = optarg;
				break;
			case 'r':
				boot_image = optarg;
				break;
			case 't':
				tpm_key = true;
				break;
			case 'o':
				output = optarg;
				break;
			case 'u':
				user = optarg;
				break;
		}

	if ( boot_image == NULL ) {
		fputs("No filesystem image specified.\n", stderr);
		return 1;
	}
	if ( key_file == NULL ) {
		fputs("No keyfile specified.\n", stderr);
		return 1;
	}
	if ( output == NULL ) {
		fputs("No output file specified.\n", stderr);
		return 1;
	}
	if ( user != NULL ) {
		uid = strtol(user, NULL, 10);
		if ( errno == ERANGE )
			goto done;
		if ( user < 0 )
			goto done;
	}

	INIT(HurdLib, Buffer, image, goto done);
	INIT(HurdLib, Buffer, key, goto done);
	INIT(HurdLib, Buffer, iv, goto done);

	if ( !tpm_key ) {
		if ( !load_keys(key_file, iv, key, uid) ) {
			fputs("Cannot load keys.\n", stderr);
			goto done;
		}
	}
	else {
		if ( !load_tpm_keys(key_file, iv, key, uid) ) {
			fputs("Cannot load tpm keys.\n", stderr);
			goto done;
		}
	}

	if ( !load_image(boot_image, image, iv, key, uid) ) {
		fputs("Cannot load filesystem image.\n", stderr);
		goto done;
	}


	if ( (cipher = NAAAIM_AES256_cbc_Init_decrypt(key, iv)) == NULL ) {
		fputs("Cannot initialize decryptor.\n", stderr);
		goto done;
	}
	if ( (decrypted = cipher->decrypt(cipher, image)) == NULL ) {
		fputs("Failed decryption.\n", stderr);
		goto done;
	}

	retn = load_filesystem(output, decrypted);


 done:
	WHACK(key);
	WHACK(iv);
	WHACK(image);
	WHACK(file);
	WHACK(cipher);

	return retn ? 0 : 1;
}
