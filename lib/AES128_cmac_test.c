/** \file
 * This file implements a unit test for the AES128_cmac object.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include <HurdLib.h>
#include <Buffer.h>

#include <NAAAIM.h>
#include "AES128_cmac.h"


/**
 * Key for test vector.
 */
const static uint8_t Key[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, \
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c 	\
};


/**
 * Test message.
 */
const static uint8_t Message[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, \
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a  \
};


/**
 * Expected MAC value.
 */
const static uint8_t Mac[] = {
	0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, \
	0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
};


extern int main(int argc, char *argv[])

{
	int retn = 1;

	Buffer bufr = NULL;

	AES128_cmac cmac = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, Key, sizeof(Key)) )
		ERR(goto done);

	INIT(NAAAIM, AES128_cmac, cmac, ERR(goto done));
	if ( !cmac->set_key(cmac, bufr) )
		ERR(goto done);
	if ( !cmac->add(cmac, Message, sizeof(Message)) )
		ERR(goto done);
	if ( !cmac->compute(cmac) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !bufr->add_Buffer(bufr, cmac->get_Buffer(cmac)) )
		ERR(goto done);

	fputs("CMAC: ", stdout);
	bufr->print(bufr);

	bufr->reset(bufr);
	bufr->add(bufr, Mac, sizeof(Mac));
	fputs("Expected: ", stdout);
	bufr->print(bufr);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(cmac);

	return retn;
}
