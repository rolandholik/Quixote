/** \file
 * This file is designed to provide implementations for enclave based
 * support for functionality which is defined when the <arpa/inet.h>
 * file is included.
 */

/**************************************************************************
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


#include <stdint.h>
#include "arpa/inet.h"


/* 16-bit endian translation functions. */
uint16_t ntohs(uint16_t value)

{
	return value << 8 | value >> 8;
}

uint16_t htons(uint16_t value)

{
	return value << 8 | value >> 8;
}


/* 32-bit endian translation functions. */
uint32_t htonl(uint32_t value)

{
	return value >> 24 | (value >> 8 & 0xff00) \
		|  (value << 8 & 0xff0000) | value << 24;
}

uint32_t ntohl(uint32_t value)

{
	return value >> 24 | (value >> 8 & 0xff00) \
		|  (value << 8 & 0xff0000) | value << 24;
}
