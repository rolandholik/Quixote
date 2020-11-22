/** \file
 * This file implements defintions to provide enclave based support for
 * functionality which is available when the <arpa/inet.h> standard
 * C library header is included.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* 16-bit endian translation function. */
extern uint16_t htons(uint16_t);
extern uint16_t ntohs(uint16_t);


/* 32-bit endian translation functions. */
extern uint32_t htonl(uint32_t);
extern uint32_t ntohl(uint32_t);
