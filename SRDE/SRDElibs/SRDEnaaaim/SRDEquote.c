/** \file
 * This file implements methods which encapsulate the OCALL's needed
 * to implement remote attestation quote processing via a SRDEquote
 * object running in untrusted userspace.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#define IAS_VERSION "3"


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>

#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include "NAAAIM.h"
#include "RSAkey.h"
#include "X509cert.h"
#include "SRDE.h"
#include "SRDEquote.h"
#include "Base64.h"


/* Object state extraction macro. */
#define STATE(var) CO(SRDEquote_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SRDEquote_OBJID)
#error Object identifier not defined.
#endif


/**
 * The Intel attestation root certificate.
 */
static const uint8_t IntelCA[1895] = {
	0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, \
	0x49, 0x4e, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, \
	0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, \
	0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x46, \
	0x53, 0x7a, 0x43, 0x43, 0x41, 0x37, 0x4f, 0x67, \
	0x41, 0x77, 0x49, 0x42, 0x41, 0x67, 0x49, 0x4a, \
	0x41, 0x4e, 0x45, 0x48, 0x64, 0x6c, 0x30, 0x79, \
	0x6f, 0x37, 0x43, 0x55, 0x4d, 0x41, 0x30, 0x47, \
	0x43, 0x53, 0x71, 0x47, 0x53, 0x49, 0x62, 0x33, \
	0x44, 0x51, 0x45, 0x42, 0x43, 0x77, 0x55, 0x41, \
	0x4d, 0x48, 0x34, 0x78, 0x43, 0x7a, 0x41, 0x4a, \
	0x42, 0x67, 0x4e, 0x56, 0x0a, 0x42, 0x41, 0x59, \
	0x54, 0x41, 0x6c, 0x56, 0x54, 0x4d, 0x51, 0x73, \
	0x77, 0x43, 0x51, 0x59, 0x44, 0x56, 0x51, 0x51, \
	0x49, 0x44, 0x41, 0x4a, 0x44, 0x51, 0x54, 0x45, \
	0x55, 0x4d, 0x42, 0x49, 0x47, 0x41, 0x31, 0x55, \
	0x45, 0x42, 0x77, 0x77, 0x4c, 0x55, 0x32, 0x46, \
	0x75, 0x64, 0x47, 0x45, 0x67, 0x51, 0x32, 0x78, \
	0x68, 0x63, 0x6d, 0x45, 0x78, 0x47, 0x6a, 0x41, \
	0x59, 0x42, 0x67, 0x4e, 0x56, 0x0a, 0x42, 0x41, \
	0x6f, 0x4d, 0x45, 0x55, 0x6c, 0x75, 0x64, 0x47, \
	0x56, 0x73, 0x49, 0x45, 0x4e, 0x76, 0x63, 0x6e, \
	0x42, 0x76, 0x63, 0x6d, 0x46, 0x30, 0x61, 0x57, \
	0x39, 0x75, 0x4d, 0x54, 0x41, 0x77, 0x4c, 0x67, \
	0x59, 0x44, 0x56, 0x51, 0x51, 0x44, 0x44, 0x43, \
	0x64, 0x4a, 0x62, 0x6e, 0x52, 0x6c, 0x62, 0x43, \
	0x42, 0x54, 0x52, 0x31, 0x67, 0x67, 0x51, 0x58, \
	0x52, 0x30, 0x5a, 0x58, 0x4e, 0x30, 0x0a, 0x59, \
	0x58, 0x52, 0x70, 0x62, 0x32, 0x34, 0x67, 0x55, \
	0x6d, 0x56, 0x77, 0x62, 0x33, 0x4a, 0x30, 0x49, \
	0x46, 0x4e, 0x70, 0x5a, 0x32, 0x35, 0x70, 0x62, \
	0x6d, 0x63, 0x67, 0x51, 0x30, 0x45, 0x77, 0x49, \
	0x42, 0x63, 0x4e, 0x4d, 0x54, 0x59, 0x78, 0x4d, \
	0x54, 0x45, 0x30, 0x4d, 0x54, 0x55, 0x7a, 0x4e, \
	0x7a, 0x4d, 0x78, 0x57, 0x68, 0x67, 0x50, 0x4d, \
	0x6a, 0x41, 0x30, 0x4f, 0x54, 0x45, 0x79, 0x0a, \
	0x4d, 0x7a, 0x45, 0x79, 0x4d, 0x7a, 0x55, 0x35, \
	0x4e, 0x54, 0x6c, 0x61, 0x4d, 0x48, 0x34, 0x78, \
	0x43, 0x7a, 0x41, 0x4a, 0x42, 0x67, 0x4e, 0x56, \
	0x42, 0x41, 0x59, 0x54, 0x41, 0x6c, 0x56, 0x54, \
	0x4d, 0x51, 0x73, 0x77, 0x43, 0x51, 0x59, 0x44, \
	0x56, 0x51, 0x51, 0x49, 0x44, 0x41, 0x4a, 0x44, \
	0x51, 0x54, 0x45, 0x55, 0x4d, 0x42, 0x49, 0x47, \
	0x41, 0x31, 0x55, 0x45, 0x42, 0x77, 0x77, 0x4c, \
	0x0a, 0x55, 0x32, 0x46, 0x75, 0x64, 0x47, 0x45, \
	0x67, 0x51, 0x32, 0x78, 0x68, 0x63, 0x6d, 0x45, \
	0x78, 0x47, 0x6a, 0x41, 0x59, 0x42, 0x67, 0x4e, \
	0x56, 0x42, 0x41, 0x6f, 0x4d, 0x45, 0x55, 0x6c, \
	0x75, 0x64, 0x47, 0x56, 0x73, 0x49, 0x45, 0x4e, \
	0x76, 0x63, 0x6e, 0x42, 0x76, 0x63, 0x6d, 0x46, \
	0x30, 0x61, 0x57, 0x39, 0x75, 0x4d, 0x54, 0x41, \
	0x77, 0x4c, 0x67, 0x59, 0x44, 0x56, 0x51, 0x51, \
	0x44, 0x0a, 0x44, 0x43, 0x64, 0x4a, 0x62, 0x6e, \
	0x52, 0x6c, 0x62, 0x43, 0x42, 0x54, 0x52, 0x31, \
	0x67, 0x67, 0x51, 0x58, 0x52, 0x30, 0x5a, 0x58, \
	0x4e, 0x30, 0x59, 0x58, 0x52, 0x70, 0x62, 0x32, \
	0x34, 0x67, 0x55, 0x6d, 0x56, 0x77, 0x62, 0x33, \
	0x4a, 0x30, 0x49, 0x46, 0x4e, 0x70, 0x5a, 0x32, \
	0x35, 0x70, 0x62, 0x6d, 0x63, 0x67, 0x51, 0x30, \
	0x45, 0x77, 0x67, 0x67, 0x47, 0x69, 0x4d, 0x41, \
	0x30, 0x47, 0x0a, 0x43, 0x53, 0x71, 0x47, 0x53, \
	0x49, 0x62, 0x33, 0x44, 0x51, 0x45, 0x42, 0x41, \
	0x51, 0x55, 0x41, 0x41, 0x34, 0x49, 0x42, 0x6a, \
	0x77, 0x41, 0x77, 0x67, 0x67, 0x47, 0x4b, 0x41, \
	0x6f, 0x49, 0x42, 0x67, 0x51, 0x43, 0x66, 0x50, \
	0x47, 0x52, 0x2b, 0x74, 0x58, 0x63, 0x38, 0x75, \
	0x31, 0x45, 0x74, 0x4a, 0x7a, 0x4c, 0x41, 0x31, \
	0x30, 0x46, 0x65, 0x75, 0x31, 0x57, 0x67, 0x2b, \
	0x70, 0x37, 0x65, 0x0a, 0x4c, 0x6d, 0x53, 0x52, \
	0x6d, 0x65, 0x61, 0x43, 0x48, 0x62, 0x6b, 0x51, \
	0x31, 0x54, 0x46, 0x33, 0x4e, 0x77, 0x6c, 0x33, \
	0x52, 0x6d, 0x70, 0x71, 0x58, 0x6b, 0x65, 0x47, \
	0x7a, 0x4e, 0x4c, 0x64, 0x36, 0x39, 0x51, 0x55, \
	0x6e, 0x57, 0x6f, 0x76, 0x59, 0x79, 0x56, 0x53, \
	0x6e, 0x64, 0x45, 0x4d, 0x79, 0x59, 0x63, 0x33, \
	0x73, 0x48, 0x65, 0x63, 0x47, 0x67, 0x66, 0x69, \
	0x6e, 0x45, 0x65, 0x68, 0x0a, 0x72, 0x67, 0x42, \
	0x4a, 0x53, 0x45, 0x64, 0x73, 0x53, 0x4a, 0x39, \
	0x46, 0x70, 0x61, 0x46, 0x64, 0x65, 0x73, 0x6a, \
	0x73, 0x78, 0x71, 0x7a, 0x47, 0x52, 0x61, 0x32, \
	0x30, 0x50, 0x59, 0x64, 0x6e, 0x6e, 0x66, 0x57, \
	0x63, 0x43, 0x54, 0x76, 0x46, 0x6f, 0x75, 0x6c, \
	0x70, 0x62, 0x46, 0x52, 0x34, 0x56, 0x42, 0x75, \
	0x58, 0x6e, 0x6e, 0x56, 0x4c, 0x56, 0x7a, 0x6b, \
	0x55, 0x76, 0x6c, 0x58, 0x54, 0x0a, 0x4c, 0x2f, \
	0x54, 0x41, 0x6e, 0x64, 0x38, 0x6e, 0x49, 0x5a, \
	0x6b, 0x30, 0x7a, 0x5a, 0x6b, 0x46, 0x4a, 0x37, \
	0x50, 0x35, 0x4c, 0x74, 0x65, 0x50, 0x76, 0x79, \
	0x6b, 0x6b, 0x61, 0x72, 0x37, 0x4c, 0x63, 0x53, \
	0x51, 0x4f, 0x38, 0x35, 0x77, 0x74, 0x63, 0x51, \
	0x65, 0x30, 0x52, 0x31, 0x52, 0x61, 0x66, 0x2f, \
	0x73, 0x51, 0x36, 0x77, 0x59, 0x4b, 0x61, 0x4b, \
	0x6d, 0x46, 0x67, 0x43, 0x47, 0x65, 0x0a, 0x4e, \
	0x70, 0x45, 0x4a, 0x55, 0x6d, 0x67, 0x34, 0x6b, \
	0x74, 0x61, 0x6c, 0x34, 0x71, 0x67, 0x49, 0x41, \
	0x78, 0x6b, 0x2b, 0x51, 0x48, 0x55, 0x78, 0x51, \
	0x45, 0x34, 0x32, 0x73, 0x78, 0x56, 0x69, 0x4e, \
	0x35, 0x6d, 0x71, 0x67, 0x6c, 0x42, 0x30, 0x51, \
	0x4a, 0x64, 0x55, 0x6f, 0x74, 0x2f, 0x6f, 0x39, \
	0x61, 0x2f, 0x56, 0x2f, 0x6d, 0x4d, 0x65, 0x48, \
	0x38, 0x4b, 0x76, 0x4f, 0x41, 0x69, 0x51, 0x0a, \
	0x62, 0x79, 0x69, 0x6e, 0x6b, 0x4e, 0x6e, 0x64, \
	0x6e, 0x2b, 0x42, 0x67, 0x6b, 0x35, 0x73, 0x53, \
	0x56, 0x35, 0x44, 0x46, 0x67, 0x46, 0x30, 0x44, \
	0x66, 0x66, 0x56, 0x71, 0x6d, 0x56, 0x4d, 0x62, \
	0x6c, 0x74, 0x35, 0x70, 0x33, 0x6a, 0x50, 0x74, \
	0x49, 0x6d, 0x7a, 0x42, 0x49, 0x48, 0x30, 0x51, \
	0x51, 0x72, 0x58, 0x4a, 0x71, 0x33, 0x39, 0x41, \
	0x54, 0x38, 0x63, 0x52, 0x77, 0x50, 0x35, 0x48, \
	0x0a, 0x61, 0x66, 0x75, 0x56, 0x65, 0x4c, 0x48, \
	0x63, 0x44, 0x73, 0x52, 0x70, 0x36, 0x68, 0x6f, \
	0x6c, 0x34, 0x50, 0x2b, 0x5a, 0x46, 0x49, 0x68, \
	0x75, 0x38, 0x6d, 0x6d, 0x62, 0x49, 0x31, 0x75, \
	0x30, 0x68, 0x48, 0x33, 0x57, 0x2f, 0x30, 0x43, \
	0x32, 0x42, 0x75, 0x59, 0x58, 0x42, 0x35, 0x50, \
	0x43, 0x2b, 0x35, 0x69, 0x7a, 0x46, 0x46, 0x68, \
	0x2f, 0x6e, 0x50, 0x30, 0x6c, 0x63, 0x32, 0x4c, \
	0x66, 0x0a, 0x36, 0x72, 0x45, 0x4c, 0x4f, 0x39, \
	0x4c, 0x5a, 0x64, 0x6e, 0x4f, 0x68, 0x70, 0x4c, \
	0x31, 0x45, 0x78, 0x46, 0x4f, 0x71, 0x39, 0x48, \
	0x2f, 0x42, 0x38, 0x74, 0x50, 0x51, 0x38, 0x34, \
	0x54, 0x33, 0x53, 0x67, 0x62, 0x34, 0x6e, 0x41, \
	0x69, 0x66, 0x44, 0x61, 0x62, 0x4e, 0x74, 0x2f, \
	0x7a, 0x75, 0x36, 0x4d, 0x6d, 0x43, 0x47, 0x6f, \
	0x35, 0x55, 0x38, 0x6c, 0x77, 0x45, 0x46, 0x74, \
	0x47, 0x4d, 0x0a, 0x52, 0x6f, 0x4f, 0x61, 0x58, \
	0x34, 0x41, 0x53, 0x2b, 0x39, 0x30, 0x39, 0x78, \
	0x30, 0x30, 0x6c, 0x59, 0x6e, 0x6d, 0x74, 0x77, \
	0x73, 0x44, 0x56, 0x57, 0x76, 0x39, 0x76, 0x42, \
	0x69, 0x4a, 0x43, 0x58, 0x52, 0x73, 0x43, 0x41, \
	0x77, 0x45, 0x41, 0x41, 0x61, 0x4f, 0x42, 0x79, \
	0x54, 0x43, 0x42, 0x78, 0x6a, 0x42, 0x67, 0x42, \
	0x67, 0x4e, 0x56, 0x48, 0x52, 0x38, 0x45, 0x57, \
	0x54, 0x42, 0x58, 0x0a, 0x4d, 0x46, 0x57, 0x67, \
	0x55, 0x36, 0x42, 0x52, 0x68, 0x6b, 0x39, 0x6f, \
	0x64, 0x48, 0x52, 0x77, 0x4f, 0x69, 0x38, 0x76, \
	0x64, 0x48, 0x4a, 0x31, 0x63, 0x33, 0x52, 0x6c, \
	0x5a, 0x48, 0x4e, 0x6c, 0x63, 0x6e, 0x5a, 0x70, \
	0x59, 0x32, 0x56, 0x7a, 0x4c, 0x6d, 0x6c, 0x75, \
	0x64, 0x47, 0x56, 0x73, 0x4c, 0x6d, 0x4e, 0x76, \
	0x62, 0x53, 0x39, 0x6a, 0x62, 0x32, 0x35, 0x30, \
	0x5a, 0x57, 0x35, 0x30, 0x0a, 0x4c, 0x30, 0x4e, \
	0x53, 0x54, 0x43, 0x39, 0x54, 0x52, 0x31, 0x67, \
	0x76, 0x51, 0x58, 0x52, 0x30, 0x5a, 0x58, 0x4e, \
	0x30, 0x59, 0x58, 0x52, 0x70, 0x62, 0x32, 0x35, \
	0x53, 0x5a, 0x58, 0x42, 0x76, 0x63, 0x6e, 0x52, \
	0x54, 0x61, 0x57, 0x64, 0x75, 0x61, 0x57, 0x35, \
	0x6e, 0x51, 0x30, 0x45, 0x75, 0x59, 0x33, 0x4a, \
	0x73, 0x4d, 0x42, 0x30, 0x47, 0x41, 0x31, 0x55, \
	0x64, 0x44, 0x67, 0x51, 0x57, 0x0a, 0x42, 0x42, \
	0x52, 0x34, 0x51, 0x33, 0x74, 0x32, 0x70, 0x6e, \
	0x36, 0x38, 0x30, 0x4b, 0x39, 0x2b, 0x51, 0x6a, \
	0x66, 0x72, 0x4e, 0x58, 0x77, 0x37, 0x68, 0x77, \
	0x46, 0x52, 0x50, 0x44, 0x41, 0x66, 0x42, 0x67, \
	0x4e, 0x56, 0x48, 0x53, 0x4d, 0x45, 0x47, 0x44, \
	0x41, 0x57, 0x67, 0x42, 0x52, 0x34, 0x51, 0x33, \
	0x74, 0x32, 0x70, 0x6e, 0x36, 0x38, 0x30, 0x4b, \
	0x39, 0x2b, 0x51, 0x6a, 0x66, 0x72, 0x0a, 0x4e, \
	0x58, 0x77, 0x37, 0x68, 0x77, 0x46, 0x52, 0x50, \
	0x44, 0x41, 0x4f, 0x42, 0x67, 0x4e, 0x56, 0x48, \
	0x51, 0x38, 0x42, 0x41, 0x66, 0x38, 0x45, 0x42, \
	0x41, 0x4d, 0x43, 0x41, 0x51, 0x59, 0x77, 0x45, \
	0x67, 0x59, 0x44, 0x56, 0x52, 0x30, 0x54, 0x41, \
	0x51, 0x48, 0x2f, 0x42, 0x41, 0x67, 0x77, 0x42, \
	0x67, 0x45, 0x42, 0x2f, 0x77, 0x49, 0x42, 0x41, \
	0x44, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x0a, \
	0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, \
	0x41, 0x51, 0x73, 0x46, 0x41, 0x41, 0x4f, 0x43, \
	0x41, 0x59, 0x45, 0x41, 0x65, 0x46, 0x38, 0x74, \
	0x59, 0x4d, 0x58, 0x49, 0x43, 0x76, 0x51, 0x71, \
	0x65, 0x58, 0x59, 0x51, 0x49, 0x54, 0x6b, 0x56, \
	0x32, 0x6f, 0x4c, 0x4a, 0x73, 0x70, 0x36, 0x4a, \
	0x34, 0x4a, 0x41, 0x71, 0x4a, 0x61, 0x62, 0x48, \
	0x57, 0x78, 0x59, 0x4a, 0x48, 0x47, 0x69, 0x72, \
	0x0a, 0x49, 0x45, 0x71, 0x75, 0x63, 0x52, 0x69, \
	0x4a, 0x53, 0x53, 0x78, 0x2b, 0x48, 0x6a, 0x49, \
	0x4a, 0x45, 0x55, 0x56, 0x61, 0x6a, 0x38, 0x45, \
	0x30, 0x51, 0x6a, 0x45, 0x75, 0x64, 0x36, 0x59, \
	0x35, 0x6c, 0x4e, 0x6d, 0x58, 0x6c, 0x63, 0x6a, \
	0x71, 0x52, 0x58, 0x61, 0x43, 0x50, 0x4f, 0x71, \
	0x4b, 0x30, 0x65, 0x47, 0x52, 0x7a, 0x36, 0x68, \
	0x69, 0x2b, 0x72, 0x69, 0x70, 0x4d, 0x74, 0x50, \
	0x5a, 0x0a, 0x73, 0x46, 0x4e, 0x61, 0x42, 0x77, \
	0x4c, 0x51, 0x56, 0x56, 0x39, 0x30, 0x35, 0x53, \
	0x44, 0x6a, 0x41, 0x7a, 0x44, 0x7a, 0x4e, 0x49, \
	0x44, 0x6e, 0x72, 0x63, 0x6e, 0x58, 0x79, 0x42, \
	0x34, 0x67, 0x63, 0x44, 0x46, 0x43, 0x76, 0x77, \
	0x44, 0x46, 0x4b, 0x4b, 0x67, 0x4c, 0x52, 0x6a, \
	0x4f, 0x42, 0x2f, 0x57, 0x41, 0x71, 0x67, 0x73, \
	0x63, 0x44, 0x55, 0x6f, 0x47, 0x71, 0x35, 0x5a, \
	0x56, 0x69, 0x0a, 0x7a, 0x4c, 0x55, 0x7a, 0x54, \
	0x71, 0x69, 0x51, 0x50, 0x6d, 0x55, 0x4c, 0x41, \
	0x51, 0x61, 0x42, 0x39, 0x63, 0x36, 0x4f, 0x74, \
	0x69, 0x36, 0x73, 0x6e, 0x45, 0x46, 0x4a, 0x69, \
	0x43, 0x51, 0x36, 0x37, 0x4a, 0x4c, 0x79, 0x57, \
	0x2f, 0x45, 0x38, 0x33, 0x2f, 0x66, 0x72, 0x7a, \
	0x43, 0x6d, 0x4f, 0x35, 0x52, 0x75, 0x36, 0x57, \
	0x6a, 0x55, 0x34, 0x74, 0x6d, 0x73, 0x6d, 0x79, \
	0x38, 0x52, 0x61, 0x0a, 0x55, 0x64, 0x34, 0x41, \
	0x50, 0x4b, 0x30, 0x77, 0x5a, 0x54, 0x47, 0x74, \
	0x66, 0x50, 0x58, 0x55, 0x37, 0x77, 0x2b, 0x49, \
	0x42, 0x64, 0x47, 0x35, 0x45, 0x7a, 0x30, 0x6b, \
	0x45, 0x31, 0x71, 0x7a, 0x78, 0x47, 0x51, 0x61, \
	0x4c, 0x34, 0x67, 0x49, 0x4e, 0x4a, 0x31, 0x7a, \
	0x4d, 0x79, 0x6c, 0x65, 0x44, 0x6e, 0x62, 0x75, \
	0x53, 0x38, 0x55, 0x69, 0x63, 0x6a, 0x4a, 0x69, \
	0x6a, 0x76, 0x71, 0x41, 0x0a, 0x31, 0x35, 0x32, \
	0x53, 0x71, 0x30, 0x34, 0x39, 0x45, 0x53, 0x44, \
	0x7a, 0x2b, 0x31, 0x72, 0x52, 0x47, 0x63, 0x32, \
	0x4e, 0x56, 0x45, 0x71, 0x68, 0x31, 0x4b, 0x61, \
	0x47, 0x58, 0x6d, 0x74, 0x58, 0x76, 0x71, 0x78, \
	0x58, 0x63, 0x54, 0x42, 0x2b, 0x4c, 0x6a, 0x79, \
	0x35, 0x42, 0x77, 0x32, 0x6b, 0x65, 0x30, 0x76, \
	0x38, 0x69, 0x47, 0x6e, 0x67, 0x46, 0x42, 0x50, \
	0x71, 0x43, 0x54, 0x56, 0x42, 0x0a, 0x33, 0x6f, \
	0x70, 0x35, 0x4b, 0x42, 0x47, 0x33, 0x52, 0x6a, \
	0x62, 0x46, 0x36, 0x52, 0x52, 0x53, 0x7a, 0x77, \
	0x7a, 0x75, 0x57, 0x66, 0x4c, 0x37, 0x51, 0x45, \
	0x72, 0x4e, 0x43, 0x38, 0x57, 0x45, 0x79, 0x35, \
	0x79, 0x44, 0x56, 0x41, 0x52, 0x7a, 0x54, 0x41, \
	0x35, 0x2b, 0x78, 0x6d, 0x42, 0x63, 0x33, 0x38, \
	0x38, 0x76, 0x39, 0x44, 0x6d, 0x32, 0x31, 0x48, \
	0x47, 0x66, 0x63, 0x43, 0x38, 0x4f, 0x0a, 0x44, \
	0x44, 0x2b, 0x67, 0x54, 0x39, 0x73, 0x53, 0x70, \
	0x73, 0x73, 0x71, 0x30, 0x61, 0x73, 0x63, 0x6d, \
	0x76, 0x48, 0x34, 0x39, 0x4d, 0x4f, 0x67, 0x6a, \
	0x74, 0x31, 0x79, 0x6f, 0x79, 0x73, 0x4c, 0x74, \
	0x64, 0x43, 0x74, 0x4a, 0x57, 0x2f, 0x39, 0x46, \
	0x5a, 0x70, 0x6f, 0x4f, 0x79, 0x70, 0x61, 0x48, \
	0x78, 0x30, 0x52, 0x2b, 0x6d, 0x4a, 0x54, 0x4c, \
	0x77, 0x50, 0x58, 0x56, 0x4d, 0x72, 0x76, 0x0a, \
	0x44, 0x61, 0x56, 0x7a, 0x57, 0x68, 0x35, 0x61, \
	0x69, 0x45, 0x78, 0x2b, 0x69, 0x64, 0x6b, 0x53, \
	0x47, 0x4d, 0x6e, 0x58, 0x0a, 0x2d, 0x2d, 0x2d, \
	0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x43, 0x45, \
	0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, \
	0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a
};


/**
 * The following array defines the strings used to indicate the
 * general result of the attestation.
 */
static const char *Quote_status[] = {
	"OK",
	"SIGNATURE_INVALID",
	"GROUP_REVOKED",
	"SIGNATURE_REVOKED",
	"KEY_REVOKED",
	"SIGRL_VERSION_MISMATCH",
	"GROUP_OUT_OF_DATE",
	"CONFIGURATION_NEEDED",
	"UNDEFINED",
	NULL
};


/**
 * The following structure defines the information 'blob' that is
 * returned from the Intel attestation servers if the EPID group
 * has been revoked or is out of date.
 */
struct platform_info {
	uint8_t sgx_epid_group_flags;
	uint8_t sgx_tcb_evaluation_flags[2];
	uint8_t pse_evaluation_flags[2];
	struct SGX_psvn latest_equivalent_tcb_psvn;
	uint8_t latest_pse_isvsvn[4];
	uint8_t latest_psda_svn[4];
	uint32_t xeid;
	uint8_t GroupId[4];
	uint8_t signature[64];
} __attribute__((packed));


/** SRDEquote private state information. */
struct NAAAIM_SRDEquote_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Flag to indicate that development mode is in effect. */
	_Bool development;

	/* Untrusted instance. */
	unsigned int instance;

	/* Quoting enclave target information. */
	struct SGX_targetinfo qe_target_info;

	/* Information derived from an attestation report. */
	String report;

	String version;
	String id;
	String timestamp;

	String signature;
	String certificate;

	Buffer nonce;

	enum SRDEquote_status status;

	struct SRDE_quote quote;

	struct platform_info platform_info;
};


/**
 * Internal private function.
 *
 * This method is responsible for marshalling arguements and generating
 * the OCALL for the external methods call.
 *
 * \param ocp	A pointer to the data structure which is used to
 *		marshall the arguements into and out of the OCALL.
 *
 * \return	An integer value is used to indicate the status of
 *		the SGX call.  A value of zero indicate there was no
 *		error while a non-zero value, particularly negative
 *		indicates an error occurred in the call.  The return
 *		value from the external object is embedded in the
 *		data marshalling structure.
 */

static int sgxquote_ocall(struct SRDEquote_ocall *ocall)

{
	_Bool retn = false;

	int status = SGX_ERROR_INVALID_PARAMETER;

	void *ap;

	size_t quote_token_size = 0,
	       pce_token_size	= 0,
	       epid_blob_size	= 0,
	       arena_size	= sizeof(struct SRDEquote_ocall);

	struct SRDEquote_ocall *ocp = NULL;


	/* Verify arguements and set size of arena. */
	if ( ocall->ocall == SRDEquote_init ) {
		if ( ocall->quote_token != NULL ) {
			quote_token_size = strlen(ocall->quote_token) + 1;
			if ( !sgx_is_within_enclave(ocall->quote_token, \
						    quote_token_size) )
				goto done;
			arena_size += quote_token_size;
		}

		if ( ocall->pce_token != NULL ) {
			pce_token_size = strlen(ocall->pce_token) + 1;
			if ( !sgx_is_within_enclave(ocall->pce_token, \
						    pce_token_size) )
				goto done;
			arena_size += pce_token_size;
		}

		if ( ocall->epid_blob != NULL ) {
			epid_blob_size = strlen(ocall->epid_blob) + 1;
			if ( !sgx_is_within_enclave(ocall->epid_blob, \
						    epid_blob_size) )
				goto done;
			arena_size += epid_blob_size;
		}
	}

	if ( ocall->ocall == SRDEquote_generate_report ) {
		if ( !sgx_is_within_enclave(ocall->arena, ocall->bufr_size) )
			goto done;
		arena_size += ocall->bufr_size;
	}


	/* Allocate and initialize the outbound method structure. */
	if ( (ocp = sgx_ocalloc(arena_size)) == NULL )
		goto done;

	memset(ocp, '\0', arena_size);
	*ocp = *ocall;


	/* Setup arena and pointers to it. */
	if ( ocall->ocall == SRDEquote_init ) {
		ap = ocp->arena;

		if ( ocall->quote_token != NULL ) {
			memcpy(ap, ocall->quote_token, quote_token_size);
			ocp->quote_token = ap;
			ap += quote_token_size;
		}

		if ( ocall->pce_token != NULL ) {
			memcpy(ap, ocall->pce_token, pce_token_size);
			ocp->pce_token = ap;
			ap += pce_token_size;
		}

		if ( ocall->epid_blob != NULL ) {
			memcpy(ap, ocall->epid_blob, epid_blob_size);
			ocp->epid_blob = ap;
		}
	}

	if ( ocall->ocall == SRDEquote_generate_report)
		memcpy(ocp->arena, ocall->bufr, ocall->bufr_size);


	/* Call the SGX duct manager. */
	if ( (status = sgx_ocall(SRDENAAAIM_OCALL2, ocp)) == 0 ) {
		retn = true;
		*ocall = *ocp;
	}


 done:
	sgx_ocfree();

	if ( status != 0 )
		return status;
	if ( !retn )
		return SGX_ERROR_UNEXPECTED;
	return 0;
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SRDEquote_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SRDEquote_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SRDEquote_OBJID;

	S->poisoned    = false;
	S->development = false;

	S->instance = 0;

	memset(&S->qe_target_info, '\0', sizeof(struct SGX_targetinfo));

	S->report	= NULL;
	S->version	= NULL;
	S->id		= NULL;
	S->timestamp	= NULL;
	S->signature	= NULL;
	S->certificate	= NULL;
	S->nonce	= NULL;

	S->status = SRDEquote_status_UNDEFINED;

	memset(&S->quote, '\0', sizeof(struct SRDE_quote));
	memset(&S->platform_info, '\0', sizeof(struct platform_info));

	return;
}


/**
 * External public method.
 *
 * This method implements the OCALL which initializes the object
 * in untrusted userspace.
 *
 * \param this		A pointer to the quoting object to be initialized.
 *
 * \param quote_token	A character pointer to a null-terminated buffer
 *			containing the name of the file that contains
 *			the initialization token for the quoting enclave.
 *
 * \param pce_token	A character pointer to a null-terminated buffer
 *			containing the name of the file that contains
 *			the initialization token for the PCE enclave.
 *
 * \param epid_blob	The name of the file containing the EPID
 *			blob.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the initialization of the quote.  A false
 *		value indicates an error occurred while a true
 *		value indicates the quote was successfully initialized.
 */

static _Bool init(CO(SRDEquote, this), CO(char *, quote_token), \
		  CO(char *, pce_token), CO(char *, epid_blob))

{
	STATE(S);

	_Bool retn = false;

	struct SRDEquote_ocall ocall;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SRDEquote_ocall));

	ocall.ocall	= SRDEquote_init;
	ocall.instance	= S->instance;

	ocall.quote_token = (char *) quote_token;
	ocall.pce_token	  = (char *) pce_token;
	ocall.epid_blob	  = (char *) epid_blob;

	if ( sgxquote_ocall(&ocall) != 0 )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the OCALL which is used to generate an
 * enclave quote for remote attestation.
 *
 * \param this		A pointer to the quoting object to be
 *			initialized.
 *
 * \param report	A pointer to to the enclave report that is to
 *			be attested.
 *
 * \param spid		The service provider identity to be used for
 *			the quote.
 *
 * \param nonce		The random nonce to be used for the quote.
 *
 * \param quote		The object which the binary quote is to be
 *			loaded into.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the initialization of the quote.  A false
 *		value indicates an error occurred while a true
 *		value indicates the quote was successfully initialized.
 */

static _Bool generate_quote(CO(SRDEquote, this),			 \
			    struct SGX_report *report, CO(Buffer, spid), \
			    CO(Buffer, nonce), CO(Buffer, quote))

{
	STATE(S);

	_Bool retn = false;

	struct SRDEquote_ocall ocall;


	/* Verify object and arguement status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( spid->poisoned(spid) )
		ERR(goto done);
	if ( spid->size(spid) != 16 )
		ERR(goto done);
	if ( nonce->poisoned(nonce) )
		ERR(goto done);
	if ( nonce->size(nonce) != 16 )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SRDEquote_ocall));

	ocall.ocall	= SRDEquote_generate_quote,
	ocall.instance	= S->instance;

	ocall.report = *report;
	memcpy(ocall.spid, spid->get(spid), spid->size(spid));
	memcpy(ocall.nonce, nonce->get(nonce), nonce->size(nonce));

	if ( sgxquote_ocall(&ocall) != 0 )
		ERR(goto done);

	if ( !quote->add(quote, ocall.bufr, ocall.bufr_size) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the OCALL which implements the generation of
 * an attestation requote on an enclave quote.
 *
 * \param this		A pointer to the quoting object to be
 *			initialized.
 *
 * \param quote		The object which contains the quote which is
 *			to be verifed by the authentication servers.
 *
 * \param report	The object that will be loaded with the report
 *			that is returned.
 *
 * \param apikey	An object containing the authentication key
 *			that should be used when communicating with
 *			Intel IAS services.  Setting this value to
 *			NULL will cause the older certificate/key
 *			mechanism to be used.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the report generation.  A false value indicates
 *		an error occurred while a true value indicates the report
 *		was successfully generated.
 */

static _Bool generate_report(CO(SRDEquote, this), CO(Buffer, quote), \
			     CO(String, report), CO(String, apikey))

{
	STATE(S);

	_Bool retn = false;

	Buffer bufr = NULL;

	struct SRDEquote_ocall ocall;


	/* Verify object and arguement status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( quote->poisoned(quote) )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SRDEquote_ocall));

	if ( apikey != NULL ) {
		ocall.apikey = true;
		memcpy(ocall.key, apikey->get(apikey), apikey->size(apikey));
	}

	if ( S->nonce != NULL ) {
		ocall.set_nonce = true;
		memcpy(ocall.ias_nonce, S->nonce->get(S->nonce), \
		       sizeof(ocall.ias_nonce));
	}

	ocall.development = S->development;

	ocall.ocall	= SRDEquote_generate_report,
	ocall.instance	= S->instance;

	ocall.bufr	= quote->get(quote);
	ocall.bufr_size = quote->size(quote);

	if ( sgxquote_ocall(&ocall) != 0 )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, ocall.bufr, ocall.bufr_size) )
		ERR(goto done);
	if ( !report->add(report, (char *) bufr->get(bufr)) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);

	return true;
}


/**
 * Internal private function.
 *
 * This method parses the supplied input for conformance with the
 * version of IAS services that the SRDEquote object is designed to
 * handle.  It is a subordinate helper function for the ->decode_report
 * method.
 *
 * \param field	The object containing the field to be parsed.
 *
 * \param rgx	The object which is to be used to create the
 *		regular expression.
 *
 * \param value	A pointer to the object that will be loaded with
 *		the parsed field value.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the field extraction.  A false value is
 *		used to indicate a failure occurred during the field
 *		entry extraction.  A true value indicates the
 *		field has been successfully extracted and the value
 *		variable contains a legitimate value.
 */

static _Bool _get_version(CO(String, field), CO(String, rgx), \
			  CO(String, value))

{
	_Bool retn       = false,
	      have_regex = false;

	char *fp,
	     element[2];

	size_t len;

	regex_t regex;

	regmatch_t regmatch[2];


	/* Extract the field element. */
	rgx->reset(rgx);
	if ( !rgx->add(rgx, "[,{]\"version\":([^,}]*).*") )
		ERR(goto done);
	value->reset(value);


	if ( regcomp(&regex, rgx->get(rgx), REG_EXTENDED) != 0 )
		ERR(goto done);
	have_regex = true;

	if ( regexec(&regex, field->get(field), 2, regmatch, 0) != REG_OK )
		ERR(goto done);

	len = regmatch[1].rm_eo - regmatch[1].rm_so;
	if ( len > field->size(field) )
		ERR(goto done);


	/* Copy the field element to the output object. */
	memset(element, '\0', sizeof(element));
	fp = field->get(field) + regmatch[1].rm_so;

	while ( len-- ) {
		element[0] = *fp;
		value->add(value, element);
		++fp;
	}
	if ( value->poisoned(value) )
		ERR(goto done);

	retn = true;


 done:
	if ( have_regex )
		regfree(&regex);

	return retn;
}


/**
 * Internal private function.
 *
 * This method parses the supplied input and extracts the brace
 * delimited report.
 *
 * \param field		The object containing the field to be parsed.
 *
 * \param value		A pointer to the object that will be loaded
 *			with the parsed report.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the report extraction.  A false value is
 *		used to indicate a failure occurred during the
 *		extraction.  A true value indicates the report has
 *		been successfully extracted and the value object
 *		contains a legitimate value.
 */

static _Bool _get_report(CO(String, field), CO(String, report))

{
	_Bool retn       = false,
	      have_regex = false;

	char *fp,
	     element[2];

	const char *rgx = "(\\{[^\\}]*\\})";

	size_t len;

	regex_t regex;

	regmatch_t regmatch[2];


	/* Match the report field. */
	if ( regcomp(&regex, rgx, REG_EXTENDED) != 0 )
		ERR(goto done);
	have_regex = true;

	if ( regexec(&regex, field->get(field), 2, regmatch, 0) != REG_OK )
		ERR(goto done);

	len = regmatch[1].rm_eo - regmatch[1].rm_so;
	if ( len > field->size(field) )
		ERR(goto done);


	/* Copy the field element to the output object. */
	memset(element, '\0', sizeof(element));
	fp = field->get(field) + regmatch[1].rm_so;

	while ( len-- ) {
		element[0] = *fp;
		report->add(report, element);
		++fp;
	}
	if ( report->poisoned(report) )
		ERR(goto done);

	retn = true;


 done:
	if ( have_regex )
		regfree(&regex);

	return retn;
}


/**
 * Internal private function.
 *
 * This method parses the supplied input for a single JSON field.  It
 * is a subordinate helper function for the ->decode_report method.
 *
 * \param noerr	A flag variable used to indicate that an error
 *		condition should not be generated if there is
 *		no field match.
 *
 * \param field	The object containing the field to be parsed.
 *
 * \param rgx	The object which is to be used to create the
 *		regular expression.
 *
 * \param fd	The field descriptor tag which is to be returned.
 *
 * \param value	A pointer to the object that will be loaded with
 *		the parsed field value.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the field extraction.  A false value is
 *		used to indicate a failure occurred during the field
 *		entry extraction.  A true value indicates the
 *		field has been successfully extracted and the value
 *		variable contains a legitimate value.
 */

static _Bool _get_field(const _Bool noerr, CO(String, field), \
			CO(String, rgx), CO(char *, fd), CO(String, value))

{
	_Bool retn       = false,
	      have_regex = false;

	char *fp,
	     element[2];

	size_t len;

	regex_t regex;

	regmatch_t regmatch[2];


	/* Extract the field element. */
	value->reset(value);

	rgx->reset(rgx);
	rgx->add(rgx, ".*\"");
	rgx->add(rgx, fd);
	if ( !rgx->add(rgx, "\":\"([^\"]*).*") )
		ERR(goto done);

	if ( regcomp(&regex, rgx->get(rgx), REG_EXTENDED) != 0 )
		ERR(goto done);
	have_regex = true;

	if ( regexec(&regex, field->get(field), 2, regmatch, 0) != REG_OK ) {
		if ( noerr )
			goto done;
		ERR(goto done);
	}

	len = regmatch[1].rm_eo - regmatch[1].rm_so;
	if ( len > field->size(field) )
		ERR(goto done);


	/* Copy the field element to the output object. */
	memset(element, '\0', sizeof(element));
	fp = field->get(field) + regmatch[1].rm_so;

	while ( len-- ) {
		element[0] = *fp;
		value->add(value, element);
		++fp;
	}
	if ( value->poisoned(value) )
		ERR(goto done);

	retn = true;

 done:
	if ( have_regex )
		regfree(&regex);

	return retn;
}


/**
 * Internal private function.
 *
 * This is a support function for the ->decode_report method that
 * compartmentalizes the extraction of the report signature and
 * certificate.  This method leaves the binary form of the signature
 * in the object state and the percent-decoded certification in the
 * object state.
 *
 * \param S		A pointer to the object state.
 *
 * \param field		The report data that is to be parsed.
 *
 * \param rgx		A pointer to the object that will be used to
 *			hold the regular expression.
 *
 * \param hd		The header definition that is to be extracted.
 *
 * \param header	The object that the extracted header will be
 *			placed into.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the header extraction.  A false value is
 *		used to indicate a failure occurred during the
 *		extraction.  A true value indicates the signature and
 *		certificate have been successfully extracted.
 */

static _Bool _get_header(CO(String, field), CO(String, rgx), CO(char *, hd), \
			 CO(String, header))

{
	_Bool retn       = false,
	      have_regex = false;

	char *fp,
	     element[2];

	size_t len;

	regex_t regex;

	regmatch_t regmatch[2];


	/* Extract and convert the signature to binary form. */
	rgx->reset(rgx);
	if ( !rgx->add(rgx, hd) )
		ERR(goto done);
	if ( !rgx->add(rgx, ": ([^\r]*)\r") )
		ERR(goto done);

	if ( regcomp(&regex, rgx->get(rgx), REG_EXTENDED) != 0 )
		ERR(goto done);
	have_regex = true;

	if ( regexec(&regex, field->get(field), 2, regmatch, 0) != REG_OK )
		ERR(goto done);

	len = regmatch[1].rm_eo - regmatch[1].rm_so;
	if ( len > field->size(field) )
		ERR(goto done);


	/* Copy the field element to the output object. */
	memset(element, '\0', sizeof(element));
	fp = field->get(field) + regmatch[1].rm_so;

	while ( len-- ) {
		element[0] = *fp;
		header->add(header, element);
		++fp;
	}

	if ( header->poisoned(header) )
		ERR(goto done);
	retn = true;


 done:
	if ( have_regex )
		regfree(&regex);

	return retn;
}


/**
 * Internal private function.
 *
 * This is a support function for the ->decode_report method that
 * converts the certificate from a percent encoded object into
 * a standard ASCII object.  This routine should hardly be considered
 * a full implementation of URL percent decoding but rather something
 * sufficient to get the certificate extracted.
 *
 * \param certificate	A pointer to the object containing the
 *			certificate.  The decoded certificate will
 *			be placed back into this object.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the decoding.  A false value is
 *		used to indicate a failure occurred during the
 *		the process and the contents of the supplied object
 *		must be considered to be in an indeterminate state.
 *		A true value indicates the certificate has been
 *		successfully decoded and the supplied object contains
 *		a valid copy of the certificate.
 */

static _Bool _decode_certificate(CO(String, certificate))

{
	_Bool retn = false;

	char *cp,
	     element[3];

	size_t len;

	Buffer cert = NULL;


	/* Verify object status. */
	if ( certificate == NULL )
		ERR(goto done);
	if ( certificate->size == 0 )
		ERR(goto done);
	if ( certificate->size(certificate) < 3 )
		ERR(goto done);


	INIT(HurdLib, Buffer, cert, ERR(goto done));

	cp  = certificate->get(certificate);
	len = certificate->size(certificate);

	memset(element, '\0', sizeof(element));

	while ( len-- ) {
		if ( (*cp == '%') && (len >= 2) ) {
			memcpy(element, cp+1, 2);
			if ( !cert->add_hexstring(cert, element) )
				ERR(goto done);
			cp += 3;
		} else {
			if ( !cert->add(cert, (unsigned char *) cp, 1) )
				ERR(goto done);
			++cp;
		}
	}

	element[0] = '\0';
	if ( !cert->add(cert, (unsigned char *) element, 1) )
		ERR(goto done);

	certificate->reset(certificate);
	if ( !certificate->add(certificate, (char *) cert->get(cert)) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(cert);

	return retn;
}


/**
 * External public method.
 *
 * This method implements the decoding of an enclave attestation report
 * that has been previously requested.
 *
 * \param this		A pointer to the quoting object which is to
 *			be used for decoding the report.
 *
 * \param report	The object containing the report data that is
 *			to be decoded.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the initialization of the quote.  A false
 *		value indicates an error occurred while a true
 *		value indicates the quote was successfully initialized.
 */

static _Bool decode_report(CO(SRDEquote, this), CO(String, report))

{
	STATE(S);

	_Bool retn = false;

	uint16_t tlv_size;

	struct TLVshort {
		uint8_t type;
		uint8_t version;
		uint16_t size;
	} __attribute__((packed)) *tlv;

	Buffer bufr = NULL;

	String rpt    = NULL,
	       field  = NULL,
	       fregex = NULL;

	Base64 base64 = NULL;


	/* Decode the version file and abort if not correct. */
	INIT(HurdLib, String, fregex, ERR(goto done));

	INIT(HurdLib, String, S->version, ERR(goto done));
	if ( !_get_version(report, fregex, S->version) )
		ERR(goto done);
	if ( memcmp(IAS_VERSION, S->version->get(S->version), \
		    S->version->size(S->version)) != 0 )
		ERR(goto done);

	/* Extract the report itself. */
	INIT(HurdLib, String, S->report, ERR(goto done));
	if ( !_get_report(report, S->report) )
		ERR(goto done);

	/* Extract the report signature and certificate. */
	INIT(HurdLib, String, S->signature, ERR(goto done));
	if ( !_get_header(report, fregex, "[xX]-[iI][aA][sS][rR]" \
			  "eport-[sS]ignature", S->signature) )
		ERR(goto done);

	INIT(HurdLib, String, S->certificate, ERR(goto done));
	if ( !_get_header(report, fregex, "[xX]-[iI][aA][sS][rR]" \
			  "eport-[sS]igning-[cC]ertificate", S->certificate) )
		ERR(goto done);
	if ( !_decode_certificate(S->certificate) )
		ERR(goto done);

	/* Extract the report fields. */
	INIT(HurdLib, String, S->id, ERR(goto done));
	if ( !_get_field(field, S->report, fregex, "id", S->id) )
		ERR(goto done);

	INIT(HurdLib, String, S->timestamp, ERR(goto done));
	if ( !_get_field(false, S->report, fregex, "timestamp", S->timestamp) )
		ERR(goto done);

	INIT(HurdLib, String, field, ERR(goto done));
	if ( _get_field(true, S->report, fregex, "nonce", field) ) {
		if ( S->nonce == NULL ) {
			INIT(HurdLib, Buffer, S->nonce, ERR(goto done));
		}
		else
			S->nonce->reset(S->nonce);
		if ( !S->nonce->add_hexstring(S->nonce, field->get(field)) )
			ERR(goto done);
		field->reset(field);
	}

	if ( !_get_field(false, S->report, fregex, "isvEnclaveQuoteStatus", \
			 field) )
		ERR(goto done);

	for (S->status= 0; Quote_status[S->status] != NULL; ++S->status) {
		if ( strcmp(field->get(field), Quote_status[S->status]) \
		     == 0)
			break;
	}


	/* Decode the quote body. */
	field->reset(field);
	if ( !_get_field(false, S->report, fregex, "isvEnclaveQuoteBody", \
			 field) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Base64, base64, ERR(goto done));

	if ( !base64->decode(base64, field, bufr) )
		ERR(goto done);

	memcpy(&S->quote, bufr->get(bufr), sizeof(struct SRDE_quote));


	/* Decode the platform information report if available. */
	if ( S->status == SRDEquote_status_GROUP_OUT_OF_DATE || \
	     S->status == SRDEquote_status_GROUP_REVOKED ||     \
	     S->status == SRDEquote_status_CONFIGURATION_NEEDED ) {
		field->reset(field);
		if ( !_get_field(false, S->report, fregex, \
				 "platformInfoBlob", field) )
			ERR(goto done);

		bufr->reset(bufr);
		if ( !bufr->add_hexstring(bufr, field->get(field)) )
			ERR(goto done);

		tlv = (struct TLVshort *) bufr->get(bufr);
		if ( (tlv->type != 21) || (tlv->version != 2) )
			ERR(goto done);
		tlv_size = ntohs(tlv->size);

		bufr->reset(bufr);
		if ( !bufr->add_hexstring(bufr, \
					  field->get(field) + sizeof(*tlv)*2) )
			ERR(goto done);
		if ( tlv_size != bufr->size(bufr) )
			ERR(goto done);

		memcpy(&S->platform_info, bufr->get(bufr), \
		       sizeof(struct platform_info));
	}

	retn = true;


 done:
	WHACK(bufr);

	WHACK(rpt);
	WHACK(field);
	WHACK(fregex);

	WHACK(base64);

	return retn;
}


/**
 * External public method.
 *
 * This method validates a report that has been decoded by verifying
 * the IAS supplied signature.  Before validating the signature the
 * the Intel provided signing certificate is validated with a version
 * of the certificate that is embedded in this object.
 *
 * \param this		A pointer to the object which is to have its
 *			report validated.
 *
 * \param status	A pointer to a boolean value that will be
 *			used to convey the status of the report.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the report validation.  A false
 *		value indicates an error occurred during the
 *		validation process and the status variable cannot be
 *		counted on to bear an information.  A true value
 *		indicates the report validation process was
 *		successful and the pointer to the provided status
 *		variable can be counted on to have valid data.
 */

static _Bool validate_report(CO(SRDEquote, this), _Bool *status)

{
	STATE(S);

	_Bool retn  = false,
	      valid = false;

	Buffer bufr	= NULL,
	       certbufr	= NULL,
	       report	= NULL;

	Base64 b64 = NULL;

	X509cert cert = NULL;

	RSAkey key = NULL;


	/* Validate object and report status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->status == SRDEquote_status_UNDEFINED )
		ERR(goto done);


	/* Verify the integrity of the supplied certificates. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, IntelCA, sizeof(IntelCA)) )
		ERR(goto done);

	INIT(HurdLib, Buffer, certbufr, ERR(goto done));
	if ( !certbufr->add(certbufr,					  \
			    (void *) S->certificate->get(S->certificate), \
			    S->certificate->size(S->certificate)) )
		ERR(goto done);

	INIT(NAAAIM, X509cert, cert, ERR(goto done));
	if ( !cert->add(cert, bufr) )
		ERR(goto done);

	cert->time_check(cert, false);
	if ( !cert->verify(cert, certbufr, &valid) )
		ERR(goto done);
	if ( !valid )
		ERR(goto done);

	/* Verify the report signature. */
	INIT(NAAAIM, RSAkey, key, ERR(goto done));
	if ( !key->load_certificate(key, certbufr) )
		ERR(goto done);

	INIT(NAAAIM, Base64, b64, ERR(goto done));
	bufr->reset(bufr);
	if ( !b64->decode(b64, S->signature, bufr) )
		ERR(goto done);

	INIT(HurdLib, Buffer, report, ERR(goto done));
	if ( !report->add(report, (void *) S->report->get(S->report), \
			  S->report->size(S->report)) )
		ERR(goto done);

	if ( !key->verify(key, bufr, report, &valid) )
		ERR(goto done);

	retn	= true;
	*status = valid;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);
	WHACK(certbufr);
	WHACK(report);
	WHACK(b64);
	WHACK(cert);
	WHACK(key);

	return true;
}


/**
 * External public method.
 *
 * This method specifies the nonce value that should be included with
 * the attestation quote request sent to the athentication services.
 * The nonce is an optional value that can be included in the
 * report in order to indicate the 'liveness' of the report.  It is
 * typically used when a client is requesting an attestation report
 * and desires to verify that the report is not being replayed.
 *
 * \param this		A pointer to the object which is to have its
 *			report validated.
 *
 * \param nonce		The object containing the nonce that is to
 *			be added to the object.
 *
 * \return	A boolean value is returned to indicate the
 *		status of setting of the nonce.  A false value indicates
 *		an error occurred and an assumption cannot be made
 *	        that the object has a valid nonce.  A true value indicates
 *		the nonce was successfully set.
 */

static _Bool set_nonce(CO(SRDEquote, this), CO(Buffer, nonce))

{
	STATE(S);

	_Bool retn = false;


	/* Validate object state and arguements. */
	if ( S->poisoned )
		ERR(goto done);
	if ( nonce == NULL )
		ERR(goto done);
	if ( nonce->poisoned(nonce) )
		ERR(goto done);
	if ( nonce->size(nonce) > 16 )
		ERR(goto done);


	/* Create the state specific nonce object and set it. */
	INIT(HurdLib, Buffer, S->nonce, ERR(goto done));
	if ( !S->nonce->add_Buffer(S->nonce, nonce) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the OCALL which requests access to the
 * target information for the quoting enclave.
 *
 * \param this	A pointer to the object whose quoting enclave
 *		information is to be returned.
 *
 * \return	A pointer to the target structure is returned.  This
 *		may contain all null values if the object has not
 *		been initialized.
 */

static struct SGX_targetinfo * get_qe_targetinfo(CO(SRDEquote, this))

{
	STATE(S);

	_Bool retn = false;

	struct SRDEquote_ocall ocall;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SRDEquote_ocall));

	ocall.ocall	= SRDEquote_get_qe_targetinfo;
	ocall.instance	= S->instance;

	if ( sgxquote_ocall(&ocall) != 0 )
		ERR(goto done);

	S->qe_target_info = *ocall.qe_target_info;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return &S->qe_target_info;
}


/**
 * External public method.
 *
 * This method implements an accessor method for returning a pointer
 * to the structure containing the quote information for the attesting
 * enclave.
 *
 * \param this	A pointer to the object whose quote information is to
 *		be returned.
 *
 * \return	A pointer to the quote information structure is returned.
 *		This may contain all null values if the quote has not
 *		been generated.
 */

static struct SRDE_quote * get_quoteinfo(CO(SRDEquote, this))

{
	STATE(S);

	return &S->quote;
}


/**
 * External public method.
 *
 * This method implements setting whether or not the development version
 * of the IAS service should be used.
 *
 * \param this	A pointer to the object whose development status is to
 *		be set.
 *
 * \param mode	The value that the development flag is to be set to.
 */

static void development(CO(SRDEquote, this), const _Bool mode)

{
	STATE(S);


	S->development = mode;
	return;
}


/**
 * External public method.
 *
 * This method implements the decoding and print out of an attestation
 * report
 *
 * \param this	A pointer to the object containing the attestation report
 *		to be generated.
 */

static void dump_report(CO(SRDEquote, this))

{
	STATE(S);

	_Bool valid = false;

	uint16_t flags;

	uint32_t gid;

	struct SGX_reportbody *bp;

	struct platform_info *plb;

	struct SGX_psvn *psvnp;

	Buffer bufr = NULL;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("*POISONED*\n", stdout);
		return;
	}
	if ( S->status == SRDEquote_status_UNDEFINED ) {
		fputs("No report available.\n", stdout);
		return;
	}


	/* Output signature status. */
	fputs("Signature:\n", stdout);
	S->signature->print(S->signature);

	fputs("\nCertificate:\n", stdout);
	S->certificate->print(S->certificate);

	this->validate_report(this, &valid);
	fprintf(stdout, "Signature: %s\n\n", valid ? "VALID" : "INVALID");


	/* Output report. */
	fputs("ID:        ", stdout);
	S->id->print(S->id);

	fputs("Version:   ", stdout);
	S->version->print(S->version);

	fputs("Timestamp: ", stdout);
	S->timestamp->print(S->timestamp);

	if ( S->nonce != NULL ) {
		fputs("Nonce:     ", stdout);
		S->nonce->print(S->nonce);
	}

	fprintf(stdout, "Status:    %s\n", Quote_status[S->status]);


	fputs("\nQuote:\n", stdout);
	fprintf(stdout, "\tversion:    %u\n", S->quote.version);
	fprintf(stdout, "\tsign_type:  %u\n", S->quote.sign_type);

	memcpy(&gid, S->quote.epid_group_id, sizeof(gid));
	fprintf(stdout, "\tgroup id:   0x%08x\n", gid);

	fprintf(stdout, "\tQE svn:     %u\n", S->quote.qe_svn);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (unsigned char *) S->quote.basename, \
			sizeof(S->quote.basename)) )
		ERR(goto done);
	fputs("\tBasename:   ", stdout);
	bufr->print(bufr);

	bp = &S->quote.report_body;
	fputs("\tReport body:\n", stdout);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, bp->cpusvn, sizeof(bp->cpusvn)) )
		ERR(goto done);
	fputs("\t\tcpusvn:      ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\t\tmiscselect:  %u\n", bp->miscselect);
	fprintf(stdout, "\t\tattributes:  flags=0x%0lx, xfrm=0x%0lx\n", \
		bp->attributes.flags, bp->attributes.xfrm);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, bp->mr_enclave.m, sizeof(bp->mr_enclave.m)) )
		ERR(goto done);
	fputs("\t\tmeasurement: ", stdout);
	bufr->print(bufr);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, bp->mrsigner, sizeof(bp->mrsigner)) )
		ERR(goto done);
	fputs("\t\tsigner:      ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\t\tISV prodid:  %u\n", bp->isvprodid);
	fprintf(stdout, "\t\tISV svn:     %u\n", bp->isvsvn);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, bp->reportdata, sizeof(bp->reportdata)) )
		ERR(goto done);
	fputs("\t\treportdata:  ", stdout);
	bufr->print(bufr);


	/* Report platform status. */
	fprintf(stdout, "\nPlatform status: %s\n", Quote_status[S->status]);

	if ( !(S->status == SRDEquote_status_GROUP_OUT_OF_DATE ||
	       S->status == SRDEquote_status_GROUP_REVOKED) )
		goto done;


	/* Output platform information report. */
	fputs("\nPlatform Info Report:\n", stdout);
	plb = &S->platform_info;

	fprintf(stdout, "\tEPID group flags: %u\n", plb->sgx_epid_group_flags);
	if ( plb->sgx_epid_group_flags & 0x1 )
		fputs("\t\tEPID group revoked.\n", stdout);
	if ( plb->sgx_epid_group_flags & 0x2 )
		fputs("\t\tPerformance rekey available.\n", stdout);
	if ( plb->sgx_epid_group_flags & 0x4 )
		fputs("\t\tEPID group out of date.\n", stdout);


	memcpy(&flags, plb->sgx_tcb_evaluation_flags, sizeof(flags));
	flags = ntohs(flags);
	fprintf(stdout, "\n\tTCB evaluation flags: %u\n", flags);
	if ( flags & 0x1 )
		fputs("\t\tCPU svn out of date.\n", stdout);
	if ( flags & 0x2 )
		fputs("\t\tQE enclave out of date.\n", stdout);
	if ( flags & 0x4 )
		fputs("\t\tPCE enclave out of date.\n", stdout);

	memcpy(&flags, plb->pse_evaluation_flags, sizeof(flags));
	flags = ntohs(flags);
	fprintf(stdout, "\n\tPSE evaluation flags: %u\n", flags);

	psvnp = &plb->latest_equivalent_tcb_psvn;
	bufr->reset(bufr);
	if ( !bufr->add(bufr, psvnp->cpu_svn, sizeof(psvnp->cpu_svn)) )
		ERR(goto done);

	fputs("\n\tRecommended platform status:\n", stdout);
	fputs("\t\tCPU svn: ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\t\tISV svn: %u\n", psvnp->isv_svn);

	fprintf(stdout, "\n\tExtended group id: 0x%x\n", plb->xeid);


 done:
	WHACK(bufr);

	return;
}


/**
 * External public method.
 *
 * This method implements the OCALL which requests destruction of
 * the userspace instance of the SRDEquote object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SRDEquote, this))

{
	STATE(S);

	struct SRDEquote_ocall ocall;


	/* Release implementation object. */
	memset(&ocall, '\0', sizeof(struct SRDEquote_ocall));
	ocall.ocall    = SRDEquote_whack;
	ocall.instance = S->instance;
	sgxquote_ocall(&ocall);


	/* Destroy enclave resources. */
	WHACK(S->report);

	WHACK(S->id);
	WHACK(S->version);
	WHACK(S->timestamp);
	WHACK(S->signature);
	WHACK(S->certificate);

	WHACK(S->nonce);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SRDEquote object.
 *
 * \return	A pointer to the initialized SRDEquote.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SRDEquote NAAAIM_SRDEquote_Init(void)

{
	Origin root;

	SRDEquote this = NULL;

	struct HurdLib_Origin_Retn retn;

	struct SRDEquote_ocall ocall;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SRDEquote);
	retn.state_size   = sizeof(struct NAAAIM_SRDEquote_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SRDEquote_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize the untrusted object. */
	memset(&ocall, '\0', sizeof(struct SRDEquote_ocall));
	ocall.ocall = SRDEquote_init_object;
	if ( sgxquote_ocall(&ocall) != 0 )
		goto err;
	this->state->instance = ocall.instance;

	/* Method initialization. */
	this->init = init;

	this->generate_quote  = generate_quote;
	this->generate_report = generate_report;
	this->decode_report   = decode_report;
	this->validate_report = validate_report;

	this->get_qe_targetinfo = get_qe_targetinfo;
	this->get_quoteinfo	= get_quoteinfo;

	this->set_nonce = set_nonce;

	this->development = development;
	this->dump_report = dump_report;
	this->whack	  = whack;

	return this;


 err:
	root->whack(root, this, this->state);
	return NULL;
}
