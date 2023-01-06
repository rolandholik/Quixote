/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Code generation macros. */
/* Macro for setting error location. */
#if 0
#define NAAAIM_DEBUG
#endif


/* The size of an individual identity in bytes. */
#define NAAAIM_IDSIZE 32


/* Numeric library identifier. */
#define NAAAIM_LIBID 3

/* Object identifiers. */
#define NAAAIM_SHA256_OBJID		1
#define NAAAIM_RSAkey_OBJID		3
#define NAAAIM_Base64_OBJID		31
#define NAAAIM_XENduct_OBJID		33
#define NAAAIM_COE_OBJID		46
#define NAAAIM_Cell_OBJID		47
#define NAAAIM_SecurityEvent_OBJID	48
#define NAAAIM_TSEM_OBJID		49
#define NAAAIM_SecurityPoint_OBJID	50
#define NAAAIM_EventModel_OBJID		51
#define NAAAIM_EventParser_OBJID	52


/* Error handling macro. */
#define ERR(action) {fprintf(stderr, "[%s,%s,%d]: Error location.\n", __FILE__, __func__, __LINE__); action;}
