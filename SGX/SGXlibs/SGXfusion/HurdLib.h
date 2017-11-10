/** \file
 * This file is the object identifier file for the HurdLib object
 * library.
 */

/**************************************************************************
 * (C)Copyright 2006, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


#ifndef HurdLib_HEADER
#define HurdLib_HEADER

/*
 * Include definitions for shim code.
 */
#include <fusion-shim.h>

/*
 * The following definitions are used to implement source size
 * optimizations for various commonly used routines.
 */

/* Macro for defining a pointer to a constant object. */
#define CO(obj, var) const obj const var

/* Macro to implement safe object destruction. */
#define WHACK(obj) if (obj != NULL) {obj->whack(obj); obj = NULL;}

/* No argument object initialization macros. */
#define _CCALL(lib,obj,init) lib##_##obj##_##init
#define INIT(lib, obj, var, action) \
	if ( (var = _CCALL(lib,obj,Init)()) == NULL ) action

#define ERR(action) {fprintf(stderr, "[%s,%s,%d]: Error location.\n", __FILE__, __func__, __LINE__); action;}


/* Library memory debugging. */
#if defined(DMALLOC)
#include <dmalloc.h>
#endif


/* HurdLib numeric object identifier. */
#define HurdLib_LIBID 1


/* Numeric object identifiers. */
#define HurdLib_Origin_OBJID		1
#define HurdLib_Fibsequence_OBJID	2
#define HurdLib_Buffer_OBJID		3
#define HurdLib_String_OBJID		4
#define HurdLib_Config_OBJID		5
#define HurdLib_File_OBJID		6

#endif
