/** \file
 * This file contains header definitions which are needed to support
 * functions exported from the companion reg-support.c file.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

wctype_t wctype(const char *s);
int iswctype(wint_t wc, wctype_t type);
