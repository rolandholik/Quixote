/** \file
 * This file contains header definitions which are needed to support
 * functions exported from the companion reg-support.c file.
 */


wctype_t wctype(const char *s);
int iswctype(wint_t wc, wctype_t type);
