/** \file
 * This contains the definitions that are used to configure the
 * mbedtls library for the functionality that is needed in the
 * Sancho_Cell implementation.
 */

/**************************************************************************
 * (C)Copyright 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

/* Enable base64 support. */
#define MBEDTLS_BASE64_C

/* Enable message digests. */
#define MBEDTLS_MD_C

/* Enable SHA256. */
#define MBEDTLS_SHA256_C

/* Enable PEM processing. */
#define MBEDTLS_PEM_PARSE_C

/* Enable public key support. */
#define MBEDTLS_PK_C

/* Enable publick key parsing. */
#define MBEDTLS_PK_PARSE_C

/* Enable ASN1 processing .*/
#define MBEDTLS_ASN1_PARSE_C

/* Enable big number support. */
#define MBEDTLS_BIGNUM_C

/* Enable OID support. */
#define  MBEDTLS_OID_C

/* Enable C implementation of RSA support. */
#define MBEDTLS_RSA_C

/* Enable PKCS1.15 padding .*/
#define MBEDTLS_PKCS1_V15

/* Enable OAEP padding. */
#define MBEDTLS_PKCS1_V21

/* Enable prime number generation. */
#define MBEDTLS_GENPRIME

/* Include the configuration checker. */
#include <mbedtls/check_config.h>
