# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************


#
# Include micro-controller build definitions.
#
ifndef MCUCFGDIR
MCUCFGDIR=${shell cd ..; pwd}
endif

include ${MCUCFGDIR}/STmcu.mk


#
# Variable declarations.
#
DEFINES = -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"


#
# Object and source file definitions.
#
LIBSRC = Base64.c RSAkey.c SHA256.c

MBEDSRC = base64.c rsa.c rsa_internal.c bignum.c oid.c platform_util.c \
	pem.c pk.c pk_wrap.c pkparse.c asn1parse.c sha256.c md.c md_wrap.c

CSRC = ${LIBSRC} ${MBEDSRC}

COBJS = ${CSRC:.c=.o}

LIBNAME = NAAAIM
LIBRARY = lib${LIBNAME}.a


#
# Build definitions.
#
CINCLUDE = -I . -I ../.. -I ../../../lib -I ../HurdLib -I ../../../HurdLib \
	-I ${MBEDDIR}/include


CFLAGS = ${PLATFORM} ${DEFINES} ${CDEBUG} ${CINCLUDE} -fno-diagnostics-color \
	-Wall


#
# Compilation directives.
#
%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ../../../HurdLib/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ${MBEDDIR}/library/%.c
	${CC} ${CFLAGS} -c $< -o $@;


#
# Targets
#
all: ${LIBRARY}

${LIBRARY}: ${COBJS}
	${AR} r ${LIBRARY} $^;
	${RANLIB} ${LIBRARY};

clean:
	rm -f ${COBJS} *~;

clobber: clean
	rm -f ${LIBRARY};


# Source dependencies.
Base64.o: ${LIBNAME}.h ../../../lib/Base64.h
RSAkey.o: ${LIBNAME}.h ../../../lib/SHA256.h ../../../lib/RSAkey.h
SHA256.o: ${LIBNAME}.h ../../../lib/SHA256.h
