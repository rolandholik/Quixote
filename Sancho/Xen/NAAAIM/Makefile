# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************


#
# Include stubdomain build definitions.
#
ifndef XENCFGDIR
XENCFGDIR=${shell cd ..; pwd}
endif

include ${XENCFGDIR}/Config.mk

TARGET_CPPFLAGS = -U __linux__ -U __FreeBSD__ -U __sun__ -nostdinc	\
	-isystem ../mini-os/include				\
	-isystem ../mini-os/include/posix			\
	-isystem ../newlib-root/x86_64-xen-elf/include		\
	-isystem /usr/lib/gcc/x86_64-unknown-linux-gnu/4.9.4/include	\
	-isystem ../mini-os/include/x86					\
	-isystem ../mini-os/include/x86/x86_64

DEFINES = -DHAVE_LIBC -D__MINIOS__ -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"

MBEDDIR	  = /u/usr/sources/Development_STM/mbedtls-2.16.11


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
# Compilation definitions.
#
CINCLUDE = -I . -I ../.. -I ../../../lib -I ../../../HurdLib \
	-I ${MBEDDIR}/include

CFLAGS = ${PLATFORM} ${DEFINES} ${TARGET_CPPFLAGS} ${CDEBUG} ${CINCLUDE} -Wall


#
# Compilation directives.
#
%.o: %.c
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
