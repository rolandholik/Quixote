# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

# Variable declarations.
CC = musl-gcc
CARGS = -O2 -fomit-frame-pointer -march=core2
CDEBUG = -g
CFLAGS = -Wall ${CARGS} ${CDEBUG}

MUSL_INCLUDE   = -I /usr/local/musl/include
HURD_INCLUDE   = -I ../HurdLib
SSL_INCLUDE    = -I /usr/local/musl/ssl/include
NAAAIM_INCLUDE = -I ../lib
INCLUDES = ${MUSL_INCLUDE} ${HURD_INCLUDE} ${SSL_INCLUDE} ${NAAAIM_INCLUDE}

HURD_LIBRARY   = -L ../HurdLib -lHurdLib
SSL_LIBRARY    = -L /usr/local/musl/ssl/lib -lssl
NAAAIM_LIBRARY = -L ../lib -lNAAAIM
LIBS = ${NAAAIM_LIBRARY} ${HURD_LIBRARY} ${SSL_LIBRARY}

LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib

CFLAGS := ${CFLAGS} ${INCLUDES}


#
# Compilation directives.
#
%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}


#
# Default targets.
#
all: ${COBJS} binaries

binaries: ${BINARIES}

clean:
	rm -f *.o *~ TAGS;
	rm -f ${BINARIES};
