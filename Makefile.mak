# ***************************************************************************
# (C)Copyright 2015, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CC = musl-gcc
CARGS = -O2 -fomit-frame-pointer -march=core2
CDEBUG = -g
CFLAGS = -Wall ${CARGS} ${CDEBUG}

MUSL_INCLUDE   = -I /usr/local/musl/include
HURD_INCLUDE   = -I ../HurdLib
SSL_INCLUDE    = -I /usr/local/musl/ssl/include
NAAAIM_INCLUDE = -I ../include
INCLUDES = ${MUSL_INCLUDE} ${HURD_INCLUDE} ${SSL_INCLUDE} ${NAAAIM_INCLUDE}

HURD_LIBRARY   = -L ../HurdLib -lHurdLib
SSL_LIBRARY    = -L /usr/local/musl/ssl/lib -lssl
NAAAIM_LIBRARY = -L ../lib -L NAAAIM
LIBS = ${NAAAIM_LIBRARY} ${HURD_LIBRARY} ${SSL_LIBRARY}

LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib ${LIBS}

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
