# ***************************************************************************
# (C)Copyright 2014, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = idgine.c Identity.c IDengine.c

BINARIES = idgine gen-id idsvr fetch-id recip-svr fwd-id

CC = musl-gcc

MUSL_INCLUDE = /usr/local/musl/include

#
# Locations of SSL include files and libraries
#
SSL_INCLUDE = /usr/local/musl/ssl/include
SSL_LIBRARY = -L /usr/local/musl/ssl/lib -l ssl -l crypto


CDEBUG = -O2 -fomit-frame-pointer -march=core2
CDEBUG = -g ${DMALLOC}

CFLAGS = -Wall ${CDEBUG}

# LDFLAGS = -s -L/usr/local/krb5/lib 
LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib -L../lib -L../HurdLib


#
# Compilation directives.
#
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}

LIBS = -lNAAAIM -lHurdLib

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib -I${SSL_INCLUDE} \
	-I${MUSL_INCLUDE}/tss


#
# Target directives.
#
.PHONY: all binaries

# Targets
all: ${COBJS} binaries

binaries: ${BINARIES}

idgine: idgine.o IDengine.o Identity.o ../OrgID.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY} -lfl;

gen-id: gen-id.o IDengine.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

idsvr: idsvr.o IDengine.o Identity.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

fetch-id: fetch-id.o IDengine.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

recip-svr: recip-svr.o IDengine.o Identity.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

fwd-id: fwd-id.o IDengine.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

clean:
	rm -f *.o *~ TAGS;
	rm -f ${BINARIES};


# Source dependencies.
idgine.o: IDengine.h

idsvr.o: Identity.h IDengine.h
fetch-id.o: Identity.h IDengine.h 

IDengine.o: IDengine.h
Identity.o: Identity.h
