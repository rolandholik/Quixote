# ***************************************************************************
# Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = idgine.c Identity.c IDengine.c

BINARIES = idgine gen-id idsvr fetch-id recip-svr fwd-id

CC = musl-gcc


#
# Locations of SSL include files and libraries
#
ifeq (${CC}, musl-gcc)
SSL_INCLUDE = /usr/local/musl/include
SSL_CRYPTO = -L /usr/local/musl/lib -lcrypto
else
SSL_INCLUDE = /usr/local/IDfusion/include
SSL_CRYPTO = -L /usr/local/IDfusion/lib -lcrypto -ldl -lpthread
endif


CDEBUG = -O2 -fomit-frame-pointer -march=core2
CDEBUG = -g ${DMALLOC}

CFLAGS = -Wall ${CDEBUG}

LDFLAGS = -g -L ../lib -L ../HurdLib
ifneq (${CC}, musl-gcc)
LDFLAGS += -lrt -Wl,-rpath=/usr/local/IDfusion/lib
endif


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

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib -I${SSL_INCLUDE}


#
# Target directives.
#
.PHONY: all binaries

# Targets
all: ${COBJS} binaries

binaries: ${BINARIES}

idgine: idgine.o IDengine.o Identity.o ../OrgID.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO} -lfl;

gen-id: gen-id.o IDengine.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

idsvr: idsvr.o IDengine.o Identity.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

fetch-id: fetch-id.o IDengine.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

recip-svr: recip-svr.o IDengine.o Identity.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

fwd-id: fwd-id.o IDengine.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

install-bin:
	@echo "Nothing to install.";

clean:
	rm -f *.o *~ TAGS;
	rm -f ${BINARIES};


# Source dependencies.
idgine.o: IDengine.h

idsvr.o: Identity.h IDengine.h
fetch-id.o: Identity.h IDengine.h 

IDengine.o: IDengine.h
Identity.o: Identity.h
