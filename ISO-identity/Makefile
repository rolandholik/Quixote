# ***************************************************************************
# (C)Copyright 2017, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = Actor.c Subject.c cboot.c cboot-mgr.c

TOOLS = test-actor test-subject generate-contours sha-tool \
	compute-measurement set-behavior cboot cboot-mgr

CC = musl-gcc

MUSL_INCLUDE = /usr/local/musl/include

CDEBUG = -g -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG}

LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib -L../lib -L../HurdLib

# OpenSSL crypto library
SSL_CRYPTO  = -L /usr/local/musl/lib -lcrypto


#
# Compilation directives.
#
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@;

%.o: %.s
	${AS} -o $@ $<;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}
AOBJS = ${ASRC:.s=.o}

LIBS = -lNAAAIM -lHurdLib 

HURDLIB = -L../lib -lHurdLib

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib -I/usr/local/musl/include


#
# Target directives.
#
.PHONY: all tools

# Targets
all: ${COBJS} tools

tools: ${TOOLS}

test-actor: test-actor.o Actor.o
	${CC} ${LDFLAGS} -o $@ $^ ../SHA256.o ${HURDLIB} ${SSL_CRYPTO};

test-subject: test-subject.o Subject.o
	${CC} ${LDFLAGS} -o $@ $^ ../SHA256.o ${HURDLIB} ${SSL_CRYPTO};

generate-contours: generate-contours.o Actor.o Subject.o
	${CC} ${LDFLAGS} -o $@ $^ ../SHA256.o ${HURDLIB} ${SSL_CRYPTO};

compute-measurement: compute-measurement.o Actor.o Subject.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${HURDLIB} ${SSL_CRYPTO};

sha-tool: sha-tool.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${HURDLIB} ${SSL_CRYPTO};

set-behavior: set-behavior.o
	${CC} ${LDFLAGS} -o $@ $^ ${HURDLIB}

cboot: cboot.o ../SHA256.o ../SGX/SGXenclave.o ../SGX/SGXloader.o	\
	../SGX/SGXmetadata.o ../SGX/SGXsigstruct.o ../SGX/boot-sgx.o	\
	../SGX/sgx-ocall.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO} \
		-Wl,--rpath /usr/local/musl/lib -lelf

cboot-mgr: cboot-mgr.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${TOOLS};


# Source dependencies.
# sgx-metadata.o: SGX.h
# sgx-load.o: SGXenclave.h

Actor.o: Actor.h
# SGXmetadata.o: SGX.h SGXmetadata.h
# SGXloader.o: SGX.h SGXloader.h
# SGXenclave.o: SGX.h SGXenclave.h SGXmetadata.h SGXloader.h
# SGXsigstruct.o: SGX.h SGXsigstruct.h

cboot.o: cboot.h

cboot-mgr.o: cboot.h
