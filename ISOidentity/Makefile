# ***************************************************************************
# (C)Copyright 2017, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = Actor.c Subject.c ExchangeEvent.c ISOidentity.c ContourPoint.c \
	cboot.c cboot-mgr.c compute-aggregate.c

TOOLS = test-actor test-subject test-event generate-contours sha-tool	  \
	compute-measurement set-behavior cboot cboot-mgr test-ISOidentity \
	compute-aggregate bad-actor

CC = musl-gcc

MUSL_INCLUDE = /usr/local/musl/include

CDEBUG = -g -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG}

LDFLAGS = ${STATIC} -g

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

ELFLIB = -lelf

HURD_LIBRARY = ../HurdLib/libHurdLib.a
HURDLIB	     = -L ../HurdLib -lHurdLib

RDK_LIBRARY = ../SGX/libSGXrdk.a
RDKLIB	    = -L ../SGX -lSGXrdk ${ELFLIB}

NAAAIM_LIBRARY = ../lib/libNAAAIM.a
NAAAIMLIB      = -L ../lib -lNAAAIM

LIBS = ${NAAAIMLIB} ${HURDLIB}

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib -I/usr/local/musl/include \
	-I ../SGX/ISOidentity -I ../SGX


#
# Target directives.
#
.PHONY: all tools

# Targets
all: ${COBJS} tools

tools: ${TOOLS}

test-actor: test-actor.o Actor.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

test-subject: test-subject.o Subject.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

test-event: test-event.o ExchangeEvent.o Actor.o Subject.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

test-ISOidentity: test-ISOidentity.o ISOidentity.o ContourPoint.o \
	ExchangeEvent.o Actor.o Subject.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

generate-contours: generate-contours.o ExchangeEvent.o Actor.o Subject.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

compute-measurement: compute-measurement.o Actor.o Subject.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

compute-aggregate: compute-aggregate.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

bad-actor: bad-actor.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

sha-tool: sha-tool.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

set-behavior: set-behavior.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

cboot: cboot.o ../SGX/ISOidentity/ISOenclave.o ISOidentity.o ContourPoint.o \
	ExchangeEvent.o Actor.o Subject.o ${RDK_LIBRARY}  ${NAAAIM_LIBRARY} \
	${HURD_LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ISOidentity.o ContourPoint.o		    \
		ExchangeEvent.o Actor.o Subject.o 			    \
		../SGX/ISOidentity/ISOenclave.o ${RDKLIB} ${LIBS} ${SSL_CRYPTO}

cboot-mgr: cboot-mgr.o ../SGX/ISOidentity/ISOmanager.o \
	${RDK_LIBRARY} ${NAAAIM_LIBRARY} ${HURD_LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ../SGX/ISOidentity/ISOmanager.o \
		${RDKLIB} ${LIBS} ${SSL_CRYPTO}

tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${TOOLS};


# Source dependencies.
# sgx-metadata.o: SGX.h
# sgx-load.o: SGXenclave.h

Actor.o: Actor.h
ContourPoint.o: ContourPoint.h
ExchangeEvent.o: ExchangeEvent.h
ISOidentity.o: ISOidentity.h
# SGXmetadata.o: SGX.h SGXmetadata.h
# SGXloader.o: SGX.h SGXloader.h
# SGXenclave.o: SGX.h SGXenclave.h SGXmetadata.h SGXloader.h
# SGXsigstruct.o: SGX.h SGXsigstruct.h

cboot.o: cboot.h

cboot-mgr.o: cboot.h
