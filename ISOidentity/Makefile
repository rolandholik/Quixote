# **************************************************************************
# * (C)Copyright IDfusion, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

# Variable declarations.
INSTPATH       = ${DESTDIR}/opt/IDfusion

CSRC = Actor.c Subject.c ExchangeEvent.c ISOidentity.c ContourPoint.c \
	cboot.c cboot-mgr.c compute-aggregate.c

TOOLS = test-actor test-subject test-event generate-contours sha-tool	  \
	compute-measurement set-behavior cboot cboot-mgr test-ISOidentity \
	compute-aggregate bad-actor
INSTALLBIN  = generate-contours sha-tool cboot-mgr
INSTALLSBIN = set-behavior cboot

CC = musl-gcc

CDEBUG = -g -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG}

LDFLAGS = ${STATIC} -g

# OpenSSL crypto library
ifeq (${CC}, musl-gcc)
SSL_INCLUDE = /usr/local/musl/include
SSL_CRYPTO = -L /usr/local/musl/lib -lcrypto
else
LDFLAGS += -Wl,-rpath=/usr/local/IDfusion/lib
SSL_INCLUDE = /usr/local/IDfusion/include
SSL_CRYPTO = -L /usr/local/IDfusion/lib -lcrypto -ldl -lpthread
endif


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

RDK_LIBRARY = ../SRDE/libSRDEruntime.a
RDKLIB	    = -L ../SRDE -lSRDEruntime ${ELFLIB}

NAAAIM_LIBRARY = ../lib/libNAAAIM.a
NAAAIMLIB      = -L ../lib -lNAAAIM

LIBS = ${NAAAIMLIB} ${HURDLIB}

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib -I ../SRDE/ISOidentity \
	-I ../SRDE


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

cboot: cboot.o ../SRDE/ISOidentity/ISOenclave.o ISOidentity.o ContourPoint.o \
	ExchangeEvent.o Actor.o Subject.o ${RDK_LIBRARY} ${NAAAIM_LIBRARY}   \
	${HURD_LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ISOidentity.o ContourPoint.o		     \
		ExchangeEvent.o Actor.o Subject.o 			     \
		../SRDE/ISOidentity/ISOenclave.o ${RDKLIB} ${LIBS}	     \
		${SSL_CRYPTO}

cboot-mgr: cboot-mgr.o ../SRDE/ISOidentity/ISOmanager.o \
	${RDK_LIBRARY} ${NAAAIM_LIBRARY} ${HURD_LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ../SRDE/ISOidentity/ISOmanager.o \
		${RDKLIB} ${LIBS} ${SSL_CRYPTO}

tags:
	/opt/emacs/bin/etags *.{h,c};

install-bin:
	[ -d ${INSTPATH}/bin ] || mkdir -p ${INSTPATH}/bin;
	install -s ${INSTALLBIN} ${INSTPATH}/bin;
	[ -d ${INSTPATH}/sbin ] || mkdir -p ${INSTPATH}/sbin;
	install -s ${INSTALLSBIN} ${INSTPATH}/sbin;
	[ -e /distrib/SRDE/opt/IDfusion/sbin/runc ] && \
		install /distrib/SRDE/opt/IDfusion/sbin/runc ${INSTPATH}/sbin;

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
# SRDEloader.o: SRDE.h SRDEloader.h
# SGXenclave.o: SRDE.h SRDEenclave.h SGXmetadata.h SRDEloader.h
# SGXsigstruct.o: SRDE.h SGXsigstruct.h

cboot.o: cboot.h

cboot-mgr.o: cboot.h
