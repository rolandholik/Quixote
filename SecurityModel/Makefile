# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/


#
# Include global build definitions if this is a sub-directory build.
#
ifndef BUILD_CONFIG
include ${shell cd ..; pwd}/Build.mk
endif

# Variable declarations.
INSTPATH       = ${DESTDIR}/opt/Quixote

SANCHODIR = ../Sancho/SGX

CSRC = COE.c Cell.c SecurityEvent.c SecurityPoint.c TSEM.c EventModel.c \
	compute-aggregate.c generate-pseudonym.c generate-states.c

TOOLS = test-COE test-cell test-event generate-states sha-tool		\
	compute-measurement set-behavior test-TSEM compute-aggregate	\
	bad-actor sign-model generate-pseudonym

INSTALLBIN  = generate-states generate-pseudonym sign-model
INSTALLSBIN = set-behavior

CC = musl-gcc

CDEBUG = -g -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG}

LDFLAGS = ${STATIC} -g

# OpenSSL crypto library
ifeq (${CC}, musl-gcc)
SSL_INCLUDE = /usr/local/musl/include
SSL_CRYPTO = -L /usr/local/musl/lib -lcrypto
else
LDFLAGS += -Wl,-rpath=/usr/local/ESD/lib
SSL_INCLUDE = /usr/local/ESD/include
SSL_CRYPTO = -L /usr/local/ESD/lib -lcrypto -ldl -lpthread
endif

# libcap library
ifeq (${CC}, musl-gcc)
LIBCAP = -L /usr/local/musl/lib -lcap
else
LIBCAP = -lcap
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

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib -I ${SANCHODIR} -I ../SRDE


#
# Target directives.
#
.PHONY: all tools

# Targets
all: ${COBJS} tools

tools: ${TOOLS}

test-COE: test-COE.o COE.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

test-cell: test-cell.o Cell.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

test-event: test-event.o SecurityEvent.o COE.o Cell.o EventModel.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

test-TSEM: test-TSEM.o TSEM.o SecurityPoint.o SecurityEvent.o COE.o Cell.o \
	EventModel.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

generate-states: generate-states.o SecurityEvent.o COE.o Cell.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

compute-measurement: compute-measurement.o COE.o Cell.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

compute-aggregate: compute-aggregate.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

bad-actor: bad-actor.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

sha-tool: sha-tool.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

set-behavior: set-behavior.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

sign-model: sign-model.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

generate-pseudonym: generate-pseudonym.o Cell.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

tags:
	/opt/emacs/bin/etags *.{h,c};

install-bin:
	[ -d ${INSTPATH}/bin ] || mkdir -p ${INSTPATH}/bin;
	install -s ${INSTALLBIN} ${INSTPATH}/bin;
	[ -d ${INSTPATH}/sbin ] || mkdir -p ${INSTPATH}/sbin;
	install -s ${INSTALLSBIN} ${INSTPATH}/sbin;
	[ -e /distrib/SRDE/opt/ESD/sbin/runc ] && \
		install /distrib/SRDE/opt/ESD/sbin/runc ${INSTPATH}/sbin;

clean:
	rm -f *.o *~ TAGS;

distclean: clean
	rm -f ${TOOLS};


# Source dependencies.
# srde-metadata.o: SGX.h
# srde-load.o: SGXenclave.h

COE.o: COE.h
SecurityPoint.o: SecurityPoint.h
SecurityEvent.o: SecurityEvent.h
TSEM.o: TSEM.h
EventModel.o: EventModel.h SecurityEvent.h

# SRDEmetadata.o: SGX.h SRDEmetadata.h
# SRDEloader.o: SRDE.h SRDEloader.h
# SGXenclave.o: SRDE.h SRDEenclave.h SRDEmetadata.h SRDEloader.h
# SRDEsigstruct.o: SRDE.h SRDEsigstruct.h
