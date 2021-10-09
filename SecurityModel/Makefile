# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

# Variable declarations.
INSTPATH       = ${DESTDIR}/opt/ESD

SANCHODIR = ../Sancho/SGX

CSRC = COE.c Cell.c SecurityEvent.c SecurityPoint.c TSEM.c cboot.c \
	cboot-mgr.c compute-aggregate.c

TOOLS = test-coe test-subject test-event generate-contours sha-tool	  \
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

test-coe: test-coe.o COE.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

test-subject: test-subject.o Cell.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

test-event: test-event.o SecurityEvent.o COE.o Cell.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

test-ISOidentity: test-ISOidentity.o TSEM.o SecurityPoint.o SecurityEvent.o \
	COE.o Cell.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

generate-contours: generate-contours.o SecurityEvent.o COE.o Cell.o
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

cboot: cboot.o ${SANCHODIR}/SanchoSGX.o TSEM.o SecurityPoint.o		\
	SecurityEvent.o COE.o Cell.o ${RDK_LIBRARY} ${NAAAIM_LIBRARY}	\
	${HURD_LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< TSEM.o SecurityPoint.o COE.o Cell.o	   \
		SecurityEvent.o ${SANCHODIR}/SanchoSGX.o ${RDKLIB} ${LIBS} \
		${LIBCAP} ${SSL_CRYPTO};

cboot-mgr: cboot-mgr.o ${SANCHODIR}/ISOmanager.o ${RDK_LIBRARY} \
	${NAAAIM_LIBRARY} ${HURD_LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ${SANCHODIR}/ISOmanager.o ${RDKLIB} \
		${LIBS} ${SSL_CRYPTO};

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
	rm -f ${TOOLS};


# Source dependencies.
# srde-metadata.o: SGX.h
# srde-load.o: SGXenclave.h

COE.o: COE.h
SecurityPoint.o: SecurityPoint.h
SecurityEvent.o: SecurityEvent.h
TSEM.o: TSEM.h

# SRDEmetadata.o: SGX.h SRDEmetadata.h
# SRDEloader.o: SRDE.h SRDEloader.h
# SGXenclave.o: SRDE.h SRDEenclave.h SRDEmetadata.h SRDEloader.h
# SRDEsigstruct.o: SRDE.h SRDEsigstruct.h

cboot.o: cboot.h

cboot-mgr.o: cboot.h
