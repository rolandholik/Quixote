# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

# Variable declarations.
INSTPATH = ${DESTDIR}/opt/Quixote

ifdef SRDE_PRODUCTION
TYPE = -DSRDE_PRODUCTION
endif

SGXDIR = ../SRDE
include ${SGXDIR}/Make.enclave

SANCHODIR = ../Sancho
SANCHOSGX = ${SANCHODIR}/SGX

CSRC = quixote.c quixote-mcu.c quixote-sgx.c quixote-sgx-u.c \
	quixote-console.c quixote-xen.c test-sancho.c test-sancho-xen.c

TOOLS = quixote quixote-mcu quixote-us quixote-sgx quixote-sgx-u quixote-xen \
	quixote-console test-sancho test-thread test-sancho-xen		     \
	test-domain-creation

INSTALLBIN  = quixote-console
INSTALLSBIN = quixote quixote-mcu quixote-us quixote-sgx quixote-sgx-u \
	quixote-xen

CC = musl-gcc

CDEBUG = -g -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG} ${TYPE}

LDFLAGS = ${STATIC} -g


#
# Compilation directives.
#
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}

HURD_LIBRARY = ../HurdLib/libHurdLib.a
HURDLIB	     = -L ../HurdLib -lHurdLib

NAAAIM_LIBRARY = ../lib/libNAAAIM.a
NAAAIMLIB      = -L ../lib -lNAAAIM

SEDE_LIBRARY = ../libSRDEruntime.a
SEDELIB	     = -L ${SGXDIR} -lSRDEruntime

ELFLIB = -lelf

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

LIBS	= ${NAAAIMLIB} ${HURDLIB} ${LIBCAP} ${SSL_CRYPTO}
LIBDEPS = ${HURD_LIBRARY} ${NAAAIM_LIBRARY}
XENLIBS = ${shell pkg-config --libs xenstore}  \
	${shell pkg-config --libs xengnttab}   \
	${shell pkg-config --libs xentoolcore} \
	${shell pkg-config --libs xentoollog}  \
	${shell pkg-config --libs xenevtchn} -lpthread

MODELDEPS = ../SecurityModel/COE.o ../SecurityModel/Cell.o		  \
	../SecurityModel/SecurityPoint.o ../SecurityModel/SecurityEvent.o \
	../SecurityModel/TSEM.o ../SecurityModel/EventModel.o

CFLAGS := ${CFLAGS} -I .. -I ../SecurityModel -I ../lib -I ../HurdLib \
	-I ${SGXDIR} -I ${SANCHOSGX}

XENCFLAGS = ${shell pkg-config --cflags xenstore}


#
# Target directives.
#
.PHONY: all tools

# Targets
all: ${COBJS} tools

tools: ${TOOLS}

quixote: quixote.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

quixote-mcu: quixote-mcu.o ${LIBDEPS} ${MODELDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${MODELDEPS} ${LIBS};

quixote-us: quixote-us.o ${LIBDEPS} ${MODELDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${MODELDEPS} ${LIBS};

quixote-sgx: quixote-sgx.o ${SANCHOSGX}/SanchoSGX.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${SANCHOSGX}/SanchoSGX.o ${SEDELIB} ${LIBS} \
		${ELFLIB} ${SSL_CRYPTO};

quixote-sgx-u: quixote-sgx-u.o ${SANCHOSGX}/SanchoSGX.o sancho-enclave.h \
	${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${SANCHOSGX}/SanchoSGX.o ${SEDELIB} ${LIBS} \
		${ELFLIB} ${SSL_CRYPTO};

quixote-xen: quixote-xen.o ${LIBDEPS} ${MODELDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${MODELDEPS} ${LIBS} ${XENLIBS};

quixote-xen.o: quixote-xen.c
	${CC} ${CFLAGS} ${XENCFLAGS} -c $< -o $@;

quixote-console: quixote-console.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

test-sancho: test-sancho.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

test-thread: test-thread.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS} -lpthread;

test-sancho-xen: test-sancho-xen.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS} ${XENLIBS};

sancho-enclave.h: ${SANCHOSGX}/SanchoSGX.signed.so
	${SGXDIR}/generate-array -i ${SANCHOSGX}/SanchoSGX.signed.so \
		-n Enclave > $@ || rm $@;

test-domain-creation: test-domain-creation.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

install-bin:
	[ -d ${INSTPATH}/bin ] || mkdir -p ${INSTPATH}/bin;
	install -s ${INSTALLBIN} ${INSTPATH}/bin;
	[ -d ${INSTPATH}/sbin ] || mkdir -p ${INSTPATH}/sbin;
	install -s ${INSTALLSBIN} ${INSTPATH}/sbin;

clean:
	rm -f *.o *~;
	rm -f ${TOOLS};


# Source dependencies.
quixote.o: quixote.h sancho-cmd.h
quixote-us.o: quixote.h sancho-cmd.h
quixote-mcu.o: quixote.h sancho-cmd.h
quixote-sgx-u.o: quixote.h sancho-cmd.h sancho-enclave.h
quixote-console.o: sancho-cmd.h
test-sancho.o: sancho-cmd.h
