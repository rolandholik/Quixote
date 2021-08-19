# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

# Variable declarations.
INSTPATH = ${DESTDIR}/opt/ESD

CSRC = quixote.c quixote-console.c test-sancho.c

TOOLS = quixote quixote-us quixote-console test-sancho test-thread

INSTALLBIN  = quixote-console
INSTALLSBIN = quixote quixote-us

CC = musl-gcc

CDEBUG = -g -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG}

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

# OpenSSL crypto library
ifeq (${CC}, musl-gcc)
SSL_INCLUDE = /usr/local/musl/include
SSL_CRYPTO = -L /usr/local/musl/lib -lcrypto
else
LDFLAGS += -Wl,-rpath=/usr/local/ESD/lib
SSL_INCLUDE = /usr/local/ESD/include
SSL_CRYPTO = -L /usr/local/ESD/lib -lcrypto -ldl -lpthread
endif

LIBS	= ${NAAAIMLIB} ${HURDLIB} ${SSL_CRYPTO}
LIBDEPS = ${HURD_LIBRARY} ${NAAAIM_LIBRARY}

MODELDEPS = ../ISOidentity/Actor.o ../ISOidentity/Subject.o	     \
	../ISOidentity/ContourPoint.o ../ISOidentity/ExchangeEvent.o \
	../ISOidentity/ISOidentity.o

CFLAGS := ${CFLAGS} -I.. -I../ISOidentity -I../lib -I../HurdLib


#
# Target directives.
#
.PHONY: all tools

# Targets
all: ${COBJS} tools

tools: ${TOOLS}

quixote: quixote.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

quixote-us: quixote-us.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${MODELDEPS} ${LIBS};

quixote-console: quixote-console.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

test-sancho: test-sancho.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

test-thread: test-thread.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS} -lpthread;

install-bin:
	[ -d ${INSTPATH}/bin ] || mkdir -p ${INSTPATH}/bin;
	install -s ${INSTALLBIN} ${INSTPATH}/bin;
	[ -d ${INSTPATH}/sbin ] || mkdir -p ${INSTPATH}/sbin;
	install -s ${INSTALLSBIN} ${INSTPATH}/sbin;
	[ -e /distrib/SRDE/opt/ESD/sbin/runc ] && \
		install /distrib/SRDE/opt/ESD/sbin/runc ${INSTPATH}/sbin;

clean:
	rm -f *.o *~;
	rm -f ${TOOLS};


# Source dependencies.
quixote.o: sancho-cmd.h
quixote-console.o: sancho-cmd.h
test-sancho.o: sancho-cmd.h
