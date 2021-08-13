# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

# Variable declarations.
INSTPATH = ${DESTDIR}/opt/ESD

CSRC = quixote.c quixote-console.c test-sancho.c

TOOLS = quixote quixote-console test-sancho test-thread

INSTALLBIN  = quixote-console
INSTALLSBIN = quixote

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

LIBS	= ${NAAAIMLIB} ${HURDLIB}
LIBDEPS = ${HURD_LIBRARY} ${NAAAIM_LIBRARY}

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib


#
# Target directives.
#
.PHONY: all tools

# Targets
all: ${COBJS} tools

tools: ${TOOLS}

quixote: quixote.o ${LIBDEPS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

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
