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
INSTPATH = ${BUILD_INSTPATH}

SANCHODIR = ../Sancho/SGX

CSRC = COE.c Cell.c SecurityEvent.c SecurityPoint.c TSEM.c EventModel.c \
	EventParser.c compute-aggregate.c generate-pseudonym.c		\
	generate-states.c test-parser.c

TOOLS = test-COE test-cell test-event generate-states sha-tool	   \
	compute-measurement test-TSEM compute-aggregate	sign-model \
	generate-pseudonym test-parser

INSTALLBIN  = generate-states generate-pseudonym sign-model

CDEBUG = -g -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG}

LDFLAGS = ${BUILD_LDFLAGS}

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

HURD_LIBRARY = ../HurdLib/libHurdLib.a
HURDLIB	     = -L ../HurdLib -lHurdLib

RDK_LIBRARY = ../SRDE/libSRDEruntime.a
RDKLIB	    = -L ../SRDE -lSRDEruntime ${BUILD_ELFLIB}

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

test-COE: test-COE.o COE.o EventParser.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${BUILD_LIBCRYPTO};

test-cell: test-cell.o Cell.o EventParser.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${BUILD_LIBCRYPTO};

test-event: test-event.o SecurityEvent.o COE.o Cell.o EventModel.o \
	EventParser.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${BUILD_LIBCRYPTO};

test-TSEM: test-TSEM.o TSEM.o SecurityPoint.o SecurityEvent.o COE.o Cell.o \
	EventModel.o EventParser.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${BUILD_LIBCRYPTO};

generate-states: generate-states.o SecurityEvent.o EventParser.o COE.o Cell.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${BUILD_LIBCRYPTO};

compute-measurement: compute-measurement.o COE.o Cell.o EventParser.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${BUILD_LIBCRYPTO};

compute-aggregate: compute-aggregate.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${BUILD_LIBCRYPTO};

sha-tool: sha-tool.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${BUILD_LIBCRYPTO};

sign-model: sign-model.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${BUILD_LIBCRYPTO};

generate-pseudonym: generate-pseudonym.o Cell.o EventParser.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${BUILD_LIBCRYPTO};

test-parser: test-parser.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

tags:
	/opt/emacs/bin/etags *.{h,c};

install-bin:
	install -s ${INSTALLBIN} ${INSTPATH}/bin;

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
EventParser.o: EventParser.h

# SRDEmetadata.o: SGX.h SRDEmetadata.h
# SRDEloader.o: SRDE.h SRDEloader.h
# SGXenclave.o: SRDE.h SRDEenclave.h SRDEmetadata.h SRDEloader.h
# SRDEsigstruct.o: SRDE.h SRDEsigstruct.h
