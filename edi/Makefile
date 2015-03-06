# ***************************************************************************
# (C)Copyright 2014, IDfusion, LLC. All rights reserved.
# ***************************************************************************

CSRC = edi-transmitter.c edi-engine.c edi-receiver.c send-edi.c

BINARIES = edi-transmitter edi-engine edi-receiver send-edi

include ../Makefile.mak


# Executable targets.
edi-engine: edi-engine.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

edi-transmitter: edi-transmitter.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

edi-receiver: edi-receiver.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

send-edi: send-edi.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};
