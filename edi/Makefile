# ***************************************************************************
# (C)Copyright 2014, IDfusion, LLC. All rights reserved.
# ***************************************************************************

CSRC = edi-transmitter.c edi-engine.c edi-receiver.c send-edi.c \
	EDIpacket.c

BINARIES = edi-transmitter edi-engine edi-receiver send-edi

include ../Makefile.mak


# Executable targets.
edi-engine: edi-engine.o EDIpacket.o ../AES256_cbc.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

edi-transmitter: edi-transmitter.o EDIpacket.o ../AES256_cbc.o ../IDtoken.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltspi;

edi-receiver: edi-receiver.o EDIpacket.o ../AES256_cbc.o ../IDtoken.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltspi;

send-edi: send-edi.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

# Source file specific rules.
edi-engine.o: edi-engine.c edi.h
	${CC} ${CFLAGS} -I../utils -I.. -c $< -o $@;

EDIpacket.o: EDIpacket.c EDIpacket.h ../NAAAIM.h
	${CC} ${CFLAGS} -I.. -c $< -o $@;
