# ***************************************************************************
# (C)Copyright 2014, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = Duct.c OTEDKS.c Curve25519.c IPC.c SoftwareStatus.c Ivy.c IDmgr.c \
	PossumPacket.c PossumPipe.c

TESTS = Duct_test OTEDKS_test Curve25519_test IPC_test

CC = musl-gcc

MUSL_INCLUDE = /usr/local/musl/include

LIBNAME = NAAAIM
LIBRARY = lib${LIBNAME}.a

#
# Locations of SSL include files and libraries
#
SSL_INCLUDE = /usr/local/musl/ssl/include
SSL_LIBRARY = -L /usr/local/musl/ssl/lib -l ssl


CDEBUG = -O2 -fomit-frame-pointer -march=core2
CDEBUG = -g ${DMALLOC}

CFLAGS = -Wall ${CDEBUG}

# LDFLAGS = -s -L/usr/local/krb5/lib 
LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib -L../HurdLib 


#
# Compilation directives.
#
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}

CFLAGS := ${CFLAGS} -I.. -I../HurdLib -I${SSL_INCLUDE}


#
# Target directives.
#
.PHONY: all tests


# Targets
all: ${LIBRARY}

${LIBRARY}: ${COBJS}
	ar r ${LIBRARY} $^;
	ranlib ${LIBRARY};

tests: ${TESTS} ${COBJS}

Duct_test: Duct_test.o Duct.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib

OTEDKS_test: OTEDKS_test.o OTEDKS.o ../SHA256.o ../IDtoken.o ../SHA256_hmac.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib -L \
		/usr/local/musl/ssl/lib -l ssl;

Curve25519_test: Curve25519_test.o Curve25519.o ../RandomBuffer.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${SSL_LIBRARY};

IPC_test: IPC_test.o IPC.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib -lrt;

tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${LIBRARY};
	rm -f ${TESTS} OTEDKS.out;


# Source dependencies.
Duct.o: Duct.h ../NAAAIM.h
OTEDKS.o: ../NAAAIM.h OTEDKS.h
Curve25519.o: ../NAAAIM.h Curve25519.h
SoftwareStatus.o: ../NAAAIM.h SoftwareStatus.h

Duct_test.o: Duct.h ../NAAAIM.h
