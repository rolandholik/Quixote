# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/


# Variable declarations.
INSTPATH = ${DESTDIR}/opt/ESD
INSTINCLUDE = ../NAAAIM.h AES256_cbc.h Base64.h Curve25519.h Duct.h	\
	Duct_mgr.h HTTP.h IDmgr.h IDtoken.h IPC.h Ivy.h LocalDuct.h	\
	OTEDKS.h PossumPacket.h PossumPipe.h RSAkey.h RandomBuffer.h	\
	SHA256.h  SHA256_hmac.h SmartCard.h SoftwareStatus.h TPM2cmd.h	\
	X509cert.h Prompt.h TPMcmd.h AES128_cmac.h TTYduct.h XENduct.h	\
	TSEMcontrol.h

CSRC = Duct.c OTEDKS.c Curve25519.c IPC.c SoftwareStatus.c Ivy.c IDmgr.c    \
	TPMcmd.c TPM2cmd.c PossumPacket.c PossumPipe.c RSAkey.c SmartCard.c \
	LocalDuct.c HTTP.c Base64.c Duct_mgr.c SHA256.c SHA256_hmac.c	    \
	RandomBuffer.c AES256_cbc.c IDtoken.c X509cert.c Prompt.c	    \
	AES128_cmac.c TTYduct.c XENduct.c TSEMcontrol.c

TESTS = Duct_test Curve25519_test IPC_test PossumPipe_test RSAkey_test \
	LocalDuct_test X509cert_test Prompt_test AES128_cmac_test      \
	TTYduct_test #SmartCard_test

CC = musl-gcc

LIBNAME = NAAAIM
LIBRARY = lib${LIBNAME}.a


#
# Locations of SSL include files and libraries
#

ifeq (${CC}, musl-gcc)
SSL_INCLUDE = /usr/local/musl/include
SSL_CRYPTO = -L /usr/local/musl/lib -lcrypto
SC_INCLUDE = /usr/local/include/PCSC
else
SSL_INCLUDE = /usr/local/ESD/include
SSL_CRYPTO = -Wl,-rpath=/usr/local/ESD/lib -L /usr/local/ESD/lib \
	-lcrypto
SC_INCLUDE = /usr/local/ESD/include/PCSC
endif


CDEBUG = -O2 -fomit-frame-pointer -march=core2
CDEBUG = -g ${DMALLOC}

CFLAGS	  = -Wall -fpic ${CDEBUG}
XENCFLAGS = ${shell pkg-config --cflags xenstore}

LDFLAGS = -g -L ../HurdLib 


#
# Compilation directives.
#
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}

CINCLUDE := -I .. -I ../HurdLib -I ${SSL_INCLUDE} -I /usr/local/Quixote/include

CFLAGS := ${CFLAGS} ${CINCLUDE}


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

LocalDuct_test: LocalDuct_test.o LocalDuct.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib

OTEDKS_test: OTEDKS_test.o OTEDKS.o IDtoken.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${SSL_CRYPTO};

Curve25519_test: Curve25519_test.o Curve25519.o RandomBuffer.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${SSL_CRYPTO};

IPC_test: IPC_test.o IPC.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib -lrt;

PossumPipe_test: PossumPipe_test.o PossumPipe.o IDtoken.o
	${CC} ${LDFLAGS} -o $@ $^ -L . -lNAAAIM -L../HurdLib -lHurdLib \
	${SSL_CRYPTO} -lrt -ltspi;

RSAkey_test: RSAkey_test.o RSAkey.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${SSL_CRYPTO}

X509cert_test: X509cert_test.o X509cert.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${SSL_CRYPTO}

Prompt_test: Prompt_test.o Prompt.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${SSL_CRYPTO}

AES128_cmac_test: AES128_cmac_test.o AES128_cmac.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${SSL_CRYPTO}

TTYduct_test: TTYduct_test.o TTYduct.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${SSL_CRYPTO}

SmartCard_test: SmartCard_test.o SmartCard.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib \
		-L/usr/local/lib -lpcsclite

SmartCard.o: SmartCard.c SmartCard.h
	$(CC) $(CFLAGS) -I ${SC_INCLUDE} -c $< -o $@;

XENduct.o: XENduct.c
	${CC} ${CFLAGS} ${XENCFLAGS} -c $< -o $@;

install-dev:
	[ -d ${INSTPATH}/include ] || mkdir -p ${INSTPATH}/include;
	[ -d ${INSTPATH}/include/NAAAIM ] || \
		mkdir -p ${INSTPATH}/include/NAAAIM;
	install -m 644 ${INSTINCLUDE} ${INSTPATH}/include/NAAAIM;
	[ -d ${INSTPATH}/lib ] || mkdir -p ${INSTPATH}/lib;
	install -m 644 ${LIBRARY} ${INSTPATH}/lib;

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

PossumPipe.o: ../NAAAIM.h PossumPipe.h Duct.h SoftwareStatus.h Curve25519.h \
	PossumPacket.h IDmgr.h Ivy.h TPMcmd.h

Duct_test.o: Duct.h ../NAAAIM.h
PossumpPipe_test.o: PossumPipe.h
X509cert_test: X509cert.o ../NAAAIM.h
RSAkey.o: RSAkey.h
TPM2cmd.o: TPM2cmd.h ../NAAAIM.h
SHA256.o: SHA256.h ../NAAAIM.h
SHA256_hmac.o: SHA256_hmac.h ../NAAAIM.h
RandomBuffer.o: RandomBuffer.h ../NAAAIM.h
AES256_cbc.o: AES256_cbc.h ../NAAAIM.h
IDtoken.o: IDtoken.h SHA256.h SHA256_hmac.h ../NAAAIM.h
X509cert.o: X509cert.h ../NAAAIM.h
Prompt.o: Prompt.h ../NAAAIM.h
AES128_cmac.o : AES128_cmac.h ../NAAAIM.h
TTYduct.o: TTYduct.h ../NAAAIM.h
XENduct.o: XENduct.h ../NAAAIM.h
TSEMcontrol.o: TSEMcontrol.h ../NAAAIM.h
