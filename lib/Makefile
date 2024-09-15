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
INSTINCLUDE = ../NAAAIM.h AES256_cbc.h Base64.h Curve25519.h Duct.h	\
	Duct_mgr.h HTTP.h IDmgr.h IDtoken.h IPC.h Ivy.h LocalDuct.h	\
	OTEDKS.h PossumPacket.h PossumPipe.h RSAkey.h RandomBuffer.h	\
	SHA256.h  SHA256_hmac.h SmartCard.h SoftwareStatus.h		\
	X509cert.h Prompt.h AES128_cmac.h TTYduct.h XENduct.h		\
	TSEMcontrol.h TSEMevent.h TSEMparser.h MQTTduct.h TSEMworkload.h

CSRC = Duct.c OTEDKS.c Curve25519.c IPC.c SoftwareStatus.c Ivy.c IDmgr.c     \
	RSAkey.c LocalDuct.c HTTP.c Base64.c Duct_mgr.c SHA256.c	     \
	SHA256_hmac.c RandomBuffer.c AES256_cbc.c IDtoken.c X509cert.c	     \
	Prompt.c AES128_cmac.c TTYduct.c XENduct.c TSEMcontrol.c TSEMevent.c \
	TSEMparser.c MQTTduct.c TSEMworkload.c

TESTS = Duct_test Curve25519_test IPC_test RSAkey_test			\
	LocalDuct_test X509cert_test Prompt_test AES128_cmac_test	\
	TTYduct_test MQTTduct_test test-parser #SmartCard_test

MOSQUITTO_LIB = -L ${TOPDIR}/Support/mosquitto/lib -l mosquitto -lssl

LIBNAME = NAAAIM
LIBRARY = lib${LIBNAME}.a

SC_INCLUDE = /usr/local/ESD/include/PCSC

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

CINCLUDE := -I .. -I ../HurdLib -I /usr/local/Quixote/include \
	-I ../Support/mosquitto/include

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
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${BUILD_LIBCRYPTO};

Curve25519_test: Curve25519_test.o Curve25519.o RandomBuffer.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${BUILD_LIBCRYPTO};

IPC_test: IPC_test.o IPC.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib -lrt;

RSAkey_test: RSAkey_test.o RSAkey.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${BUILD_LIBCRYPTO}

X509cert_test: X509cert_test.o X509cert.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${BUILD_LIBCRYPTO}

Prompt_test: Prompt_test.o Prompt.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${BUILD_LIBCRYPTO}

AES128_cmac_test: AES128_cmac_test.o AES128_cmac.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${BUILD_LIBCRYPTO}

TTYduct_test: TTYduct_test.o TTYduct.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${BUILD_LIBCRYPTO}

SmartCard_test: SmartCard_test.o SmartCard.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib \
		-L/usr/local/lib -lpcsclite

MQTTduct_test: MQTTduct_test.o MQTTduct.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib ${MOSQUITTO_LIB} \
		${BUILD_LIBCRYPTO}

test-parser: test-parser.o TSEMparser.o
	${CC} ${LDFLAGS} -o $@ $^ -L ../HurdLib -lHurdLib

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
	rm -f ${TESTS} OTEDKS.out;

distclean: clean
	rm -f ${LIBRARY};


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
TSEMworkload.o: TSEMworkload.h TSEMcontrol.h ../NAAAIM.h
MQTTduct.o: MQTTduct.h ../NAAAIM.h
