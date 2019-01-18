# ***************************************************************************
# (C)Copyright 2017, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC   = test-naaaim.c
ENCSRC = test-naaaim-enclave.c test-naaaim-interface.c
LIBSRC = SHA256.c RandomBuffer.c Curve25519.c SHA256_hmac.c AES256_cbc.c \
	Duct.c SGXquote.c Base64.c IDtoken.c PossumPacket.c PossumPipe.c \
	SoftwareStatus.c OTEDKS.c IDmgr.c Ivy.c ssl-ocall.c
ASRC   = rdrand.s

DUCTSRC	  = test-Duct-enclave.c test-Duct-interface.c
POSSUMSRC = test-Possum-enclave.c test-Possum-interface.c RandomBuffer.c

TOOLS = test-naaaim test-Duct test-Possum

LIBNAME = SGXnaaaim
LIBRARY = lib${LIBNAME}.a

ENCLAVE_CC = gcc64

SGX_SDK	    = /opt/intel/sgxsdk
SGX_SSL	= /opt/intel/sgxssl
SGX_INCLUDE = -I . -I ${SGX_SDK}/include -I ${SGX_SDK}/include/tlibc \
	-I ${SGX_SDK}/include/stlport -I ../SGXfusion -I ../../../lib \
	-I ../.. -I ${SGX_SSL}/include

ENCLAVE_CFLAGS = -Wall -nostdinc -fvisibility=hidden -fpie -fstack-protector \
	${SGX_INCLUDE} -fno-builtin

SGX_LIBRARY_PATH = ${SGX_SDK}/lib64
SSL_LIBRARY_PATH = ${SGX_SSL}/lib64

SGX_TRTS_LIB	    = sgx_trts
SGX_CRYPTO_LIB	    = sgx_tcrypto
SGX_SERVICE_LIBRARY = sgx_tservice

ENCLAVE_LDFLAGS = -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles  \
	-Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive	     \
	-L${SGX_LIBRARY_PATH} -L${SSL_LIBRARY_PATH} -L . -L ../SGXfusion     \
	-Wl,--whole-archive						     \
	-l${SGX_TRTS_LIB} -lSGXfusion					     \
	-Wl,--no-whole-archive						     \
	-Wl,--start-group						     \
	-lsgx_tstdc -l${SGX_CRYPTO_LIB} -l${SGX_SERVICE_LIBRARY} -lSGXnaaaim \
	-lsgx_tsgxssl_crypto						     \
	-lsgx_tcxx							     \
	-Wl,--end-group							     \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined			     \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic			     \
	-Wl,--defsym,__ImageBase=0					     \
	-Wl,--version-script=ldscript

SGX_SIGNER = ${SGX_SDK}/bin/sgx_sign


CC = musl-gcc

CFLAGS = -Wall -O2 -fomit-frame-pointer -march=core2 -I ../.. -I ../../.. \
	-I ../../../HurdLib 

LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib

ELFLIB = -Wl,-rpath /usr/local/musl/lib -lelf

HURD_LIBRARY = ../../../HurdLib/libHurdLib.a
HURDLIB	     = -L ../../../HurdLib -lHurdLib

NAAAIM_LIBRARY = ../../../lib/libNAAAIM.a
NAAAIMLIB      = -L ../../../lib -lNAAAIM

RDK_LIBRARY = ../../libSGXrdk.a
RDKLIB	    = -L ../../ -lSGXrdk

SSL_CRYPTO  = -L /usr/local/musl/lib -lcrypto

LIBRARY_DEPENDS = ${HURD_LIBRARY} ${NAAAIM_LIBRARY} ${RDK_LIBRARY}
LIBS		= ${RDKLIB} ${ELFLIB} ${NAAAIMLIB} ${HURDLIB}


#
# Compilation directives.
#
%.o: %.c
	${ENCLAVE_CC} ${ENCLAVE_CFLAGS} -c $< -o $@;

%.o: ../../../lib/%.c
	$(ENCLAVE_CC) $(ENCLAVE_CFLAGS) -c $< -o $@;

%.o: %.s
	${AS} -o $@ $<;


#
# Automatic definition of classes and objects.
#
COBJS	   = ${CSRC:.c=.o}
LIBOBJS	   = ${LIBSRC:.c=.o} ${ASRC:.s=.o}
ENCOBJS	   = ${ENCSRC:.c=.o}
DUCTOBJS   = ${DUCTSRC:.c=.o}
POSSUMOBJS = ${POSSUMSRC:.c=.o}


#
# Target directives.
#
.PHONY: all tools enclave LDscript


# Targets
all: ${LIBRARY} enclave tools

enclave: ldscript test-naaaim.signed.so test-Duct.signed.so \
	test-Possum.signed.so

test-naaaim.signed.so: test-naaaim.so
	${SGX_SIGNER} sign -key Private-key.pem -enclave $^ -out $@ \
		-config test-naaaim-enclave.xml;

test-naaaim.so: ${ENCOBJS} ${LIBRARY}
	${ENCLAVE_CC} -o $@ ${ENCOBJS} ${ENCLAVE_LDFLAGS};

test-Duct.signed.so: test-Duct.so
	${SGX_SIGNER} sign -key Private-key.pem -enclave $^ -out $@ \
		-config test-Duct-enclave.xml;

test-Duct.so: ${DUCTOBJS} ${LIBRARY}
	${ENCLAVE_CC} -o $@ ${DUCTOBJS} ${ENCLAVE_LDFLAGS};

test-Possum.signed.so: test-Possum.so
	${SGX_SIGNER} sign -key Private-key.pem -enclave $^ -out $@ \
		-config test-Possum-enclave.xml;

test-Possum.so: ${POSSUMOBJS} ${LIBRARY}
	${ENCLAVE_CC} -o $@ ${POSSUMOBJS} ${ENCLAVE_LDFLAGS};

ldscript:
	echo "{"			>  ldscript;
	echo "global:"			>> ldscript;
	echo "g_global_data_sim;"	>> ldscript;
	echo "g_global_data;"		>> ldscript;
	echo "enclave_entry;"		>> ldscript;
	echo "local:"			>> ldscript;
	echo "*;"			>> ldscript;
	echo "};"			>> ldscript;


tools: ${TOOLS}

test-naaaim: test-naaaim.o ${LIBRARY_DEPENDS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

test-naaaim.o: test-naaaim.c
	${CC} ${CFLAGS} -c $< -o $@;

test-Duct: test-Duct.o ${LIBRARY_DEPDNDS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

test-Duct.o: test-Duct.c
	${CC} ${CFLAGS} -I ../../../lib -c $< -o $@;

test-Possum: test-Possum.o ../../../IDtoken.o ../../../SHA256.o \
	../../../SHA256_hmac.o ${LIBRARY_DEPENDS}
	${CC} ${LDFLAGS} -o $@ $< ../../../IDtoken.o ../../../SHA256.o \
		../../../SHA256_hmac.o ${LIBS} ${SSL_CRYPTO};

test-Possum.o: test-Possum.c
	${CC} ${CFLAGS} -I ../../../lib -c $< -o $@;

${LIBRARY}: ${LIBOBJS}
	ar r ${LIBRARY} $^;
	ranlib ${LIBRARY};

clean:
	rm -f *.o *~ ldscript;
	rm -f ${TOOLS};
	rm -f ${LIBRARY};
	rm -f test-naaaim.so test-naaaim.signed.so test-Duct.so \
		test-Duct.signed.so test-Possum.so test-Possum.signed.so;


# Source dependencies.
test-naaaim-enclave.o: test-naaaim-interface.h SHA256.h
test-naaaim-interface.o: test-naaaim-interface.h

test-Possum-enclave.o: test-Possum-interface.h
test-Possum-interface.o: test-Possum-interface.h

SHA256.o: SHA256.h
RandomBuffer.o: RandomBuffer.h
