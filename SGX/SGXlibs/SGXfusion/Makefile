# ***************************************************************************
# (C)Copyright 2017, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC   = test-fusion.c
ENCSRC = test-fusion-enclave.c test-fusion-interface.c
LIBSRC = fusion-shim.c regcomp.c regexec.c regerror.c tre-mem.c reg-support.c \
	inet.c Origin.c Fibsequence.c Buffer.c String.c
ASRC   = enclu_ereport.s enclu_egetkey.s

TOOLS = test-fusion

LIBNAME = SGXfusion
LIBRARY = lib${LIBNAME}.a

ENCLAVE_CC = gcc64

SGX_SDK	    = /opt/intel/sgxsdk
SGX_INCLUDE = -I . -I ${SGX_SDK}/include -I ${SGX_SDK}/include/tlibc \
	-I ${SGX_SDK}/include/stlport

ENCLAVE_CFLAGS = -Wall -nostdinc -fvisibility=hidden -fpie -fstack-protector \
	${SGX_INCLUDE} -fno-builtin

SGX_LIBRARY_PATH = ${SGX_SDK}/lib64

SGX_TRTS_LIB	    = sgx_trts
SGX_CRYPTO_LIB	    = sgx_tcrypto
SGX_SERVICE_LIBRARY = sgx_tservice

ENCLAVE_LDFLAGS = -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles  \
	-L${SGX_LIBRARY_PATH} -L.					     \
	-Wl,--whole-archive						     \
	-l${SGX_TRTS_LIB} -l${LIBNAME}					     \
	-Wl,--no-whole-archive						     \
	-Wl,--start-group						     \
	-lsgx_tstdc -l${SGX_CRYPTO_LIB} -l${SGX_SERVICE_LIBRARY}	     \
	-Wl,--end-group							     \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined			     \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic			     \
	-Wl,--defsym,__ImageBase=0					     \
	-Wl,--version-script=ldscript

SGX_SIGNER = ${SGX_SDK}/bin/sgx_sign


CC = musl-gcc

CFLAGS = -Wall -O2 -fomit-frame-pointer -march=core2 -I ../.. -I ../../.. \
	-I ../../../HurdLib 

LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib -L../../../lib

ELFLIB	= -Wl,--rpath /usr/local/musl/lib -lelf

HURD_LIBRARY = ../../../HurdLib
HURDLIB	     = -L ../../../HurdLib -lHurdLib

RDK_LIBRARY = ../../libSGXrdk.a
RDKLIB	    = -L ../../ -lSGXrdk


#
# Compilation directives.
#
%.o: %.c
	${ENCLAVE_CC} ${ENCLAVE_CFLAGS} -c $< -o $@;

%.o: %.s
	${AS} -o $@ $<;


#
# Automatic definition of classes and objects.
#
COBJS	= ${CSRC:.c=.o}
LIBOBJS = ${LIBSRC:.c=.o} ${ASRC:.s=.o}
ENCOBJS = ${ENCSRC:.c=.o}


#
# Target directives.
#
.PHONY: all tools enclave LDscript


# Targets
all: ${LIBRARY} enclave tools

enclave: ldscript test-fusion.signed.so

test-fusion.signed.so: test-fusion.so
	${SGX_SIGNER} sign -key Private-key.pem -enclave $^ -out $@ \
		-config test-fusion-enclave.xml;

test-fusion.so: ${ENCOBJS}
	${ENCLAVE_CC} -o $@ $^ ${ENCLAVE_LDFLAGS};

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

test-fusion: test-fusion.o ${RDK_LIBRARY} ${HURD_LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ${RDKLIB} ${ELFLIB} ${HURDLIB};

test-fusion.o: test-fusion.c
	${CC} ${CFLAGS} -c $< -o $@;

${LIBRARY}: ${LIBOBJS}
	ar r ${LIBRARY} $^;
	ranlib ${LIBRARY};

clean:
	rm -f *.o *~ ldscript;
	rm -f ${TOOLS};
	rm -f ${LIBRARY};
	rm -f test-fusion.so test-fusion.signed.so;


# Source dependencies.
test-fusion-enclave.o: test-fusion-interface.h HurdLib.h Buffer.h
test-fusion-interface.o: test-fusion-interface.h
fusion-shim.o: fusion-shim.h

Origin.o: HurdLib.h Origin.h
Fibsequence.o: HurdLib.h Origin.h Fibsequence.h
Buffer.o: HurdLib.h Origin.h Fibsequence.h Buffer.h
