# ***************************************************************************
# (C)Copyright 2017, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC   = test-local-enclave.c
ENCSRC1 = LocalTarget-enclave.c LocalTarget-interface.c
ENCSRC2 = LocalSource-enclave.c LocalSource-interface.c

TOOLS = test-local-target

ENCLAVE_CC = gcc64

SGX_SDK	    = /opt/intel/sgxsdk
SGX_INCLUDE = -I . -I $(SGX_SDK)/include -I $(SGX_SDK)/include/tlibc \
	-I $(SGX_SDK)/include/stlport -I .. -I ../../ISOidentity     \
	-I ../SGXlibs/SGXfusion -I ../SGXlibs/SGXnaaaim -I../../lib

ENCLAVE_CFLAGS = -Wall -nostdinc -fvisibility=hidden -fpie -fstack-protector \
	$(SGX_INCLUDE) -fno-builtin

SGX_LIBRARY_PATH = $(SGX_SDK)/lib64

SGX_TRTS_LIB	    = sgx_trts
SGX_CRYPTO_LIB	    = sgx_tcrypto
SGX_SERVICE_LIBRARY = sgx_tservice

ENCLAVE_LDFLAGS = -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles  \
	-L${SGX_LIBRARY_PATH} -L . -L ../SGXlibs/SGXfusion		     \
	-L ../SGXlibs/SGXnaaaim						     \
	-Wl,--whole-archive						     \
	-l${SGX_TRTS_LIB} -lSGXfusion					     \
	-Wl,--no-whole-archive						     \
	-Wl,--start-group						     \
	-lsgx_tstdc -l${SGX_CRYPTO_LIB} -l${SGX_SERVICE_LIBRARY} -lSGXnaaaim \
	-Wl,--end-group							     \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined			     \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic			     \
	-Wl,--defsym,__ImageBase=0					     \
	-Wl,--version-script=ldscript

SGX_SIGNER = $(SGX_SDK)/bin/sgx_sign


CC = musl-gcc

CFLAGS = -Wall -O2 -fomit-frame-pointer -march=core2 -I .. -I ../.. \
	-I ../../HurdLib -I ../../ISOidentity

LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib -L../../lib

HURDLIB = -L../../HurdLib -lHurdLib
ELFLIB	= -Wl,--rpath /usr/local/musl/lib -lelf


#
# Compilation directives.
#
%.o: %.c
	$(ENCLAVE_CC) $(ENCLAVE_CFLAGS) -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS	= ${CSRC:.c=.o}
ENCOBJS1 = ${ENCSRC1:.c=.o}
ENCOBJS2 = ${ENCSRC2:.c=.o}


#
# Target directives.
#
.PHONY: all tools enclave


# Targets
all: ${LIBRARY} enclave tools

enclave: ldscript LocalTarget.signed.so LocalSource.signed.so

LocalTarget.signed.so: LocalTarget.so
	$(SGX_SIGNER) sign -key Private-key.pem -enclave LocalTarget.so \
		 -out $@ -config LocalTarget-enclave.xml;

LocalTarget.so: ${ENCOBJS1}
	${ENCLAVE_CC} -o $@ $^ ${ENCLAVE_LDFLAGS}

LocalSource.signed.so: LocalSource.so
	$(SGX_SIGNER) sign -key Private-key.pem -enclave $^ -out $@ \
	-config LocalTarget-enclave.xml;

LocalSource.so: ${ENCOBJS2}
	${ENCLAVE_CC} -o $@ $^ ${ENCLAVE_LDFLAGS}

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

test-local-target: test-local-target.o					  \
	../SGXenclave.o ../SGXloader.o ../SGXmetadata.o ../SGXsigstruct.o \
	../sgx-ocall.o ../boot-sgx.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB};

test-local-target.o: test-local-target.c
	${CC} ${CFLAGS} -c $< -o $@;


clean:
	rm -f *.o *~ ldscript;
	rm -f ${TOOLS};
	rm -f LocalTarget.so LocalTarget.signed.so;
	rm -f LocalSource.so LocalSource.signed.so;


# Source dependencies.
LocalTarget-enclave.o: LocalTarget-interface.h
LocalTarget-interface.o: LocalTarget-interface.h
