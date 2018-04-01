# ***************************************************************************
# (C)Copyright 2017, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC   = test-ISOidentity-enclave.c ISOenclave.c
ENCSRC = ISOidentity-enclave.c ISOidentity-interface.c			\
	ContourPoint.c Actor.c Subject.c ExchangeEvent.c ISOidentity.c

TOOLS = test-ISOidentity-enclave

ENCLAVE_CC = gcc64

SGX_SDK	    = /opt/intel/sgxsdk
SGX_INCLUDE = -I . -I $(SGX_SDK)/include -I $(SGX_SDK)/include/tlibc \
	-I $(SGX_SDK)/include/stlport -I ../../ISOidentity	     \
	-I ../SGXlibs/SGXfusion -I ../SGXlibs/SGXnaaaim

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

%.o: ../../ISOidentity/%.c
	$(ENCLAVE_CC) $(ENCLAVE_CFLAGS) -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS	= ${CSRC:.c=.o}
ENCOBJS = ${ENCSRC:.c=.o}


#
# Target directives.
#
.PHONY: all tools enclave


# Targets
all: ${LIBRARY} enclave tools

enclave: ldscript ISOidentity.signed.so

ISOidentity.signed.so: ISOidentity.so
	$(SGX_SIGNER) sign -key Private-key.pem -enclave ISOidentity.so \
		 -out $@ -config ISOidentity-enclave.xml;

ISOidentity.so: ${ENCOBJS}
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

test-ISOidentity-enclave: test-ISOidentity-enclave.o ISOenclave.o	  \
	../SGXenclave.o ../SGXloader.o ../SGXmetadata.o ../SGXsigstruct.o \
	../sgx-ocall.o ../boot-sgx.o ISOenclave.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB};

test-ISOidentity-enclave.o: test-ISOidentity-enclave.c
	${CC} ${CFLAGS} -c $< -o $@;

ISOenclave.o: ISOenclave.c
	${CC} ${CFLAGS} -c $< -o $@;


clean:
	rm -f *.o *~ ldscript;
	rm -f ${TOOLS};
	rm -f ISOidentity.so ISOidentity.signed.so;


# Source dependencies.
ISOidentity-enclave.o: ISOidentity-interface.h
ISOidentity-interface.o: ISOidentity-interface.h
