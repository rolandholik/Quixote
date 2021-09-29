# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

# Variable declarations.
INSTPATH       = ${DESTDIR}/opt/ESD
INSTALLENCLAVE = SanchoSGX.signed.so ISOmanager.signed.so

ifdef SRDE_PRODUCTION
TYPE = -DSRDE_PRODUCTION
endif

CSRC   = test-ISOidentity-enclave.c SanchoSGX.c ISOmanager.c
ENCSRC = SanchoSGX-enclave.c SanchoSGX-interface.c ISOidentity-manager.c \
	ContourPoint.c Actor.c Subject.c ExchangeEvent.c ISOidentity.c

MGRSRC = ISOmanager-enclave.c ISOmanager-interface.c

TOOLS = test-ISOidentity-enclave


ENCLAVE_CC = gcc

SGXDIR = ../../SRDE
include ${SGXDIR}/Make.enclave

SGX_SSL = /opt/intel/sgxssl

SGX_INCLUDE = -I $(SGX_SDK)/include -I $(SGX_SDK)/include/tlibc		  \
	-I $(SGX_SDK)/include/stlport -I ../../ISOidentity		  \
	-I ${SGXDIR}/SRDElibs/SRDEfusion -I ${SGXDIR}/SRDElibs/SRDEnaaaim \
	-I ../../lib  -I ${SGXDIR}

ENCLAVE_CFLAGS = -Wall -nostdinc -fvisibility=hidden -fpie -fstack-protector \
	$(SGX_INCLUDE) -fno-builtin ${TYPE}

SGX_LIBRARY_PATH = ${SGX_SDK}/lib64
SSL_LIBRARY_PATH = ${SGX_SSL}/lib64

SGX_TRTS_LIB	    = sgx_trts
SGX_CRYPTO_LIB	    = sgx_tcrypto
SGX_SERVICE_LIBRARY = sgx_tservice

ENCLAVE_LDFLAGS = -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles   \
	-Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive	      \
	-L . -L ${SGX_LIBRARY_PATH} -L ${SSL_LIBRARY_PATH}		      \
	-L ${SGXDIR}/SRDElibs/SRDEfusion -L ${SGXDIR}/SRDElibs/SRDEnaaaim     \
	-Wl,--whole-archive						      \
	-l${SGX_TRTS_LIB} -lSRDEfusion					      \
	-Wl,--no-whole-archive						      \
	-Wl,--start-group						      \
	-lsgx_tstdc -l${SGX_CRYPTO_LIB} -l${SGX_SERVICE_LIBRARY} -lSRDEnaaaim \
	-lsgx_tsgxssl_crypto						      \
	-Wl,--end-group							      \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined			      \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic			      \
	-Wl,--defsym,__ImageBase=0					      \
	-Wl,--version-script=ldscript


CC = musl-gcc

CFLAGS = -Wall -O2 -fomit-frame-pointer -march=core2 -I ../.. -I ${SGXDIR} \
	-I ../../HurdLib -I ../../ISOidentity -I ../../lib ${TYPE}

LDFLAGS = -g

ELFLIB = -lelf

HURD_LIBRARY = ../../HurdLib/libHurdLib.a
HURDLIB	     = -L ../../HurdLib -lHurdLib

NAAAIM_LIBRARY = ../../lib/libNAAAIM.a
NAAAIMLIB      = -L ../../lib -lNAAAIM

RDK_LIBRARY = ../libSRDEruntime.a
RDKLIB	    = -L ${SGXDIR} -lSRDEruntime

ifeq (${CC}, musl-gcc)
SSL_INCLUDE = /usr/local/musl/include
SSL_CRYPTO = -L /usr/local/musl/lib -lcrypto
else
SSL_INCLUDE = /usr/local/ESD/include
SSL_CRYPTO = -Wl,-rpath=/usr/local/ESD/lib -L /usr/local/ESD/lib \
	-lcrypto -ldl -lpthread
endif

LIBRARY_DEPENDS = ${HURD_LIBRARY} ${NAAAIM_LIBRARY} ${RDK_LIBRARY}
LIBS		= ${RDKLIB} ${ELFLIB} ${NAAAIMLIB} ${HURDLIB}


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
MGROBJS = ${MGRSRC:.c=.o}


#
# Target directives.
#
.PHONY: all tools enclave


# Targets
all: ${LIBRARY} ${COBJS} enclave tools

enclave: ldscript SanchoSGX.signed.so ISOmanager.signed.so

SanchoSGX.signed.so: SanchoSGX.so SanchoSGX-enclave.meta
	${SRDE_SIGN} -m SanchoSGX-enclave.meta -k ${SGXKEY} -e $< -o $@;

SanchoSGX.so: ${ENCOBJS}
	${ENCLAVE_CC} -o $@ $^ ${ENCLAVE_LDFLAGS};

ISOmanager.signed.so: ISOmanager.so ISOmanager-enclave.meta
	${SRDE_SIGN} -m ISOmanager-enclave.meta -k ${SGXKEY} -e $< -o $@;

ISOmanager.so: ${MGROBJS}
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

test-ISOidentity-enclave: test-ISOidentity-enclave.o SanchoSGX.o
	${CC} ${LDFLAGS} -o $@ $< SanchoSGX.o ${LIBS} ${SSL_CRYPTO};

test-ISOidentity-enclave.o: test-ISOidentity-enclave.c
	${CC} ${CFLAGS} -c $< -o $@;

SanchoSGX.o: SanchoSGX.c
	${CC} ${CFLAGS} -c $< -o $@;

ISOmanager.o: ISOmanager.c
	${CC} ${CFLAGS} -c $< -o $@;

install-bin:
	[ -d ${INSTPATH}/lib/enclaves ] || mkdir -p ${INSTPATH}/lib/enclaves;
	install ${INSTALLENCLAVE} ${INSTPATH}/lib/enclaves;

clean:
	rm -f *.o *~ ldscript;
	rm -f ${TOOLS};
	rm -f SanchoSGX.so SanchoSGX.signed.so ISOmanager.so \
		ISOmanager.signed.so;

clobber:


# Source dependencies.
ISOmanager.o: ISOmanager.h

ISOidentity-enclave.o: ISOidentity-interface.h
ISOidentity-interface.o: ISOidentity-interface.h
