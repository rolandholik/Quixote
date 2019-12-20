# **************************************************************************
# * (C)Copyright IDfusion, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/


# Variable declarations.
INSTPATH       = ${DESTDIR}/opt/IDfusion
INSTALLENCLAVE = LocalTarget.signed.so Attestation.signed.so \
	Provisioner.signed.so

ifdef SRDE_PRODUCTION
TYPE = -DSRDE_PRODUCTION
endif

CSRC   = test-local-enclave.c test-remote-enclave.c
ENCSRC1 = LocalTarget-enclave.c LocalTarget-interface.c
ENCSRC2 = LocalSource-enclave.c LocalSource-interface.c
ENCSRC3 = Attestation-enclave.c Attestation-interface.c
ENCSRC4 = Provisioner-enclave.c Provisioner-interface.c

TOOLS = test-local-target test-remote-target srde-provisioner \
	srde-attestation
INSTALLBIN  = srde-attestation
INSTALLSBIN = srde-provisioner

ENCLAVE_CC = gcc

SGXDIR = ..
include ${SGXDIR}/Make.enclave

SGX_SSL	= /opt/intel/sgxssl

SGX_INCLUDE = -I . -I $(SGX_SDK)/include -I $(SGX_SDK)/include/tlibc \
	-I $(SGX_SDK)/include/stlport -I .. -I ../../ISOidentity     \
	-I ../SRDElibs/SRDEfusion -I ../SRDElibs/SRDEnaaaim -I../../lib

ENCLAVE_CFLAGS = ${TYPE} -Wall -nostdinc -fvisibility=hidden -fpie \
	-fstack-protector $(SGX_INCLUDE) -fno-builtin ${TYPE}

SGX_LIBRARY_PATH = $(SGX_SDK)/lib64
SSL_LIBRARY_PATH = ${SGX_SSL}/lib64

SGX_TRTS_LIB	    = sgx_trts
SGX_CRYPTO_LIB	    = sgx_tcrypto
SGX_SERVICE_LIBRARY = sgx_tservice

ENCLAVE_LDFLAGS = -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles   \
	-Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive	      \
	-L . -L ${SGX_LIBRARY_PATH} -L ${SSL_LIBRARY_PATH}		      \
	-L ../SRDElibs/SRDEfusion -L ../SRDElibs/SRDEnaaaim		      \
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

CFLAGS = ${TYPE} -Wall -O2 -fomit-frame-pointer -march=core2 -I .. -I ../.. \
	-I ../../HurdLib -I ../../ISOidentity -I ../../lib

LDFLAGS = -g
ifneq (${CC}, musl-gcc)
LDFLAGS += -Wl,-rpath=/usr/local/IDfusion/lib -L /usr/local/IDfusion/lib
endif

ELFLIB = -lelf

HURD_LIBRARY = ../../HurdLib/libHurdLib.a
HURDLIB	     = -L ../../HurdLib -lHurdLib

NAAAIM_LIBRARY = ../../lib/libNAAAIM.a
NAAAIMLIB      = -L ../../lib -lNAAAIM

RDK_LIBRARY = ../libSRDEruntime.a
RDKLIB	    = -L ../ -lSRDEruntime

ifeq (${CC}, musl-gcc)
SSL_INCLUDE = /usr/local/musl/include
SSL_CRYPTO = -L /usr/local/musl/lib -lcrypto
else
SSL_INCLUDE = /usr/local/IDfusion/include
SSL_CRYPTO = -L /usr/local/IDfusion/lib -lcrypto -ldl -lpthread
endif

LIBRARY_DEPENDS = ${HURD_LIBRARY} ${NAAAIM_LIBRARY} ${RDK_LIBRARY}
LIBS		= ${RDKLIB} ${ELFLIB} ${NAAAIMLIB} ${HURDLIB}


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
ENCOBJS3 = ${ENCSRC3:.c=.o}
ENCOBJS4 = ${ENCSRC4:.c=.o}


#
# Target directives.
#
.PHONY: all tools enclave


# Targets
all: ${LIBRARY} enclave tools

enclave: ldscript LocalTarget.signed.so LocalSource.signed.so \
	Attestation.signed.so Provisioner.signed.so

LocalTarget.signed.so: LocalTarget.so
	$(SGX_SIGNER) sign -key ${SGXKEY} -enclave $< -out $@ \
		-config LocalTarget-enclave.xml;

LocalTarget.so: ${ENCOBJS1}
	${ENCLAVE_CC} -o $@ $^ ${ENCLAVE_LDFLAGS}

LocalSource.signed.so: LocalSource.so
	$(SGX_SIGNER) sign -key ${SGXKEY} -enclave $< -out $@ \
	-config LocalTarget-enclave.xml;

LocalSource.so: ${ENCOBJS2}
	${ENCLAVE_CC} -o $@ $^ ${ENCLAVE_LDFLAGS}

Attestation.signed.so: Attestation.so
	$(SGX_SIGNER) sign -key ${SGXKEY} -enclave $< -out $@ \
	-config Attestation-enclave.xml;

Attestation.so: ${ENCOBJS3}
	${ENCLAVE_CC} -o $@ $^ ${ENCLAVE_LDFLAGS}

Provisioner.signed.so: Provisioner.so
	$(SGX_SIGNER) sign -key ${SGXKEY} -enclave $< -out $@ \
	-config Provisioner-enclave.xml;

Provisioner.so: ${ENCOBJS4}
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

test-local-target: test-local-target.o ${LIBRARY_DEPENDS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

test-local-target.o: test-local-target.c
	${CC} ${CFLAGS} -c $< -o $@;

test-remote-target: test-remote-target.o ${LIBRARY_DEPENDS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS} ${SSL_CRYPTO};

test-remote-target.o: test-remote-target.c
	${CC} ${CFLAGS} -c $< -o $@;

srde-provisioner: srde-provisioner.o ${LIBRARY_DEPENDS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS} ${SSL_CRYPTO};

srde-provisioner.o: srde-provisioner.c
	${CC} ${CFLAGS} -c $< -o $@;

srde-attestation: srde-attestation.o ${LIBRARY_DEPENDS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS} ${SSL_CRYPTO};

srde-attestation.o: srde-attestation.c
	${CC} ${CFLAGS} -c $< -o $@;

install-bin:
	[ -d ${INSTPATH}/bin ] || mkdir -p ${INSTPATH}/bin;
	install -s ${INSTALLBIN} ${INSTPATH}/bin;
	[ -d ${INSTPATH}/sbin ] || mkdir -p ${INSTPATH}/sbin;
	install -s ${INSTALLSBIN} ${INSTPATH}/sbin;
	[ -d ${INSTPATH}/lib/enclaves ] || mkdir -p ${INSTPATH}/lib/enclaves;
	install ${INSTALLENCLAVE} ${INSTPATH}/lib/enclaves;

clean:
	rm -f *.o *~ ldscript;
	rm -f ${TOOLS};
	rm -f LocalTarget.so LocalTarget.signed.so;
	rm -f LocalSource.so LocalSource.signed.so;
	rm -f Attestation.so Attestation.signed.so;
	rm -f Provisioner.so Provisioner.signed.so;


# Source dependencies.
LocalTarget-enclave.o: LocalTarget-interface.h
LocalTarget-interface.o: LocalTarget-interface.h
Attestation-enclave.o: Attestation-interface.h
Attestation-interface.o: Attestation-interface.h
