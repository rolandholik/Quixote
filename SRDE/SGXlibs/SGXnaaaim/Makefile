# **************************************************************************
# * (C)Copyright IDfusion, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/


# Variable declarations.
INSTPATH       = ${DESTDIR}/opt/IDfusion
INSTALLENCLAVE = test-naaaim.signed.so test-Duct.signed.so \
	test-Possum.signed.so
INSTINCLUDE    = IDtoken.h NAAAIM.h PossumPacket.h PossumPipe.h RandomBuffer.h

CSRC   = test-naaaim.c
ENCSRC = test-naaaim-enclave.c test-naaaim-interface.c
LIBSRC = SHA256.c RandomBuffer.c Curve25519.c SHA256_hmac.c AES256_cbc.c  \
	Duct.c SRDEquote.c Base64.c IDtoken.c PossumPacket.c PossumPipe.c \
	SoftwareStatus.c OTEDKS.c IDmgr.c Ivy.c ssl-ocall.c
ASRC   = rdrand.s

DUCTSRC	  = test-Duct-enclave.c test-Duct-interface.c
POSSUMSRC = test-Possum-enclave.c test-Possum-interface.c RandomBuffer.c

LIBNAME	   = SRDEnaaaim
LIBRARY	   = lib${LIBNAME}.a
NAAAIMDIR  = ../../../lib

ENCLAVE_CC = gcc64

SGXDIR = ../..
include ${SGXDIR}/Make.sgx

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

ENCLAVE_LDFLAGS = -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles   \
	-Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive	      \
	-L${SGX_LIBRARY_PATH} -L${SSL_LIBRARY_PATH} -L . -L ../SGXfusion      \
	-Wl,--whole-archive						      \
	-l${SGX_TRTS_LIB} -lSRDEfusion					      \
	-Wl,--no-whole-archive						      \
	-Wl,--start-group						      \
	-lsgx_tstdc -l${SGX_CRYPTO_LIB} -l${SGX_SERVICE_LIBRARY} -lSRDEnaaaim \
	-lsgx_tsgxssl_crypto						      \
	-lsgx_tcxx							      \
	-Wl,--end-group							      \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined			      \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic			      \
	-Wl,--defsym,__ImageBase=0					      \
	-Wl,--version-script=ldscript


CC = musl-gcc

TOOLS = test-naaaim test-Duct test-Possum
INSTALLBIN = ${TOOLS}

C++TOOLS = test-naaaim-c++
ifneq (${CC}, musl-gcc)
TOOLS += ${C++TOOLS}
endif

CFLAGS = -Wall -O2 -fomit-frame-pointer -march=core2 -I ../.. -I ../../.. \
	-I ../../../HurdLib 
ifdef ENCLAVE_DIR
CFLAGS += -DENCLAVE_DIR=\"${ENCLAVE_DIR}\"
endif

LDFLAGS = ${STATIC} -g
ifneq (${CC}, musl-gcc)
LDFLAGS += -Wl,-rpath=/usr/local/IDfusion/lib -L /usr/local/IDfusion/lib
endif

ELFLIB = -lelf

HURD_LIBRARY = ../../../HurdLib/libHurdLib.a
HURDLIB	     = -L ../../../HurdLib -lHurdLib

NAAAIM_LIBRARY = ../../../lib/libNAAAIM.a
NAAAIMLIB      = -L ../../../lib -lNAAAIM

RDK_LIBRARY = ../../libSRDEruntime.a
RDKLIB	    = -L ../../ -lSRDEruntime

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
	${SGX_SIGNER} sign -key ${SGXKEY} -enclave $^ -out $@ \
		-config test-naaaim-enclave.xml;

test-naaaim.so: ${ENCOBJS} ${LIBRARY}
	${ENCLAVE_CC} -o $@ ${ENCOBJS} ${ENCLAVE_LDFLAGS};

test-Duct.signed.so: test-Duct.so
	${SGX_SIGNER} sign -key ${SGXKEY} -enclave $^ -out $@ \
		-config test-Duct-enclave.xml;

test-Duct.so: ${DUCTOBJS} ${LIBRARY}
	${ENCLAVE_CC} -o $@ ${DUCTOBJS} ${ENCLAVE_LDFLAGS};

test-Possum.signed.so: test-Possum.so
	${SGX_SIGNER} sign -key ${SGXKEY} -enclave $^ -out $@ \
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

test-naaaim-c++: test-naaaim-c++.o ${RDK_LIBRARY} ${HURD_LIBRARY}
	${CXX} ${LDFLAGS} -o $@ $< ${RDKLIB} ${ELFLIB} ${HURDLIB};

test-naaaim-c++.o: test-naaaim-c++.cpp
	${CXX} ${CFLAGS} -c $< -o $@;

test-Duct: test-Duct.o ${LIBRARY_DEPDNDS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

test-Duct.o: test-Duct.c
	${CC} ${CFLAGS} -I ../../../lib -c $< -o $@;

test-Possum: test-Possum.o ${LIBRARY_DEPENDS}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS} ${SSL_CRYPTO};

test-Possum.o: test-Possum.c
	${CC} ${CFLAGS} -I ../../../lib -c $< -o $@;

${LIBRARY}: ${LIBOBJS}
	ar r ${LIBRARY} $^;
	ranlib ${LIBRARY};

install-bin:
	[ -d ${INSTPATH}/bin ] || mkdir -p ${INSTPATH}/bin;
	install -s ${INSTALLBIN} ${INSTPATH}/bin;
	[ -d ${INSTPATH}/lib/enclaves ] || mkdir -p ${INSTPATH}/lib/enclaves;
	install ${INSTALLENCLAVE} ${INSTPATH}/lib/enclaves;

install-dev:
	[ -d ${INSTPATH}/include ] || mkdir -p ${INSTPATH}/include;
	[ -d ${INSTPATH}/include/SRDEnaaaim ] || \
		mkdir -p ${INSTPATH}/include/SRDEnaaaim;
	install -m 644 ${INSTINCLUDE} ${INSTPATH}/include/SRDEnaaaim;
	[ -d ${INSTPATH}/lib ] || mkdir -p ${INSTPATH}/lib;
	install -m 644 ${LIBRARY} ${INSTPATH}/lib;

clean:
	rm -f *.o *~ ldscript;
	rm -f ${TOOLS};
	rm -f ${LIBRARY};
	rm -f test-naaaim.so test-naaaim.signed.so test-Duct.so \
		test-Duct.signed.so test-Possum.so test-Possum.signed.so;


# Source dependencies.
test-naaaim-enclave.o: test-naaaim-interface.h RandomBuffer.h	\
	${NAAAIMDIR}/SHA256.h ${NAAAIMDIR}/Curve25519.h		\
	${NAAAIMDIR}/SHA256_hmac.h ${NAAAIMDIR}/AES256_cbc.h	\
	${NAAAIMDIR}/Base64.h
test-naaaim-interface.o: test-naaaim-interface.h

test-Duct-enclave.o: ${NAAAIMDIR}/Duct.h
test-Duct-interface.o: test-Duct-interface.h

test-Possum-enclave.o: test-Possum-interface.h RandomBuffer.h IDtoken.h	   \
	PossumPipe.h ${NAAAIMDIR}/Ivy.h ${NAAAIMDIR}/SHA256.h ../../SRDE.h \
	../SGXfusion/SGXfusion.h

test-Possum-interface.o: test-Possum-interface.h

SHA256.o: ${NAAAIMDIR}/SHA256.h
RandomBuffer.o: RandomBuffer.h
Curve25519.o: ${NAAAIMDIR}/Curve25519.h
SHA256_hmac.o: ${NAAAIMDIR}/SHA256_hmac.h
AES256_cbc.o: ${NAAAIMDIR}/AES256_cbc.h
Duct.o: ${NAAAIMDIR}/Duct.h
SRDEquote.o: ../../SRDEquote.h
Base64.o: ${NAAAIMDIR}/Base64.h
IDtoken.o: IDtoken.h
PossumPacket.o: PossumPacket.h RandomBuffer.h IDtoken.h	 \
	${NAAAIMDIR}/AES256_cbc.h ${NAAAIMDIR}/SHA256.h	 \
	${NAAAIMDIR}/SHA256_hmac.h ${NAAAIMDIR}/OTEDKS.h \
	${NAAAIMDIR}/Curve25519.h
PossumPipe.o: PossumPipe.h IDtoken.h ${NAAAIMDIR}/SHA256.h		    \
	${NAAAIMDIR}/SHA256_hmac.h ${NAAAIMDIR}/AES256_cbc.h RandomBuffer.h \
	${NAAAIMDIR}/Duct.h ${NAAAIMDIR}/SoftwareStatus.h		    \
	${NAAAIMDIR}/Curve25519.h PossumPacket.h ${NAAAIMDIR}/IDmgr.h	    \
	${NAAAIMDIR}/Ivy.h
SoftwareStatus.o: ${NAAAIMDIR}/SoftwareStatus.h ../../SRDE.h	\
	../SGXfusion/SGXfusion.h ${NAAAIMDIR}/SHA256.h
SoftwareStatus.o: ${NAAAIMDIR}/SoftwareStatus.h ../../SRDE.h	\
	../SGXfusion/SGXfusion.h ${NAAAIMDIR}/SHA256.h
OTEDKS.o: ${NAAAIMDIR}/OTEDKS.h ${NAAAIMDIR}/IDmgr.h ${NAAAIMDIR}/Ivy.h
IDmgr.o: IDtoken.h ${NAAAIMDIR}/IDmgr.h
Ivy.o: IDtoken.h ${NAAAIMDIR}/Ivy.h
