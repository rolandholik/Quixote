# **************************************************************************
# * (C)Copyright IDfusion, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/


# Variable declarations.
INSTPATH       = ${DESTDIR}/opt/IDfusion
INSTALLENCLAVE = test-fusion.signed.so
INSTINCLUDE    = Buffer.h Fibsequence.h HurdLib.h Origin.h SRDEfusion.h	   \
	String.h alltypes.h features.h fusion-shim.h reg-support.h regex.h \

CSRC   = test-fusion.c
ENCSRC = test-fusion-enclave.c test-fusion-interface.c
LIBSRC = fusion-shim.c regcomp.c regexec.c regerror.c tre-mem.c reg-support.c \
	inet.c Origin.c Fibsequence.c Buffer.c String.c
ASRC   = enclu_ereport.s enclu_egetkey.s

LIBNAME = SRDEfusion
LIBRARY = lib${LIBNAME}.a

ENCLAVE_CC = gcc64

SGXDIR = ../..
include ${SGXDIR}/Make.sgx

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


CC = musl-gcc

TOOLS = test-fusion
INSTALLBIN = ${TOOLS}

ifneq (${CC}, musl-gcc)
TOOLS += test-fusion-c++
endif

CFLAGS = -Wall -O2 -fomit-frame-pointer -march=core2 -I ../.. -I ../../.. \
	-I ../../../HurdLib
ifdef ENCLAVE_DIR
CFLAGS += -DENCLAVE_DIR=\"${ENCLAVE_DIR}\"
endif


LDFLAGS = ${STATIC} -g -L ../../../lib
ifneq (${CC}, musl-gcc)
LDFLAGS += -Wl,-rpath=/usr/local/IDfusion/lib -L /usr/local/IDfusion/lib
endif

ELFLIB	= -lelf

HURD_LIBRARY = ../../../HurdLib
HURDLIB	     = -L ../../../HurdLib -lHurdLib

RDK_LIBRARY = ../../libSRDEruntime.a
RDKLIB	    = -L ../../ -lSRDEruntime


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
	${SGX_SIGNER} sign -key ${SGXKEY} -enclave $< -out $@ \
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

test-fusion-c++: test-fusion-c++.o ${RDK_LIBRARY} ${HURD_LIBRARY}
	${CXX} ${LDFLAGS} -o $@ $< ${RDKLIB} ${ELFLIB} ${HURDLIB};

test-fusion-c++.o: test-fusion-c++.cpp
	${CXX} ${CFLAGS} -c $< -o $@;

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
	[ -d ${INSTPATH}/include/SRDEfusion ] || \
		mkdir -p ${INSTPATH}/include/SRDEfusion;
	install -m 644 ${INSTINCLUDE} ${INSTPATH}/include/SRDEfusion;
	[ -d ${INSTPATH}/lib ] || mkdir -p ${INSTPATH}/lib;
	install -m 644 ${LIBRARY} ${INSTPATH}/lib;

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
