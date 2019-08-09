# **************************************************************************
# * (C)Copyright IDfusion, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/


# Variable declarations.
INSTPATH      = ${DESTDIR}/opt/IDfusion
INSTALLBIN    = sgx-check sgx-gen-token sgx-gen-verifier sgx-load \
	sgx-metadata  sgx-provision
INSTALLSCRIPT = provision-epid provision-tokens provision-verifier
INSTINCLUDE   = PCEenclave.h PVEenclave.h QEenclave.h SGXaesgcm.h SGXcmac.h \
	SGXecdsa.h SGXepid.h SGXloader.h SGXmessage.h SGXmetadata.h	    \
	SGXquote.h SGXrsa.h SGXsigstruct.h SRDE.h SRDEenclave.h

SUBDIRS	    = SGXlibs Attestation ISOidentity Sample
DEV_SUBDIRS = SGXlibs Sample

CSRC = SGXmetadata.c SGXloader.c SRDEenclave.c SGXsigstruct.c PVEenclave.c   \
	SGXmessage.c SGXecdsa.c PCEenclave.c SGXcmac.c SGXaesgcm.c SGXrsa.c  \
	QEenclave.c SGXepid.c SGXquote.c SGXquote_sgxmgr.c sgx_exception.c   \
	sgx-ocall.c

ASRC = boot-sgx.s

LIBRARY = libSRDEruntime.a

TOOLS = sgx-check sgx-metadata sgx-loader sgx-load sgx-sigstruct	     \
	sgx-gen-token test-ecall test-pcr idf-sgx-fandf	idf-sgx-fandf-unibin \
	sgx-provision sdk-compute-size sgx-gen-verifier


LE	     = /opt/intel/sgxpsw/aesm/libsgx_le.signed.so
LE_WHITELIST = /opt/intel/sgxpsw/aesm/sgx_white_list_cert.bin
LE_SIGSTRUCT = /opt/intel/sgxpsw/aesm/le_prod_css.bin

SGXKEY = ${CURDIR}/Signing-key.pem
export SGXKEY


CC = musl-gcc
AS = as

ifeq (${CC}, musl-gcc)
CINCLUDE = -I/usr/local/musl/include
else
CINCLUDE = -I/usr/local/IDfusion/include
endif

CDEBUG = -g -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG} ${CINCLUDE}

LDFLAGS = ${STATIC} -g -L ../lib -L ../HurdLib
ifneq (${CC}, musl-gcc)
LDFLAGS += -Wl,-rpath=/usr/local/IDfusion/lib -L /usr/local/IDfusion/lib
endif

# OpenSSL crypto library
ifeq (${CC}, musl-gcc)
SSL_INCLUDE = /usr/local/musl/include
SSL_CRYPTO = -L /usr/local/musl/lib -lcrypto
else
SSL_INCLUDE = /usr/local/IDfusion/include
SSL_CRYPTO = -L /usr/local/IDfusion/lib -lcrypto -ldl -lpthread
endif

# NAAAIM library definition
NAAAIM_LIB = -L../lib -lNAAAIM

# SGXrdk library definition.
RDKLIB = -L . -lSRDEruntime

# Sources for SGX include files, used by sdk-compute-size utility.
SGXSDK = /u/usr/src/SGX/linux-sgx
SGXSDK_INCLUDES = -I/opt/intel/sgxsdk/include				\
	-I ${SGXSDK}/psw/ae/inc/internal -I ${SGXSDK}/external/epid-sdk \
	-I ${SGXSDK}/common/inc/internal -I ${SGXSDK}/psw/ae/pve


#
# Compilation directives.
#
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@;

%.o: %.s
	${AS} -o $@ $<;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}
AOBJS = ${ASRC:.s=.o}

ELFLIB = -lelf

HURDLIB = -L../lib -lHurdLib
INTEL_CRYPTO = -L/opt/intel/sgxsdk/lib64 -lsgx_tcrypto

LIBS = ${RDKLIB} ${ELFLIB} ${HURDLIB}

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib


#
# Target directives.
#
.PHONY: all tools ${SUBDIRS}

# Targets
all: generate-array ${COBJS} ${AOBJS} ${LIBRARY} tools ${SUBDIRS}

${LIBRARY}: ${COBJS} ${AOBJS}
	ar r ${LIBRARY} $^;
	ranlib ${LIBRARY};

tools: ${TOOLS}

demos: idf-sgx-fandf idf-sgx-fandf-unibin

sgx-check: sgx-check.o
	${CC} ${LDFLAGS} -o $@ $^;

sgx-metadata: sgx-metadata.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${NAAAIM_LIB} ${SSL_CRYPTO};

sgx-metadata.o: sgx-metadata.c
	$(CC) $(CFLAGS) -c $< -o $@;

sgx-loader: sgx-loader.o ${LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

sgx-loader.o: sgx-loader.c
	$(CC) $(CFLAGS) -c $< -o $@;

sgx-load: sgx-load.o ${LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

sgx-load.o: sgx-load.c
	$(CC) $(CFLAGS) -c $< -o $@;

sgx-sigstruct: sgx-sigstruct.o ${LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

sgx-sigstruct.o: sgx-sigstruct.c
	$(CC) $(CFLAGS) -c $< -o $@;

sgx-gen-token: sgx-gen-token.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${NAAAIM_LIB} ${SSL_CRYPTO};

sgx-gen-token.o: sgx-gen-token.c LE_whitelist.h
	$(CC) $(CFLAGS) -c $< -o $@;

sgx-provision: sgx-provision.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${NAAAIM_LIB} ${SSL_CRYPTO} \
		${INTEL_CRYPTO};

sgx-provision.o: sgx-provision.c
	$(CC) $(CFLAGS) -c $< -o $@;

sdk-compute-size: sdk-compute-size.o
	${CC} ${LDFLAGS} -o $@ $<;

sdk-compute-size.o: sdk-compute-size.c
	${CC} ${CFLAGS} ${SGXSDK_INCLUDES} -c $< -o $@;

generate-array: generate-array.o
	${CC} ${LDFLAGS} -o $@ $< ${HURDLIB};

generate-array.o: generate-array.c
	$(CC) $(CFLAGS) -c $< -o $@;

sgx-gen-verifier: sgx-gen-verifier.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${NAAAIM_LIB} ${SSL_CRYPTO};

sgx-gen-verifier.o: sgx-gen-verifier.c
	${CC} ${CFLAGS} -c $< -o $@;

test-ecall: test-ecall.o
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

test-pcr: test-pcr.o
	${CC} ${LDFLAGS} -static -o $@ $^ ${LIBS};

idf-sgx-fandf: idf-sgx-fandf.o
	${CC} -static ${LDFLAGS} -o $@ $^ ${LIBS} ${NAAAIM_LIB} ${SSL_CRYPTO};

idf-sgx-fandf.o: idf-sgx-fandf.c LE_whitelist.h LE.h
	$(CC) $(CFLAGS) -c $< -o $@;

idf-sgx-fandf-unibin: idf-sgx-fandf-unibin.o
	${CC} -static ${LDFLAGS} -o $@ $^ ${LIBS} ${NAAAIM_LIB} ${SSL_CRYPTO};

idf-sgx-fandf-unibin.o: idf-sgx-fandf-unibin.c LE_whitelist.h LE.h TE.h
	$(CC) $(CFLAGS) -c $< -o $@;

SGXecdsa.o: SGXecdsa.c
	$(CC) $(CFLAGS) -I /opt/intel/sgxsdk/include -c $< -o $@;

SGXcmac.o: SGXcmac.c
	$(CC) $(CFLAGS) -I /opt/intel/sgxsdk/include -c $< -o $@;

SGXaesgcm.o: SGXaesgcm.c
	$(CC) $(CFLAGS) -I /opt/intel/sgxsdk/include -c $< -o $@;


sigstruct.h: generate-array
	./generate-array -i ${LE_SIGSTRUCT} -n LE_sigstruct > $@ || rm $@;

LE_whitelist.h: generate-array
	./generate-array -i ${LE_WHITELIST} -n LE_whitelist > $@ || rm $@;

LE.h: generate-array
	./generate-array -i ${LE} -n LE_image > $@ || rm $@;

TE.h: generate-array
	./generate-array -i TE.h -n TE_image > $@ || rm $@;

#
# Subdirectory targets.
#
SGXlibs:
	${MAKE} -C $@;

Attestation:
	${MAKE} -C $@;

ISOidentity:
	${MAKE} -C $@;

Sample:
	${MAKE} -C $@;

install-bin:
	[ -d ${INSTPATH}/etc ] || mkdir -p ${INSTPATH}/etc;
	touch ${INSTPATH}/etc/host.idt ${INSTPATH}/etc/ias-cert.pem \
		${INSTPATH}/etc/ias-key.pem ${INSTPATH}/etc/spid.txt;
	[ -d ${INSTPATH}/etc/verifiers ] || mkdir -p ${INSTPATH}/etc/verifiers;
	[ -d ${INSTPATH}/etc/verifiers/ISOidentity ] || \
		mkdir -p ${INSTPATH}/etc/verifiers/ISOidentity;
	[ -d ${INSTPATH}/etc/verifiers/ISOmanager ] || \
		mkdir ${INSTPATH}/etc/verifiers/ISOmanager;
	[ -e /distrib/SRDE/opt/IDfusion/etc/ca-bundle.pem ] &&		    \
		install -m 644 /distrib/SRDE/opt/IDfusion/etc/ca-bundle.pem \
			${INSTPATH}/etc;
	[ -d ${INSTPATH}/lib ] || mkdir -p ${INSTPATH}/lib;
	[ -d ${INSTPATH}/lib ] || mkdir -p ${INSTPATH}/lib/enclaves;
	[ -d ${INSTPATH}/bin ] || mkdir -p ${INSTPATH}/bin;
	install -s ${INSTALLBIN} ${INSTPATH}/bin;
	install ${INSTALLSCRIPT} ${INSTPATH}/bin;
	${MAKE} -C SGXlibs $@;

install-dev:
	[ -d ${INSTPATH}/include ] || mkdir -p ${INSTPATH}/include;
	[ -d ${INSTPATH}/include/SRDEruntime ] || \
		mkdir -p ${INSTPATH}/include/SRDEruntime;
	install -m 644 ${INSTINCLUDE} ${INSTPATH}/include/SRDEruntime;
	[ -d ${INSTPATH}/lib ] || mkdir -p ${INSTPATH}/lib;
	install -m 644 ${LIBRARY} ${INSTPATH}/lib;
	set -e; for dir in ${DEV_SUBDIRS}; do ${MAKE} -C $$dir $@; done;

tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS sigstruct.h LE_whitelist.h LE.h TE.h;
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clean; done
	rm -f ${LIBRARY};
	rm -f generate-array ${TOOLS};


# Source dependencies.
sgx-metadata.o: SRDE.h SRDEenclave.h SGXsigstruct.h SGXmetadata.h
sgx-load.o: SRDEenclave.h
sgx-provision.o: PVEenclave.h

SGXmetadata.o: SRDE.h SGXmetadata.h
SGXloader.o: SRDE.h SGXloader.h
SRDEenclave.o: SRDE.h SRDEenclave.h SGXmetadata.h SGXloader.h
SGXsigstruct.o: SRDE.h SGXsigstruct.h sigstruct.h
PVEenclave.o: SRDE.h SRDEenclave.h PVEenclave.h
SGXmessage.o: SGXmessage.h
QEenclave.o: SRDE.h SRDEenclave.h QEenclave.h
SGXquote.o: SRDE.h QEenclave.h PCEenclave.h SGXquote.h
