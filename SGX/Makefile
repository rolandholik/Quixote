# ***************************************************************************
# (C)Copyright 2016, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
SUBDIRS = SGXlibs Attestation ISOidentity

CSRC = SGXmetadata.c SGXloader.c SGXenclave.c SGXsigstruct.c PVEenclave.c   \
	SGXmessage.c SGXecdsa.c PCEenclave.c SGXcmac.c SGXaesgcm.c SGXrsa.c \
	QEenclave.c SGXepid.c SGXquote.c SGXquote_sgxmgr.c sgx_exception.c  \
	sgx-ocall.c

ASRC = boot-sgx.s

LIBRARY = libSGXrdk.a

TOOLS = sgx-check sgx-metadata sgx-loader sgx-load sgx-sigstruct	     \
	sgx-gen-token test-ecall test-pcr idf-sgx-fandf	idf-sgx-fandf-unibin \
	sgx-provision sdk-compute-size sgx-gen-verifier

CC = musl-gcc
AS = as

MUSL_INCLUDE = /usr/local/musl/include

CDEBUG = -g -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG}

LDFLAGS = ${STATIC} -g -Wl,--rpath-link /usr/local/musl/lib -L../lib \
	-L../HurdLib

# OpenSSL crypto library
SSL_CRYPTO  = -L /usr/local/musl/lib -lcrypto

# NAAAIM library definition
NAAAIM_LIB = -L../lib -lNAAAIM

# SGXrdk library definition.
RDKLIB = -L . -lSGXrdk

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

ELFLIB = -Wl,--rpath /usr/local/musl/lib -lelf

HURDLIB = -L../lib -lHurdLib
INTEL_CRYPTO = -L/opt/intel/sgxsdk/lib64 -lsgx_tcrypto

LIBS = ${RDKLIB} ${ELFLIB} ${HURDLIB}

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib -I/usr/local/musl/include


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

sgx-metadata: sgx-metadata.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

sgx-metadata.o: sgx-metadata.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-loader: sgx-loader.o ${LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

sgx-loader.o: sgx-loader.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-load: sgx-load.o ${LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

sgx-load.o: sgx-load.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-sigstruct: sgx-sigstruct.o ${LIBRARY}
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

sgx-sigstruct.o: sgx-sigstruct.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-gen-token: sgx-gen-token.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

sgx-gen-token.o: sgx-gen-token.c LE_whitelist.h
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-provision: sgx-provision.o ../SHA256.o ../RandomBuffer.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${NAAAIM_LIB} ${SSL_CRYPTO} \
		${INTEL_CRYPTO};

sgx-provision.o: sgx-provision.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sdk-compute-size: sdk-compute-size.o
	${CC} ${LDFLAGS} -o $@ $<;

sdk-compute-size.o: sdk-compute-size.c
	${CC} ${CFLAGS} ${SGXSDK_INCLUDES} -I/usr/local/musl/include \
		-c $< -o $@;

generate-array: generate-array.o
	${CC} ${LDFLAGS} -o $@ $< ${HURDLIB};

generate-array.o: generate-array.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-gen-verifier: sgx-gen-verifier.o ../IDtoken.o ../SHA256.o ../SHA256_hmac.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${NAAAIM_LIB} ${SSL_CRYPTO};

sgx-gen-verifier.o: sgx-gen-verifier.c
	${CC} ${CFLAGS} -c $< -o $@;

test-ecall: test-ecall.o
	${CC} ${LDFLAGS} -o $@ $< ${LIBS};

test-pcr: test-pcr.o
	${CC} ${LDFLAGS} -static -o $@ $^ ${LIBS};

idf-sgx-fandf: idf-sgx-fandf.o ../SHA256.o
	${CC} -static ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

idf-sgx-fandf-unibin: idf-sgx-fandf-unibin.o ../SHA256.o
	${CC} -static ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

SGXecdsa.o: SGXecdsa.c
	$(CC) $(CFLAGS) -I /opt/intel/sgxsdk/include -c $< -o $@;

SGXcmac.o: SGXcmac.c
	$(CC) $(CFLAGS) -I /opt/intel/sgxsdk/include -c $< -o $@;

SGXaesgcm.o: SGXaesgcm.c
	$(CC) $(CFLAGS) -I /opt/intel/sgxsdk/include -c $< -o $@;


sigstruct.h: generate-array
	./generate-array -i /opt/intel/sgxpsw/aesm/le_prod_css.bin \
		-n LE_sigstruct > $@ || rm $@;

LE_whitelist.h: generate-array
	./generate-array -i sgx_white_list_cert.bin -n LE_whitelist > $@ || \
		rm $@;


#
# Subdirectory targets.
#
SGXlibs:
	${MAKE} -C $@;

Attestation:
	${MAKE} -C $@;

ISOidentity:
	${MAKE} -C $@;


tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS sigstruct.h LE_whitelist.h;
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clean; done
	rm -f ${LIBRARY};
	rm -f generate-array ${TOOLS};


# Source dependencies.
sgx-metadata.o: SGX.h SGXenclave.h SGXsigstruct.h SGXmetadata.h
sgx-load.o: SGXenclave.h
sgx-provision.o: PVEenclave.h

SGXmetadata.o: SGX.h SGXmetadata.h
SGXloader.o: SGX.h SGXloader.h
SGXenclave.o: SGX.h SGXenclave.h SGXmetadata.h SGXloader.h
SGXsigstruct.o: SGX.h SGXsigstruct.h sigstruct.h
PVEenclave.o: SGX.h SGXenclave.h PVEenclave.h
SGXmessage.o: SGXmessage.h
QEenclave.o: SGX.h SGXenclave.h QEenclave.h
SGXquote.o: SGX.h QEenclave.h PCEenclave.h SGXquote.h
