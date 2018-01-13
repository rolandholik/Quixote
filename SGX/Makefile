# ***************************************************************************
# (C)Copyright 2016, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = sgx-check.c sgx-metadata.c SGXmetadata.c SGXloader.c	    \
	SGXenclave.c SGXsigstruct.c test-ecall.c sgx-ocall.c	    \
	PVEenclave.c SGXmessage.c SGXecdsa.c PCEenclave.c SGXcmac.c \
	SGXaesgcm.c SGXrsa.c

ASRC = boot-sgx.s

TOOLS = sgx-check sgx-metadata sgx-loader sgx-load sgx-sigstruct	\
	sgx-gen-token gen-white-list test-ecall test-pcr idf-sgx-fandf	\
	idf-sgx-fandf-unibin sgx-provision sdk-compute-size

CC = musl-gcc
AS = as

MUSL_INCLUDE = /usr/local/musl/include

CDEBUG = -g -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG}

LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib -L../lib -L../HurdLib

# OpenSSL crypto library
SSL_CRYPTO  = -L /usr/local/musl/lib -lcrypto

# Sources for SGX include files, used by sdk-compute-size utility.
SGXSDK = /u/usr/src/SGX/linux-sgx
SGXSDK_INCLUDES = -I/opt/intel/sgxsdk/include			    \
	-I ${SGXSDK}/psw/ae/inc/internal -I ${SGXSDK}/external/epid \
	-I ${SGXSDK}/common/inc/internal


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

LIBS = -lNAAAIM -lHurdLib 
ELFLIB = -Wl,--rpath /usr/local/musl/lib -lelf

HURDLIB = -L../lib -lHurdLib
INTEL_CRYPTO = -L/opt/intel/sgxsdk/lib64 -lsgx_tcrypto


CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib -I/usr/local/musl/include


#
# Target directives.
#
.PHONY: all tools

# Targets
all: ${COBJS} ${AOBJS} tools

tools: ${TOOLS}

demos: idf-sgx-fandf idf-sgx-fandf-unibin

sgx-check: sgx-check.o
	${CC} ${LDFLAGS} -o $@ $^;

sgx-metadata: sgx-metadata.o SGXmetadata.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB} ${SSL_CRYPTO};

sgx-metadata.o: sgx-metadata.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-loader: sgx-loader.o SGXloader.o SGXmetadata.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB};

sgx-loader.o: sgx-loader.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-load: sgx-load.o SGXenclave.o SGXloader.o SGXmetadata.o SGXsigstruct.o \
	boot-sgx.o sgx-ocall.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB};

sgx-load.o: sgx-load.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-sigstruct: sgx-sigstruct.o SGXsigstruct.o
	${CC} ${LDFLAGS} -o $@ $^ ${HURDLIB};

sgx-sigstruct.o: sgx-sigstruct.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-gen-token: sgx-gen-token.o SGXenclave.o SGXloader.o SGXmetadata.o \
	SGXsigstruct.o ../SHA256.o boot-sgx.o sgx-ocall.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB} ${SSL_CRYPTO};

sgx-gen-token.o: sgx-gen-token.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-provision: sgx-provision.o SGXenclave.o SGXloader.o SGXmetadata.o	 \
	SGXsigstruct.o PVEenclave.o PCEenclave.o SGXmessage.o SGXecdsa.o \
	SGXcmac.o SGXaesgcm.o SGXrsa.o ../SHA256.o ../RandomBuffer.o	 \
	 boot-sgx.o sgx-ocall.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB} ${SSL_CRYPTO} \
		${INTEL_CRYPTO};

sgx-provision.o: sgx-provision.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sdk-compute-size: sdk-compute-size.o
	${CC} ${LDFLAGS} -o $@ $^;

sdk-compute-size.o: sdk-compute-size.c
	${CC} ${CFLAGS} ${SGXSDK_INCLUDES} -I/usr/local/musl/include \
		-c $< -o $@;

gen-white-list: gen-white-list.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB} ${SSL_CRYPTO};

gen-white-list.o: gen-white-list.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

test-ecall: test-ecall.o SGXenclave.o SGXloader.o SGXmetadata.o \
	SGXsigstruct.o sgx-ocall.o boot-sgx.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB};

test-pcr: test-pcr.o SGXenclave.o SGXloader.o SGXmetadata.o \
	SGXsigstruct.o sgx-ocall.o boot-sgx.o
	${CC} ${LDFLAGS} -static -o $@ $^ ${ELFLIB} ${HURDLIB};

idf-sgx-fandf: idf-sgx-fandf.o SGXenclave.o SGXloader.o SGXmetadata.o \
	SGXsigstruct.o sgx-ocall.o boot-sgx.o ../SHA256.o
	${CC} -static ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB} ${SSL_CRYPTO};

idf-sgx-fandf-unibin: idf-sgx-fandf-unibin.o SGXenclave.o SGXloader.o \
	SGXmetadata.o SGXsigstruct.o sgx-ocall.o boot-sgx.o ../SHA256.o
	${CC} -static ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB} ${SSL_CRYPTO};

SGXecdsa.o: SGXecdsa.c
	$(CC) $(CFLAGS) -I /opt/intel/sgxsdk/include -c $< -o $@;

SGXcmac.o: SGXcmac.c
	$(CC) $(CFLAGS) -I /opt/intel/sgxsdk/include -c $< -o $@;

SGXaesgcm.o: SGXaesgcm.c
	$(CC) $(CFLAGS) -I /opt/intel/sgxsdk/include -c $< -o $@;

SGXrsa.o: SGXrsa.c
	$(CC) $(CFLAGS) -I /opt/intel/sgxsdk/include -c $< -o $@;


tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${TOOLS};


# Source dependencies.
sgx-metadata.o: SGX.h SGXenclave.h SGXsigstruct.h SGXmetadata.h
sgx-load.o: SGXenclave.h
sgx-provision.o: PVEenclave.h

SGXmetadata.o: SGX.h SGXmetadata.h
SGXloader.o: SGX.h SGXloader.h
SGXenclave.o: SGX.h SGXenclave.h SGXmetadata.h SGXloader.h
SGXsigstruct.o: SGX.h SGXsigstruct.h
PVEenclave.o: SGX.h SGXenclave.h PVEenclave.h
SGXmessage.o: SGXmessage.h
