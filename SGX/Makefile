# ***************************************************************************
# (C)Copyright 2016, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = sgx-check.c sgx-test.c sgx-metadata.c SGXmetadata.c SGXloader.c \
	SGXenclave.c SGXsigstruct.c

ASRC = boot-sgx.s

TOOLS = sgx-check sgx-test sgx-metadata sgx-loader sgx-load sgx-sigstruct \
	sgx-gen-token gen-white-list

CC = musl-gcc
AS = as

MUSL_INCLUDE = /usr/local/musl/include

CDEBUG = -g -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG}

LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib -L../lib -L../HurdLib

# OpenSSL crypto library
SSL_CRYPTO  = -L /usr/local/musl/lib -lcrypto


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


CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib -I/usr/local/musl/include


#
# Target directives.
#
.PHONY: all tools

# Targets
all: ${COBJS} ${AOBJS} tools

tools: ${TOOLS}

sgx-check: sgx-check.o
	${CC} ${LDFLAGS} -o $@ $^;

sgx-test: sgx-test.o
	${CC} ${LDFLAGS} -o $@ $^;

sgx-metadata: sgx-metadata.o SGXmetadata.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB};

sgx-metadata.o: sgx-metadata.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-loader: sgx-loader.o SGXloader.o SGXmetadata.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB};

sgx-loader.o: sgx-loader.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-load: sgx-load.o SGXenclave.o SGXloader.o SGXmetadata.o SGXsigstruct.o \
	boot-sgx.o	#enter_enclave.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB};

sgx-load.o: sgx-load.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-sigstruct: sgx-sigstruct.o SGXsigstruct.o
	${CC} ${LDFLAGS} -o $@ $^ ${HURDLIB};

sgx-sigstruct.o: sgx-sigstruct.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

sgx-gen-token: sgx-gen-token.o SGXenclave.o SGXloader.o SGXmetadata.o \
	SGXsigstruct.o ../SHA256.o boot-sgx.o	# enter_enclave.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB} ${SSL_CRYPTO};

sgx-gen-token.o: sgx-gen-token.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

gen-white-list: gen-white-list.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB} ${HURDLIB} ${SSL_CRYPTO};

gen-white-list.o: gen-white-list.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

dotest: dotest.o boot-sgx.o
	${CC} ${CFLAGS} -static -o $@ $^;


tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${TOOLS};


# Source dependencies.
sgx-metadata.o: SGX.h
sgx-load.o: SGXenclave.h

SGXmetadata.o: SGX.h SGXmetadata.h
SGXloader.o: SGX.h SGXloader.h
SGXenclave.o: SGX.h SGXenclave.h SGXmetadata.h SGXloader.h
SGXsigstruct.o: SGX.h SGXsigstruct.h
