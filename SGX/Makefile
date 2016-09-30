# ***************************************************************************
# (C)Copyright 2016, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = sgx-check.c sgx-test.c sgx-metadata.c

TOOLS = sgx-check sgx-test sgx-metadata

CC = musl-gcc

MUSL_INCLUDE = /usr/local/musl/include

CDEBUG = -O2 -fomit-frame-pointer -march=core2
CFLAGS = -Wall ${CDEBUG}

LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib -L../lib -L../HurdLib


#
# Compilation directives.
#
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}

LIBS = -lNAAAIM -lHurdLib 
ELFLIB = -Wl,--rpath /usr/local/musl/lib -lelf

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib


#
# Target directives.
#
.PHONY: all tools

# Targets
all: ${COBJS} tools

tools: ${TOOLS}

sgx-check: sgx-check.o
	${CC} ${LDFLAGS} -o $@ $^;

sgx-test: sgx-test.o
	${CC} ${LDFLAGS} -o $@ $^;

sgx-metadata: sgx-metadata.o
	${CC} ${LDFLAGS} -o $@ $^ ${ELFLIB};

sgx-metadata.o: sgx-metadata.c
	$(CC) $(CFLAGS) -I/usr/local/musl/include -c $< -o $@;

tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${TOOLS};


# Source dependencies.
sgx-metadata.o: SGX.h
