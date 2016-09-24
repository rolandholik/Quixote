# ***************************************************************************
# (C)Copyright 2016, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = sgx-check.c

TOOLS = sgx-check

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

tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${TOOLS};


# Source dependencies.
