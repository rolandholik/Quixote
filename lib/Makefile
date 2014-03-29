# ***************************************************************************
# (C)Copyright 2014, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = Duct.c

TESTS = Duct_test

CC = musl-gcc

MUSL_INCLUDE = /usr/local/musl/include

LIBNAME = NAAAIM
LIBRARY = lib${LIBNAME}.a

#
# Locations of SSL include files and libraries
#
SSL_INCLUDE = /usr/local/musl/ssl/include
SSL_LIBRARY = -L /usr/local/musl/ssl/lib -l ssl


CDEBUG = -O2 -fomit-frame-pointer -march=core2
CDEBUG = -g ${DMALLOC}

CFLAGS = -Wall ${CDEBUG}

# LDFLAGS = -s -L/usr/local/krb5/lib 
LDFLAGS = -g -Wl,--rpath-link /usr/local/musl/lib -L../HurdLib 


#
# Compilation directives.
#
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}

CFLAGS := ${CFLAGS} -I.. -I../HurdLib -I${SSL_INCLUDE}


#
# Target directives.
#
.PHONY: all tests


# Targets
all: ${LIBRARY}

${LIBRARY}: ${COBJS}
	ar r ${LIBRARY} $^;
	ranlib ${LIBRARY};

tests: ${TESTS} ${COBJS}

Duct_test: Duct_test.o Duct.o
	${CC} ${LDFLAGS} -o $@ $^ -L../HurdLib -lHurdLib

tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${LIBRARY};
	rm -f ${TESTS};


# Source dependencies.
Duct.o: Duct.h ../NAAAIM.h

Duct_test.o: Duct.h ../NAAAIM.h
