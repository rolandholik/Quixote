# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

#
# Java definitions.
#
JSRC =	naaaim.java idclient.java Duct.java

JAVAC = javac
CLASSES = ${JSRC:java=class}
%.class: %.java
	${JAVAC} $<;

# Variable declarations.
CSRC = id-client-server.c SSLduct.c

BINARIES = id-client-server

CC = musl-gcc

MUSL_INCLUDE = /usr/local/musl/include

#
# Locations of SSL include files and libraries
#
SSL_INCLUDE = /usr/local/musl/ssl/include
SSL_LIBRARY = -L /usr/local/musl/ssl/lib -l ssl


CDEBUG = -O2 -fomit-frame-pointer -march=core2
CDEBUG = -g ${DMALLOC}

CFLAGS = -Wall ${CDEBUG}

# LDFLAGS = -s -L/usr/local/krb5/lib 
LDFLAGS = -g -L ../lib -L ../HurdLib


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

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib -I${SSL_INCLUDE} \
	-I${MUSL_INCLUDE}/tss -I../idgine


#
# Target directives.
#
.PHONY: all binaries classes

# Targets
all: ${COBJS} binaries classes

binaries: ${BINARIES}

classes: ${CLASSES}

jar: classes
	jar cvf idclient.jar *.class;

id-client-server: id-client-server.o SSLduct.o ../idgine/IDengine.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY} -lfl;

clean:
	rm -f *.o *~ *.class TAGS;
	rm -f ${BINARIES} idclient.jar;


# Source dependencies.
