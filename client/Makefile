# ***************************************************************************
# (C)Copyright 2011, Enjellic Systems Development, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = LCDriver.c SmartCard.c

CLIENTS = query-server

CC = gcc

# Uncomment the following two lines to enable compilation with memory debug
# support
#
# DMALLOC = -DDMALLOC
# DMALLOC_LIBS = -ldmalloc

#
# Locations of SSL include files and libraries
#
SSL_INCLUDE = /usr/local/ssl/include
SSL_LIBRARY = -L /usr/local/ssl/lib -l ssl


CDEBUG = -O2 -fomit-frame-pointer -march=pentium2 ${DMALLOC}
CDEBUG = -g ${DMALLOC}

CFLAGS = -Wall ${CDEBUG} -I./HurdLib # -pedantic-errors -ansi

# LDFLAGS = -s -L/usr/local/krb5/lib 
LDFLAGS = -g ${DMALLOC_LIBS} -L../HurdLib


#
# Compilation directives.
#
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}

LIBS = -lHurdLib -lusb -lhid -lusblcd -lpcsclite -lusb-1.0

CFLAGS := ${CFLAGS} -I.. -I../HurdLib -I${SSL_INCLUDE} \
	-I/usr/local/include/PCSC


# Targets
all: ${COBJS} clients

clients: ${CLIENTS}

query-server: query-server.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl ${SSL_LIBRARY};

tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${CLIENTS};


# Source dependencies.
query-server.o: LCDriver.h SmartCard.h

LCDriver.o: LCDriver.h

SmartCard.o: SmartCard.h
