# ***************************************************************************
# (C)Copyright 2014, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = gen-image.c load-image.c boot.c Netconfig.c IPsec.c PossumPacket.c \
	SoftwareStatus.c SoftwareTPM.c

TOOLS = gen-image load-image boot init possum gen-id-verifier software-status \
	software-tpm

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

LIBS = -lHurdLib -lNAAAIM

CFLAGS := ${CFLAGS} -I.. -I../lib -I../HurdLib -I${SSL_INCLUDE} \
	-I${MUSL_INCLUDE}/tpm_tools -I${MUSL_INCLUDE}/tss


#
# Target directives.
#
.PHONY: all tools

# Targets
all: ${COBJS} tools

tools: ${TOOLS}

gen-image: gen-image.o
	${CC} ${LDFLAGS} -o $@ $^ ../AES256_cbc.o ../SHA256_hmac.o \
		../RandomBuffer.o ${LIBS} ${SSL_LIBRARY};

load-image: load-image.o
	${CC} ${LDFLAGS} -o $@ $^ ../AES256_cbc.o ../SHA256_hmac.o ${LIBS} \
		-ltpm_unseal ${SSL_LIBRARY};

boot: boot.o SoftwareStatus.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

init: init.o Netconfig.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl;

possum: possum.o Netconfig.o IPsec.o PossumPacket.o
	${CC} ${LDFLAGS} -o $@ $^ ../IDtoken.o ../SHA256_hmac.o ../SHA256.o \
		../RandomBuffer.o ../AES256_cbc.o ${SSL_LIBRARY} ${LIBS} -lfl;

gen-id-verifier: gen-id-verifier.o
	${CC} ${LDFLAGS} -o $@ $^ ../IDtoken.o ../SHA256_hmac.o ../SHA256.o \
		${SSL_LIBRARY} ${LIBS}

software-status: software-status.o SoftwareStatus.o
	${CC} ${LDFLAGS} -o $@ $^ ${SSL_LIBRARY} ../SHA256.o ${LIBS};

software-tpm: software-tpm.o SoftwareTPM.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${TOOLS};


# Source dependencies.
Netconfig.o: Netconfig.h
IPsec.o: IPsec.h

possum.o: Netconfig.h IPsec.h PossumPacket.h ../IDtoken.h ../SHA256_hmac.h \
	../RandomBuffer.h ../AES256_cbc.h ../SHA256.h
