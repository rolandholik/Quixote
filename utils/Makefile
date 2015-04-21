# ***************************************************************************
# (C)Copyright 2014, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = gen-image.c load-image.c boot.c Netconfig.c IPsec.c SoftwareTPM.c

TOOLS = gen-image load-image boot sboot init possum gen-id-verifier	\
	software-status software-tpm tpm-cmd id-set idmgr net-config	\
	idtest device-supvr

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

LIBS = -lNAAAIM -lHurdLib 

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

boot: boot.o Netconfig.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

sboot: sboot.o Netconfig.o SoftwareTPM.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

init: init.o Netconfig.o SoftwareTPM.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl -ltspi;

possum: possum.o Netconfig.o IPsec.o
	${CC} ${LDFLAGS} -o $@ $^ ../IDtoken.o ../SHA256_hmac.o ../SHA256.o \
		../RandomBuffer.o ../AES256_cbc.o ${SSL_LIBRARY} ${LIBS}    \
		-ltspi -lfl;

gen-id-verifier: gen-id-verifier.o ../IDtoken.o ../SHA256_hmac.o \
	../SHA256.o ../RandomBuffer.o
	${CC} ${LDFLAGS} -o $@ $^ ${SSL_LIBRARY} ${LIBS} -ltspi;

software-status: software-status.o
	${CC} ${LDFLAGS} -o $@ $^ ${SSL_LIBRARY} ../SHA256.o ${LIBS};

software-tpm: software-tpm.o SoftwareTPM.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

tpm-cmd: tpm-cmd.o ../RandomBuffer.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltspi;

id-set: id-set.o ../IDtoken.o ../SHA256_hmac.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltspi;

idmgr: idmgr.o ../IDtoken.o ../SHA256_hmac.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltspi;

net-config: net-config.o Netconfig.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

idtest: idtest.o ../IDtoken.o ../SHA256_hmac.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltspi;

device-supvr: device-supvr.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${TOOLS};


# Source dependencies.
Netconfig.o: Netconfig.h
IPsec.o: IPsec.h

possum.o: Netconfig.h IPsec.h ../IDtoken.h ../SHA256_hmac.h \
	../RandomBuffer.h ../AES256_cbc.h ../SHA256.h

gen-id-verifier.o:
