# ***************************************************************************
# (C)Copyright 2014, IDfusion, LLC. All rights reserved.
# ***************************************************************************


# Variable declarations.
CSRC = gen-image.c load-image.c boot.c Netconfig.c IPsec.c PossumPacket.c \
	SoftwareStatus.c SoftwareTPM.c TPMcmd.c IDmgr.c Ivy.c

TOOLS = gen-image load-image boot sboot init possum gen-id-verifier \
	software-status software-tpm tpm-cmd id-set idmgr

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

boot: boot.o SoftwareStatus.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

sboot: sboot.o SoftwareStatus.o Netconfig.o SoftwareTPM.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

init: init.o Netconfig.o SoftwareTPM.o SoftwareStatus.o TPMcmd.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl -ltspi;

possum: possum.o Netconfig.o IPsec.o PossumPacket.o SoftwareStatus.o IDmgr.o \
	Ivy.o TPMcmd.o
	${CC} ${LDFLAGS} -o $@ $^ ../IDtoken.o ../SHA256_hmac.o ../SHA256.o \
		../RandomBuffer.o ../AES256_cbc.o ${SSL_LIBRARY} ${LIBS}    \
		-ltspi -lfl;

gen-id-verifier: gen-id-verifier.o ../IDtoken.o ../SHA256_hmac.o ../SHA256.o \
	../RandomBuffer.o Ivy.o SoftwareStatus.o TPMcmd.o
	${CC} ${LDFLAGS} -o $@ $^ ${SSL_LIBRARY} ${LIBS} -ltspi;

software-status: software-status.o SoftwareStatus.o
	${CC} ${LDFLAGS} -o $@ $^ ${SSL_LIBRARY} ../SHA256.o ${LIBS};

software-tpm: software-tpm.o SoftwareTPM.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

tpm-cmd: tpm-cmd.o TPMcmd.o ../RandomBuffer.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltspi;

id-set: id-set.o TPMcmd.o ../IDtoken.o ../SHA256_hmac.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltspi;

idmgr: idmgr.o TPMcmd.o IDmgr.o ../IDtoken.o ../SHA256_hmac.o ../SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltspi;

idtest: idtest.o IDmgr.o ../IDtoken.o ../SHA256_hmac.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltspi;

tags:
	/opt/emacs/bin/etags *.{h,c};
clean:
	rm -f *.o *~ TAGS;
	rm -f ${TOOLS};


# Source dependencies.
Netconfig.o: Netconfig.h
IPsec.o: IPsec.h
IDmgr.o: IDmgr.h TPMcmd.h ../IDtoken.h ../SHA256.h

possum.o: Netconfig.h IPsec.h PossumPacket.h Ivy.h ../IDtoken.h \
	../SHA256_hmac.h ../RandomBuffer.h ../AES256_cbc.h ../SHA256.h

Ivy.o: Ivy.h ../NAAAIM.h ../IDtoken.h
