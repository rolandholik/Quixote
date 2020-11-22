# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/


# Variable declarations.
CSRC = gen-image.c load-image.c boot.c Netconfig.c IPsec.c SoftwareTPM.c \
	device-supvr.c mgmt-supvr.c MGMTsupvr.c vm-supvr.c copy-edid.c


TOOLS = gen-image load-image boot sboot init possum gen-id-verifier	\
	software-status software-tpm tpm-cmd id-set idmgr net-config	\
	idtest device-supvr mgmt-supvr mgmt-set-key vm-supvr copy-edid	\
	tpm2-cmd

CC = musl-gcc

ifeq (${CC}, musl-gcc)
MUSL_INCLUDE = /usr/local/musl/include
else
MUSL_INCLUDE = /usr/local/IDfusion/include
endif

#
# Locations of SSL include files and libraries
#
ifeq (${CC}, musl-gcc)
SSL_INCLUDE = /usr/local/musl/include
SSL_CRYPTO = -L /usr/local/musl/lib -lcrypto
SSL_LIBRARY = -L /usr/local/musl/lib -lssl -lcrypto
else
SSL_INCLUDE = /usr/local/IDfusion/include
SSL_CRYPTO = -L /usr/local/IDfusion/lib -lcrypto -ldl -lpthread
SSL_LIBRARY = -L /usr/local/IDfusion/lib -lssl ${SSL_CRYPTO}
endif

# Location of smartcard library.
PCSC_LIBRARY = -L/usr/local/lib -lpcsclite


CDEBUG = -O2 -fomit-frame-pointer -march=core2
CDEBUG = -g ${DMALLOC}

CFLAGS = -Wall ${CDEBUG}

# LDFLAGS = -s -L/usr/local/krb5/lib 
LDFLAGS = -g -L ../lib -L ../HurdLib
ifneq (${CC}, musl-gcc)
LDFLAGS += -lpthread -lrt -Wl,-rpath=/usr/local/IDfusion/lib
endif


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
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

load-image: load-image.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltpm_unseal -ltspi ${SSL_CRYPTO};

boot: boot.o Netconfig.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

sboot: sboot.o Netconfig.o SoftwareTPM.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

init: init.o Netconfig.o SoftwareTPM.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl -ltspi ${SSL_CRYPTO} -lssl;

possum: possum.o Netconfig.o IPsec.o
	${CC} ${LDFLAGS} -o $@ $^ ${SSL_CRYPTO} ${LIBS} -ltspi -lfl;

gen-id-verifier: gen-id-verifier.o
	${CC} ${LDFLAGS} -o $@ $< ${SSL_CRYPTO} ${LIBS} -ltspi;

software-status: software-status.o
	${CC} ${LDFLAGS} -o $@ $^ ${SSL_CRYPTO} ${LIBS};

software-tpm: software-tpm.o SoftwareTPM.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

tpm-cmd: tpm-cmd.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -ltspi ${SSL_CRYPTO};

id-set: id-set.o
	${CC} ${LDFLAGS} -o $@ $< ${LIBS} -ltspi ${SSL_CRYPTO};

idmgr: idmgr.o
	${CC} ${LDFLAGS} -o $@ $< ${LIBS} -ltspi ${SSL_CRYPTO};

net-config: net-config.o Netconfig.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

idtest: idtest.o
	${CC} ${LDFLAGS} -o $@ $< ${LIBS} -ltspi ${SSL_CRYPTO};

device-supvr: device-supvr.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

mgmt-supvr: mgmt-supvr.o MGMTsupvr.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO} ${PCSC_LIBRARY};

vm-supvr: vm-supvr.o MGMTsupvr.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO} ${PCSC_LIBRARY};

copy-edid: copy-edid.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS};

mgmt-set-key: mgmt-set-key.o MGMTsupvr.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO} ${PCSC_LIBRARY};

tpm2-cmd: tpm2-cmd.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -libmtss_nf ${SSL_CRYPTO};

tags:
	/opt/emacs/bin/etags *.{h,c};

install-bin:
	@echo "Nothing to install.";

clean:
	rm -f *.o *~ TAGS;
	rm -f ${TOOLS};


# Source dependencies.
Netconfig.o: Netconfig.h
IPsec.o: IPsec.h
MGMTsupvr.o: MGMTsupvr.h

possum.o: Netconfig.h IPsec.h
mgmt-supvr.o: MGMTsupvr.h

gen-id-verifier.o:
