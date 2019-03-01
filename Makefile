/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


# Variable declarations.
CSRC = 	OrgID.c PatientID.c Authenticator.c AuthenReply.c IDqueryReply.c \
	ProviderQuery.c SSLDuct.c

# SERVERS = root-referral device-broker user-broker identity-broker \
# 	provider-server
SERVERS = root-referral device-broker user-broker

SUBDIRS = idgine utils edi SGX ISOidentity # client

# CC = gcc
CC = musl-gcc

# Uncomment the following two lines to enable compilation with memory debug
# support
#
# DMALLOC = -DDMALLOC
# DMALLOC_LIBS = -ldmalloc

#
# Locations of SSL include files and libraries
#
SSL_INCLUDE = /usr/local/musl/include
SSL_CRYPTO  = -L /usr/local/musl/lib -lcrypto
SSL_LIBRARY = -L /usr/local/musl/lib -l ssl -l crypto

#
# Locations for the Postgresql files and libraries.
#
POSTGRES_INCLUDE = /usr/local/pgsql/include
POSTGRES_LIBRARY = -L /usr/local/pgsql/lib -lpq

CDEBUG = -O2 -fomit-frame-pointer -march=pentium2 ${DMALLOC}
CDEBUG = -g ${DMALLOC}

CFLAGS = -Wall ${CDEBUG} -I./HurdLib # -pedantic-errors -ansi


# LDFLAGS = -s -L/usr/local/krb5/lib 
LDFLAGS = -g ${DMALLOC_LIBS} -L ./HurdLib  -L ./lib


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

CFLAGS := ${CFLAGS} -I./HurdLib -I${SSL_INCLUDE} -I./lib


#
# Target directives.
#
.PHONY: client lib ${SUBDIRS}


# Targets
# all: ${COBJS} genrandom genid query-client servers ${SUBDIRS}
all: HurdLib/libHurdLib.a lib ${COBJS} genrandom query-client servers \
	${SUBDIRS}

HurdLib/libHurdLib.a:
	cd HurdLib && CC=${CC} ./configure;
	make -C HurdLib;

servers: ${SERVERS} ${TOOLS}

root-referral: root-referral.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl ${SSL_LIBRARY};

device-broker: device-broker.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl ${SSL_LIBRARY};

user-broker: user-broker.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl ${SSL_LIBRARY};

identity-broker: identity-broker.o DBduct.o OrgSearch.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lrt -lfl ${SSL_LIBRARY} \
		${POSTGRES_LIBRARY};

provider-server: provider-server.o DBduct.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl ${SSL_LIBRARY} \
		${POSTGRES_LIBRARY};

query-client: query-client.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl ${SSL_LIBRARY};

genrandom: genrandom.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

genid: genid.o ${COBJS} DBduct.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl ${SSL_CRYPTO} \
		${POSTGRES_LIBRARY};

gen-npi-search: gen-npi-search.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

gen-brokerdb: gen-brokerdb.o ${COBJS} DBduct.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY} ${POSTGRES_LIBRARY};

token: token.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl ${SSL_LIBRARY};

dotest: dotest.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

ID_test: ID_test.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

SSLDuct_test: SSLDuct_test.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY}

DBduct_test: DBduct_test.o DBduct.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${POSTGRES_LIBRARY};

sha256key: sha256key.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};

DBduct.o: DBduct.c
	$(CC) $(CFLAGS) -I${POSTGRES_INCLUDE} -c $< -o $@;


#
# Subdirectory targets.
#
client:
	${MAKE} -C $@;

idgine:
	${MAKE} -C $@;

lib:
	${MAKE} -C $@;

utils:
	${MAKE} -C $@;

SGX:
	${MAKE} -C $@;

ISOidentity:
	${MAKE} -C $@;

tags:
	/opt/emacs/bin/etags *.{h,c};

clean:
	${MAKE} -C HurdLib clean;
	${MAKE} -C lib clean;
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clean; done
	rm -f *.o *~ TAGS;
	rm -f query-client
	rm -f ${SERVERS}
	rm -f genrandom genid token ID_test SSLDuct_test sha256key \
		gen-npi-search DBduct_test gen-brokerdb;


# Source dependencies.
OrgID.o: NAAAIM.h OrgID.h
PatientID.o: NAAAIM.h OrgID.h PatientID.h
SSLDuct.o: NAAAIM.h SSLDuct.h
Authenticator.o: NAAAIM.h Authenticator.h
AuthenReply.o: NAAAIM.h AuthenReply.h
OrgSearch.o: NAAAIM.h OrgSearch.h
IDqueryReply.o: NAAAIM.h IDqueryReply.h
DBDuct.o: NAAAIM.h DBduct.h
ProviderQuery.o: NAAAIM.h ProviderQuery.h

query-client.o: NAAAIM.h SSLDuct.h Authenticator.h IDqueryReply.h \
	ProviderQuery.h

root-referral.o: NAAAIM.h SSLDuct.h Authenticator.h AuthenReply.h \
	IDqueryReply.h
device-broker.o: NAAAIM.h SSLDuct.h Authenticator.h AuthenReply.h
user-broker.o: NAAAIM.h SSLDuct.h Authenticator.h AuthenReply.h
identity-broker.o: NAAAIM.h SSLDuct.h Authenticator.h AuthenReply.h \
	OrgSearch.h IDqueryReply.h DBduct.h
provider-server.o: NAAAIM.h SSLDuct.h DBduct.h ProviderQuery.h

genid.o: NAAAIM.h OrgID.h PatientID.h DBduct.o
sha256key.o: NAAAIM.h

DBduct.o: DBduct.h
