# ***************************************************************************
# (C)Copyright 2003, The Open Hurderos Foundation. All rights reserved.
#
# Please see bottom of file for change information.
# ***************************************************************************


# Variable declarations.
CSRC = 	SHA256.c SHA256_hmac.c RSAkey.c OrgID.c PatientID.c RandomBuffer.c \
	IDtoken.c Duct.c

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


LIBS = HurdLib

# LDFLAGS = -s -L/usr/local/krb5/lib 
LDFLAGS = -g ${DMALLOC_LIBS} -L./HurdLib


#
# Compilation directives.
#
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@;


#
# Automatic definition of classes and objects.
#
COBJS = ${CSRC:.c=.o}

LIBS = -l HurdLib

CFLAGS := ${CFLAGS} -I./HurdLib -I${SSL_INCLUDE}


# Targets
all: ${COBJS} genrandom genid

genrandom: genrandom.o RandomBuffer.o SHA256.o
	${CC} ${LDFLAGS} -o ${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

genid: genid.o ${COBJS}
	${CC} ${LDFLAGS} -o ${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl \
		${SSL_LIBRARY};

token: token.o ${COBJS}
	${CC} ${LDFLAGS} -o ${CC} ${LDFLAGS} -o $@ $^ ${LIBS} -lfl \
		${SSL_LIBRARY};

tags:
	/opt/emacs/bin/etags *.{h,c};

clean:
	rm -f *.o *~ TAGS;
	rm -f genrandom genid token RSAkey_test ID_test Duct_test sha256key;

dotest: dotest.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

RSAkey_test: RSAkey_test.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

ID_test: ID_test.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

Duct_test: Duct_test.o ${COBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};

sha256key: sha256key.o SHA256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_LIBRARY};


# Source dependencies.
SHA256.o: ./HurdLib/Origin.h ./HurdLib/Buffer.h SHA256.c SHA256.h
SHA256_hmac.o: ./HurdLib/Origin.h ./HurdLib/Buffer.h SHA256_hmac.h
RSAkey.o: ./HurdLib/Origin.h RSAkey.h
OrgID.o: OrgID.h SHA256.h
PatientID.o: PatientID.h OrgID.h SHA256.h
RandomBuffer.o: RandomBuffer.h
IDtoken.o: IDtoken.h
Duct.o: Duct.h

genid.o: ./HurdLib/Config.h ./HurdLib/Buffer.h SHA256.h
sha256key.o: SHA256.h
