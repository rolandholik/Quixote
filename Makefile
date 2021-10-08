# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

# Variable declarations.
INSTPATH = ${DESTDIR}/opt/ESD
HURDINC = HurdLib/Buffer.h HurdLib/Config.h HurdLib/Fibsequence.h \
	HurdLib/File.h HurdLib/HurdLib.h HurdLib/Options.h	  \
	HurdLib/Origin.h HurdLib/String.h
HURDLIB = HurdLib/libHurdLib.a

SUBDIRS	    = utils SRDE Sancho ISOidentity Quixote
DEV_SUBDIRS = lib SRDE

CC = musl-gcc


#
# Target directives.
#
.PHONY: lib ${SUBDIRS}


# Targets
all: HurdLib/libHurdLib.a lib ${SUBDIRS}

HurdLib/libHurdLib.a:
	cd HurdLib && CC=${CC} ./configure;
	make -C HurdLib;

sha256key: sha256key.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS} ${SSL_CRYPTO};


#
# Subdirectory targets.
#
lib:
	${MAKE} -C $@;

utils:
	${MAKE} -C $@;

SRDE:
	${MAKE} -C $@;

ISOidentity:
	${MAKE} -C $@;

Quixote:
	${MAKE} -C $@;

Sancho:
	${MAKE} -C $@;

install-bin:
	set -e; for dir in ${SUBDIRS}; do ${MAKE} -C $$dir $@; done;

install-dev:
	[ -d ${INSTPATH}/share ] || mkdir -p ${INSTPATH}/share;
	install -m 644 Documentation/COPYRIGHT ${INSTPATH}/share;
	[ -d ${INSTPATH}/include ] || mkdir -p ${INSTPATH}/include;
	[ -d ${INSTPATH}/include/HurdLib ] || \
		mkdir -p ${INSTPATH}/include/HurdLib;
	install -m 644 ${HURDINC} ${INSTPATH}/include/HurdLib;
	[ -d ${INSTPATH}/lib ] || mkdir -p ${INSTPATH}/lib;
	install -m 644 ${HURDLIB} ${INSTPATH}/lib;
	set -e; for dir in ${DEV_SUBDIRS}; do ${MAKE} -C $$dir $@; done;

tags:
	/opt/emacs/bin/etags *.{h,c};

clean:
	${MAKE} -C HurdLib clean;
	${MAKE} -C lib clean;
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clean; done;
