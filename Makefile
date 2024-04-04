# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

# Variable declarations.
-include Build.mk

INSTPATH = ${BUILD_INSTPATH}
VARPATH  = ${BUILD_VARPATH}

HURDINC = HurdLib/Buffer.h HurdLib/Config.h HurdLib/Fibsequence.h \
	HurdLib/File.h HurdLib/HurdLib.h HurdLib/Options.h	  \
	HurdLib/Origin.h HurdLib/String.h
HURDLIB = HurdLib/libHurdLib.a

SUBDIRS	    = Support SRDE Sancho SecurityModel Quixote
DEV_SUBDIRS = lib SRDE


#
# Target directives.
#
.PHONY: lib ${SUBDIRS}


# Targets
all: HurdLib/libHurdLib.a lib ${SUBDIRS}

HurdLib/libHurdLib.a:
	cd HurdLib && CC=${CC} CFLAGS="${BUILD_CFLAGS}" ./configure;
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

SecurityModel:
	${MAKE} -C $@;

Quixote:
	${MAKE} -C $@;

Sancho:
	${MAKE} -C $@;

Support:
	${MAKE} -C $@;

Build.mk: .config
	echo "export TOPDIR=`pwd`" > Build.mk;
	echo "export BUILD_CONFIG=true" >> Build.mk;
	echo 'include $${TOPDIR}/Config.mk' >> Build.mk;
	echo >> Build.mk;
	echo "# Local variable modifications here." >> Build.mk;
	[ -e .config ] && cat .config >> Build.mk; echo >> Build.mk \
		|| echo >> Build.mk;
	echo 'include $${TOPDIR}/Setup.mk' >> Build.mk;

.config:
	[ ! -e $@ ] && touch $@ || true;

install: install-bin
	cp README ${INSTPATH}/share/doc;

install-bin: install-path
	set -e; for dir in ${SUBDIRS}; do ${MAKE} -C $$dir $@; done;

install-dev: install-path
	[ -d ${INSTPATH}/share ] || mkdir -p ${INSTPATH}/share;
	install -m 644 Documentation/COPYRIGHT ${INSTPATH}/share;
	[ -d ${INSTPATH}/include ] || mkdir -p ${INSTPATH}/include;
	[ -d ${INSTPATH}/include/HurdLib ] || \
		mkdir -p ${INSTPATH}/include/HurdLib;
	install -m 644 ${HURDINC} ${INSTPATH}/include/HurdLib;
	[ -d ${INSTPATH}/lib ] || mkdir -p ${INSTPATH}/lib;
	install -m 644 ${HURDLIB} ${INSTPATH}/lib;
	set -e; for dir in ${DEV_SUBDIRS}; do ${MAKE} -C $$dir $@; done;

install-path:
	[ -d ${INSTPATH} ]		  || mkdir -p ${INSTPATH};
	[ -d ${INSTPATH}/etc ]		  || mkdir ${INSTPATH}/etc;
	[ -d ${INSTPATH}/bin ]		  || mkdir ${INSTPATH}/bin;
	[ -d ${INSTPATH}/sbin ]		  || mkdir ${INSTPATH}/sbin;
	[ -d ${INSTPATH}/share ]	  || mkdir ${INSTPATH}/share;
	[ -d ${INSTPATH}/share/doc ]	  || mkdir ${INSTPATH}/share/doc;
	[ -d ${VARPATH} ]		  || mkdir -p ${VARPATH};
	[ -d ${VARPATH}/Magazine]	  || mkdir ${VARPATH}/Magazine;
	[ -d ${VARPATH}/mgmt		  || mkdir ${VARPATH}/mgmt;
	[ -d ${VARPATH}/mgmt/cartridges ] || mkdir ${VARPATH}/mgmt/cartridges;
	[ -d ${VARPATH}/mgmt/processes ]  || mkdir ${VARPATH}/mgmt/processes;
	[ -d ${VARPATH}/tokens ]	  || mkdir ${VARPATH}/tokens;

tags:
	/opt/emacs/bin/etags *.{h,c};

tar:
	mkdir distrib;
	(cd HurdLib; git archive --prefix=./${NAME}/HurdLib/ HEAD) | \
		tar -C distrib -x;
	git archive --prefix=./${NAME}/ HEAD | tar -C distrib \
		--exclude ./${NAME}/.gitmodules -x;
	tar -C distrib -czf ${NAME}.tar.gz .;
	rm -rf distrib;

clean:
	${MAKE} -C HurdLib clean;
	${MAKE} -C lib clean;
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i clean; done;

distclean: clean
	${MAKE} -C lib distclean;
	${MAKE} -C HurdLib distclean;
	set -e; for i in ${SUBDIRS}; do ${MAKE} -C $$i distclean; done;
	rm -f Build.mk;

purge: distclean
	${MAKE} -C Support purge;
	${MAKE} -C Sancho purge;
