# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/


# Variable declarations.
INSTPATH = ${BUILD_INSTPATH}
TESTPATH = ${INSTPATH}/share/unit-tests

FD = ../SRDElibs/SRDEfusion
FUSION_SOURCES = ${FD}/test-fusion.c ${FD}/test-fusion-enclave.c	\
	${FD}/test-fusion-interface.c ${FD}/test-fusion-interface.h	\
	${FD}/test-fusion-enclave.xml

ND = ../SRDElibs/SRDEnaaaim
NAAAIM_SOURCES = ${ND}/test-naaaim.c ${ND}/test-naaaim-enclave.c	\
	${ND}/test-naaaim-interface.c ${ND}/test-naaaim-interface.h	\
	${ND}/test-naaaim-enclave.xml

export INSTALLDIR

#
# Target directives.
#
.PHONY: ${SUBDIRS}

all: fusion-source naaaim-source

fusion-source: ${FUSION_SOURCES}
	cp ${FUSION_SOURCES} .;

naaaim-source: ${NAAAIM_SOURCES}
	cp ${NAAAIM_SOURCES} .;

test:
	make -f Makefile.sample

install-dev:
	[ -d ${TESTPATH} ] || mkdir -p ${TESTPATH} ];
	cp ${FUSION_SOURCES} ${TESTPATH};
	cp ${NAAAIM_SOURCES} ${TESTPATH};
	cp Makefile.sample ${TESTPATH}/Makefile;

clean:
	rm -f test-fusion.c test-fusion-enclave.c test-fusion-interface.{c,h};
	rm -f test-naaaim.c test-naaaim-enclave.c test-naaaim-interface.{c,h};

distclean: clean
	rm -f test-fusion-enclave.xml
	rm -f test-naaaim-enclave.xml
	make -f Makefile.sample clobber;
