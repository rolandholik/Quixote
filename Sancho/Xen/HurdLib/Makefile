# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************


#
# Include Xen build definitions.
#
ifndef XENCFGDIR
XENCFGDIR=${shell cd ..; pwd}
endif

include ${XENCFGDIR}/Config.mk

COMPILER_DIRECTORY := ${shell dirname ${shell ${CC} -print-libgcc-file-name}}

TARGET_CPPFLAGS = -U __linux__ -U __FreeBSD__ -U __sun__ -nostdinc	\
	-isystem ../mini-os/include					\
	-isystem ../mini-os/include/posix				\
	-isystem ../newlib-root/x86_64-xen-elf/include			\
	-isystem ${COMPILER_DIRECTORY}/include				\
	-isystem ../mini-os/include/x86					\
	-isystem ../mini-os/include/x86/x86_64

DEFINES = -DHAVE_LIBC -D__MINIOS__


#
# Object and source file definitions.
#
CSRC = Origin.c Fibsequence.c Buffer.c String.c Gaggle.c

COBJS = ${CSRC:.c=.o}

LIBNAME = HurdLib
LIBRARY = lib${LIBNAME}.a


#
# Build definitions.
#
CINCLUDE = -I ../../../HurdLib

CFLAGS = ${PLATFORM} ${DEFINES} ${TARGET_CPPFLAGS} ${CDEBUG} ${CINCLUDE} -Wall


#
# Compilation directives.
#
%.o: ../../../HurdLib/%.c
	${CC} ${CFLAGS} -c $< -o $@;


# Targets
all: ${LIBRARY}

${LIBRARY}: ${COBJS}
	${AR} r ${LIBRARY} $^;
	${RANLIB} ${LIBRARY};

clean:
	rm -f ${COBJS} ${LIBRARY} *~;

distclean: clean
	rm -f ${LIBRARY};


# Source dependencies.
Origin.o: ../../../HurdLib/${LIBNAME}.h ../../../HurdLib/Origin.h
Buffer.o: ../../../HurdLib/${LIBNAME}.h ../../../HurdLib/Origin.h \
	../../../HurdLib/Fibsequence.h
Gaggle.o: ../../../HurdLib/${LIBNAME}.h ../../../HurdLib/Origin.h \
	../../../HurdLib/Buffer.h ../../../HurdLib/Gaggle.h
