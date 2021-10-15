# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************


#
# Include micro-controller build definitions.
#
ifndef MCUCFGDIR
MCUCFGDIR=${shell cd ..; pwd}
endif

include ${MCUCFGDIR}/STmcu.mk


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
CINCLUDE = -I ../../HurdLib

CFLAGS = ${PLATFORM} ${CDEBUG} ${CINCLUDE} -fno-diagnostics-color -Wall


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

clobber: clean
	rm -f ${LIBRARY};


# Source dependencies.
Origin.o: ../../../HurdLib/${LIBNAME}.h ../../../HurdLib/Origin.h
Buffer.o: ../../../HurdLib/${LIBNAME}.h ../../../HurdLib/Origin.h ../../../HurdLib/Fibsequence.h
Gaggle.o: ../../../HurdLib/${LIBNAME}.h ../../../HurdLib/Origin.h ../../../HurdLib/Buffer.h ../../../HurdLib/Gaggle.h
