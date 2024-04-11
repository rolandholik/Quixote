# * the source tree for copyright and licensing information.
# **************************************************************************


#
# Include micro-controller build definitions.
#
ifndef CFGDIR
CFGDIR=${shell cd ..; pwd}
endif

include ${CFGDIR}/Config.mk

COMPILER_DIRECTORY := ${shell dirname ${shell ${CC} -print-libgcc-file-name}}

#
# Variable declarations.
#
DEFINES = -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"


#
# Object and source file definitions.
#
CSRC = sancho_main.c sancho-interpreter.c XENduct.c COE.c Cell.c \
	SecurityEvent.c SecurityPoint.c TSEM.c EventModel.c TSEMparser.c

COBJS = ${CSRC:.c=.o}

AR     = ar
RANLIB = ranlib

LIBNAME = SanchoXen
LIBRARY = lib${LIBNAME}.a


#
# Build definitions.
#
#CINCLUDE = -I . -I ../.. -I ../../../lib -I ../HurdLib -I ../../../HurdLib

CINCLUDE = -I . -I ../../../HurdLib -I ../NAAAIM -I ../../../lib \
	-I ../../../Quixote -I ../../../SecurityModel

TARGET_CPPFLAGS = -U __linux__ -U __FreeBSD__ -U __sun__ -nostdinc	\
	-isystem ../mini-os/include					\
	-isystem ../mini-os/include/posix				\
	-isystem ../newlib-root/x86_64-xen-elf/include			\
	-isystem ${COMPILER_DIRECTORY}/include				\
	-isystem ../mini-os/include/x86					\
	-isystem ../mini-os/include/x86/x86_64

DEFINES = -DHAVE_LIBC -D__MINIOS__ -DCONFIG_PARAVIRT -DCONFIG_SPARSE_BSS -DCONFIG_CONSFRONT -DCONFIG_XENBUS -D__XEN_INTERFACE_VERSION__=0x00030205

CFLAGS = ${CINCLUDE} ${DEFINES} ${CDEBUG} ${TARGET_CPPFLAGS} ${PLATFORM} -Wall


#
# Compilation directives.
#
%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ../../../SecurityModel/%.c
	${CC} ${CFLAGS} -c $< -o $@;

%.o: ../../../lib/%.c
	${CC} ${CFLAGS} -c $< -o $@;


#
# Targets
#
all: sancho.elf

sancho.elf: ${LIBRARY}
	${MAKE} -C .. mini-os-build;

${LIBRARY}: ${COBJS}
	${AR} r ${LIBRARY} $^;
	${RANLIB} ${LIBRARY};


#
# Installation targets.
#
install-bin:
	install sancho.elf ${INSTPATH}/share;

clean:
	rm -f ${COBJS} *~;

distclean: clean
	rm -f ${LIBRARY} sancho.elf;


# Source dependencies.
