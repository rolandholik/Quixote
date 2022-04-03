# * the source tree for copyright and licensing information.
# **************************************************************************


#
# Include micro-controller build definitions.
#
ifndef CFGDIR
CFGDIR=${shell cd ..; pwd}
endif

# include ${MCUCFGDIR}/Nordic.mk


#
# Variable declarations.
#
DEFINES = -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"


#
# Object and source file definitions.
#
CSRC = sancho_main.c

COBJS = ${CSRC:.c=.o}

AR     = ar
RANLIB = ranlib

LIBNAME = SanchoXen
LIBRARY = lib${LIBNAME}.a


#
# Build definitions.
#
#CINCLUDE = -I . -I ../.. -I ../../../lib -I ../HurdLib -I ../../../HurdLib

CINCLUDE = -I ../mini-os/include -I ../mini-os/include/x86 \
	-I ../mini-os/include/x86/x86_64/

TARGET_CPPFLAGS = -U __linux__ -U __FreeBSD__ -U __sun__ -nostdinc	\
	-isystem ../mini-os/include				\
	-isystem ../mini-os/include/posix			\
	-isystem ../newlib-root/x86_64-xen-elf/include		\
	-isystem /usr/lib/gcc/x86_64-unknown-linux-gnu/4.9.4/include	\
	-isystem ../mini-os/include/x86					\
	-isystem ../mini-os/include/x86/x86_64

DEFINES = -DHAVE_LIBC -D__MINIOS__ -DCONFIG_PARAVIRT -DCONFIG_SPARSE_BSS -DCONFIG_CONSFRONT -DCONFIG_XENBUS -D__XEN_INTERFACE_VERSION__=0x00030205


CFLAGS = ${DEFINES} ${CDEBUG} ${TARGET_CPPFLAGS} -Wall -mno-red-zone


#
# Compilation directives.
#
%.o: %.c
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

clean:
	rm -f ${COBJS} *~;

clobber: clean
	rm -f ${LIBRARY} sancho.elf;


# Source dependencies.
