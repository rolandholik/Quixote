/**
 * Sample utility to dump sgx metadata from an enclave.
 */


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <libelf.h>

#include "SGX.h"


int main(int argc, char *argv[]) {

	int fd	      = -1,
	    retn      = 1,
	    index;

	size_t shstrndx;

	Elf *elfin = NULL;

	Elf64_Ehdr *ehdr;

	Elf_Scn *section,
		*section_names;

	Elf64_Shdr *shdr;

	Elf_Data *data,
		 *name_data;


	if (argc != 2) {
		fprintf(stderr, "%s: Specify enclave name.\n", argv[0]);
		goto done;
	}


	if ( elf_version(EV_CURRENT) == EV_NONE ) {
		fprintf(stderr, "%s: ELF library initialization failed.\n", \
			argv[0]);
		goto done;
	}

	if ( (fd = open(argv[1], O_RDONLY, 0)) < 0 ) {
		fprintf(stderr, "%s: Enclave file open failed, file=%s.\n", \
			argv[0], argv[1]);
		goto done;
	}

	if ( (elfin = elf_begin(fd, ELF_C_READ, NULL)) == NULL ) {
		fprintf(stderr, "%s: Failed ELF file initialization.\n", \
			argv[0]);
		goto done;
	}

	if ( (ehdr = elf64_getehdr(elfin)) == NULL ) {
		fprintf(stderr, "%s: Failed to get ELF header.\n", argv[0]);
		goto done;
	}


	/* Setup to retrieve section names. */
	if (elf_getshdrstrndx(elfin, &shstrndx) != 0) {
		fputs("Fetch of string index section failed.\n", stderr);
		goto done;
	}
	if ( (section_names = elf_getscn(elfin, shstrndx)) == NULL ) {
		fputs("Error retrieving section names section: %d\n", stderr);
		goto done;
	}
	if ( (name_data = elf_getdata(section_names, NULL)) == NULL ) {
		fputs("\tFailed to section name data.\n", stderr);
		goto done;
	}


	/* Iterate through sections. */
	for (index= 1; index < ehdr->e_shnum; index++) {
		if ( (section = elf_getscn(elfin, index)) == NULL ) {
			fprintf(stderr, "Error retrieving section: %d\n", \
				index);
			goto done;
		}

		if ( (shdr = elf64_getshdr(section)) == NULL ) {
			fprintf(stdout, "\tCannot retrieve section header: "
				"%s\n", elf_errmsg(elf_errno()));
			goto done;
		}

		if ( (data = elf_getdata(section, NULL)) == NULL ) {
			fputs("\tFailed to retrieve section data.\n", stderr);
			goto done;
		}

		if ( strcmp((char *) (name_data->d_buf + shdr->sh_name),
			    ".note.sgxmeta") == 0 ) {
			uint32_t name_size = *((uint32_t *) data->d_buf),
				 desc_size = *((uint32_t *) (data->d_buf + \
					       sizeof(uint32_t)));
			size_t lp,
			       offset = 3 * sizeof(uint32_t) + name_size;
			
			metadata_t md;

#if 1
			fprintf(stdout, "SGX metadata, section=%d:\n", index);

			memcpy(&md, (uint8_t *) (data->d_buf + offset), \
			       desc_size);
			fprintf(stdout, "Magic: 0x%lx\n", md.magic_num);
			fprintf(stdout, "Version: 0x%lx\n", md.version);
			fprintf(stdout, "TCS policy: 0x%x\n", md.tcs_policy);
			fprintf(stdout, "SSA frame size: 0x%x\n", \
				md.ssa_frame_size);
			fprintf(stdout, "Maximum save buffer size: 0x%x\n", \
				md.max_save_buffer_size);
			fprintf(stdout, "Desired misc select: 0x%x\n", \
				md.desired_misc_select);
			fprintf(stdout, "Enclave size: 0x%lx\n", \
				md.enclave_size);

			fputs("Attributes:\n", stdout);
			fprintf(stdout, "\tFlags: 0x%0lx\n", \
				md.attributes.flags);
			fprintf(stdout, "\tXFRM: 0x%0lx\n", \
				md.attributes.xfrm);

			fputs("CSS Header:\n", stdout);
#if 0
			fprintf(stdout, "\tType: 0x%x\n", \
				md.enclave_css.header.type);
			fprintf(stdout, "\tVendor: 0x%x\n", \
				md.vendor);
			fprintf(stdout, "\tDate: 0x%x\n", \
				md.date);
			fprintf(stdout, "\tHW version: 0x%x\n", \
				md.enclave_css.header.hw_version);
#endif


			fputs("CSS key:\n", stdout);
			fprintf(stdout, "\tExponent: 0x%x\n", \
				md.enclave_css.exponent);
			fputs("\tModulus: \t", stdout);
			for (lp= 0; lp < sizeof(md.enclave_css.modulus); \
				     ++lp) {
				fprintf(stdout, "%02x ", \
					md.enclave_css.modulus[lp]);
				if ( (lp+1)%16 == 0 )
					fputs("\n\t\t\t", stdout);
			}
			fputs("\n\tSignature: \t", stdout);
			for (lp= 0; \
			     lp < sizeof(md.enclave_css.signature); ++lp) {
				fprintf(stdout, "%02x ", \
					md.enclave_css.modulus[lp]);
				if ( (lp < sizeof(md.enclave_css.signature))
				     && (lp+1)%16 == 0 )
					fputs("\n\t\t\t", stdout);
			}

			fputs("\nCSS body:\n", stdout);
			fprintf(stdout, "\tMisc select: 0x%x\n", \
				md.enclave_css.miscselect);
			fprintf(stdout, "\tMisc mask: 0x%x\n", \
				md.enclave_css.miscmask);
			fputs("\tAttributes:\n", stdout);
			fprintf(stdout, "\t\tflags: 0x%0lx\n", \
				md.enclave_css.attributes.flags);
			fprintf(stdout, "\t\txfrm: 0x%0lx\n", \
				md.enclave_css.attributes.xfrm);
			fputs("\tAttribute mask:\n", stdout);
			fprintf(stdout, "\t\tflags: 0x%0lx\n", \
				md.enclave_css.attribute_mask.flags);
			fprintf(stdout, "\t\txfrm: 0x%0lx\n", \
				md.enclave_css.attribute_mask.xfrm);

#else
			for (lp= 0; lp < data->d_size; ++lp) {
				fprintf(stdout, "%02x ", \
					*((uint8_t *) (data->d_buf + lp)));
				if ( (lp+1)%16 == 0 )
					fputc('\n', stdout);
			}
			fputc('\n', stdout);
#endif
		}
	}

	retn = 0;

 done:
	elf_end(elfin);
	close(fd);

	return retn;
}
