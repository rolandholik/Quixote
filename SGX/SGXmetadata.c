/** \file
 * This file contains the implementation of an object which is used to
 * manipulate the Software Guard Extensions (SGX) metadata which is
 * integrated in the form of an ELF section into an SGX enclave shared
 * object file.
 */

/**************************************************************************
 * (C)Copyright 2016, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libelf.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXmetadata.h"


/* Object state extraction macro. */
#define STATE(var) CO(SGXmetadata_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SGXmetadata_OBJID)
#error Object identifier not defined.
#endif


/** SGXmetadata private state information. */
struct NAAAIM_SGXmetadata_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Enclave file descriptor. */
	int fd;

	/* ELF library descriptor. */
	Elf *elf;

	/* SGX metadata structures. */
	metadata_t metadata;

	Buffer patches;
	Buffer layouts;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SGXmetadata_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SGXmetadata_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SGXmetadata_OBJID;

	S->fd  = -1;
	S->elf = NULL;

	memset(&S->metadata, '\0', sizeof(S->metadata));

	S->patches = NULL;
	S->layouts = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements the loading of the SGX metadata from the
 * enclave file.
 *
 * \param this		A pointer to the object which is to hold the
 *			metadata.
 *
 * \param enclave	A pointer to the null-terminated character
 *			buffer which holds the name of the enclave.
 *
 * \return	If an error is encountered while loading the metadata
 *		a false value is returned.  A true value is returned
 *		if the object contains valid metadata.
 */

static _Bool load(CO(SGXmetadata, this), CO(char *, enclave))

{
	STATE(S);

	_Bool retn = false;

	uint8_t *dirp;

	uint32_t cnt;

	int index;

	size_t name_index,
	       offset;

	uint32_t name_size,
		 desc_size;

	Elf64_Ehdr *ehdr;

	Elf_Scn *section,
		*section_names;

	Elf64_Shdr *shdr;

	Elf_Data *data,
		 *name_data;

	struct _patch_entry_t *patch;
	struct _layout_entry_t *layout;


	/* Sanity check the object. */
	if ( S->poisoned )
		goto done;


	/* Setup and initialize ELF access to the enclave. */
	if ( elf_version(EV_CURRENT) == EV_NONE )
		ERR(goto done);
	if ( (S->fd = open(enclave, O_RDONLY, 0)) < 0 )
		ERR(goto done);
	if ( (S->elf = elf_begin(S->fd, ELF_C_READ, NULL)) == NULL )
		ERR(goto done);
	if ( (ehdr = elf64_getehdr(S->elf)) == NULL )
		ERR(goto done);


	/* Setup access to the ELF section names. */
	if (elf_getshdrstrndx(S->elf, &name_index) != 0)
		ERR(goto done);
	if ( (section_names = elf_getscn(S->elf, name_index)) == NULL )
		ERR(goto done);
	if ( (name_data = elf_getdata(section_names, NULL)) == NULL )
		ERR(goto done);


	/* Iterate through the sections looking for the metadata section.. */
	for (index= 1; index < ehdr->e_shnum; index++) {
		if ( (section = elf_getscn(S->elf, index)) == NULL )
			ERR(goto done);
		if ( (shdr = elf64_getshdr(section)) == NULL )
			ERR(goto done);
		if ( (data = elf_getdata(section, NULL)) == NULL )
			ERR(goto done);

		if ( strcmp((char *) (name_data->d_buf + shdr->sh_name),
			    ".note.sgxmeta") == 0 ) {
			name_size = *((uint32_t *) data->d_buf);
			desc_size = *((uint32_t *) (data->d_buf + \
						    sizeof(uint32_t)));
			offset = (3 * sizeof(uint32_t)) + name_size;

			memcpy(&S->metadata, \
			       (uint8_t *) (data->d_buf + offset), desc_size);
			retn = true;
		}
	}


	/* Load the patch data. */
	INIT(HurdLib, Buffer, S->patches, ERR(goto done));

	dirp = (uint8_t *) &S->metadata;
	dirp += S->metadata.dirs[DIR_PATCH].offset;
	patch = (struct _patch_entry_t *) dirp;
	cnt = S->metadata.dirs[DIR_PATCH].size / \
		sizeof(struct _patch_entry_t);

	for (index= 0; index < cnt; ++index) {
		S->patches->add(S->patches, (unsigned char *) patch, \
				sizeof(struct _patch_entry_t));
		++patch;
	}


	/* Load the layout data. */
	INIT(HurdLib, Buffer, S->layouts, ERR(goto done));

	dirp = (uint8_t *) &S->metadata;
	dirp += S->metadata.dirs[DIR_LAYOUT].offset;
	layout = (struct _layout_entry_t *) dirp;
	cnt = S->metadata.dirs[DIR_LAYOUT].size / \
		sizeof(struct _layout_entry_t);

	for (index= 0; index < cnt; ++index) {
		S->layouts->add(S->layouts, (unsigned char *) layout, \
				sizeof(struct _layout_entry_t));
		++layout;
	}


 done:
	if ( !retn ) {
		if ( S->fd != -1 )
			close(S->fd);
		if ( S->elf != NULL )
			elf_end(S->elf);
	}

	return retn;
}


/**
 * External public method.
 *
 * This method implements the patching of an enclave shared object
 * which has been previously memory mapped.  Patching the enclave
 * involves interating through the array of _patch_entry_t structures
 * which was loaded from the SGX encalve.
 *
 * \param this		A pointer to the object which contains the
 *			patch data to be applied.
 *
 * \param enclave	A pointer to the mapped enclave to which the
 *			patches are to be applied.
 *
 * \return	No return value is defined.
 */

static void patch_enclave(CO(SGXmetadata, this), uint8_t *image)

{
	STATE(S);

	uint8_t *src,
		*dst;

	uint32_t lp,
		 cnt = S->patches->size(S->patches) / \
			sizeof(struct _patch_entry_t);

	struct _patch_entry_t *patch = \
		(struct _patch_entry_t *)S->patches->get(S->patches);


	for (lp= 0; lp < cnt; ++lp, ++patch) {
		src  = (uint8_t *) &S->metadata;
		src += patch->src;
		dst  = image;
		dst += patch->dst;
		memcpy(dst, src, patch->size);
	}


	return;
}


/**
 * Internal private function
 *
 * This function implements printing out of a character buffer.  It is
 * a utility function to simplify output for the ->dump method.
 *
 * \param bufr		A pointer to the buffer to be dumped.
 *
 * \param cnt		The length of the buffer in bytes.
 *
 * \return		No return value is defined.
 */

static void _print_buffer(CO(char *, prefix), CO(uint8_t *, bufr), size_t cnt)

{
	size_t lp;


	fputs(prefix, stdout);
	for (lp= 0; lp < cnt; ++lp) {
		fprintf(stdout, "%02x ", bufr[lp]);
		if ( (lp+1 < cnt) && ((lp+1) % 16) == 0 )
			fputs("\n\t", stdout);
	}
	fputc('\n', stdout);

	return;
}


/**
 * External public method.
 *
 * This method implements the loading of the SGX metadata from the
 * enclave file.
 *
 * \param this		A pointer to the object which is to hold the
 *			metadata.
 *
 * \param enclave	A pointer to the null-terminated character
 *			buffer which holds the name of the enclave.
 *
 * \return	If an error is encountered while loading the metadata
 *		a false value is returned.  A true value is returned
 *		if the object contains valid metadata.
 */

static void dump(CO(SGXmetadata, this))

{
	STATE(S);

	uint32_t lp,
		 cnt;

	metadata_t *mp = &S->metadata;

	struct SGX_sigstruct *sp = &mp->enclave_css;

	struct _patch_entry_t *patch;

	struct _layout_entry_t *layout;


	/* Output the enlave header information. */
	fputs("HEADER:\n", stdout);
	fprintf(stdout, "magic: 0x%lx\n", mp->magic_num);
	fprintf(stdout, "version: 0x%lx\n", mp->version);
	fprintf(stdout, "tcs policy: 0x%x\n", mp->tcs_policy);
	fprintf(stdout, "ssa frame size: 0x%x\n", mp->ssa_frame_size);
	fprintf(stdout, "maximum save buffer size: 0x%x\n", \
		mp->max_save_buffer_size);
	fprintf(stdout, "desired misc select: 0x%x\n", \
		mp->desired_misc_select);
	fprintf(stdout, "enclave size: 0x%lx\n", mp->enclave_size);

	fputs("attributes:\n", stdout);
	fprintf(stdout, "\tFlags: 0x%0lx\n", mp->attributes.flags);
	fprintf(stdout, "\tXFRM: 0x%0lx\n", mp->attributes.xfrm);


	/* Output the enclave signature inormation. */
	fputs("\nSIGSTRUCT:\n", stdout);
	fputs("header: ", stdout);
	_print_buffer("", sp->header, sizeof(sp->header));

	fprintf(stdout, "vendor: 0x%x\n", sp->vendor);
	fprintf(stdout, "date: %x\n", sp->date);
	fprintf(stdout, "hw version: 0x%x\n", sp->sw_defined);
	fprintf(stdout, "exponent: 0x%x\n", sp->exponent);

	fputs("modulus:\n", stdout);
	_print_buffer("\t", sp->modulus, sizeof(sp->modulus));

	fputs("signature:\n", stdout);
	_print_buffer("\t", sp->signature, sizeof(sp->signature));

	fprintf(stdout, "misc select: 0x%0x\n", sp->miscselect);
	fprintf(stdout, "misc mask: 0x%0x\n", sp->miscmask);

	fputs("attributes:\n", stdout);
	fprintf(stdout, "\tFlags: 0x%0lx\n", sp->attributes.flags);
	fprintf(stdout, "\tXFRM: 0x%0lx\n", sp->attributes.xfrm);

	fputs("attribute mask:\n", stdout);
	fprintf(stdout, "\tFlags: 0x%0lx\n", sp->attribute_mask.flags);
	fprintf(stdout, "\tXFRM: 0x%0lx\n", sp->attribute_mask.xfrm);

	fputs("enclave measurement:\n", stdout);
	_print_buffer("\t", sp->enclave_hash, sizeof(sp->enclave_hash));

	fprintf(stdout, "isv prodid: 0x%0x\n", sp->isv_prodid);
	fprintf(stdout, "isv svn: 0x%0x\n", sp->isv_svn);

	fputs("key q1:\n", stdout);
	_print_buffer("\t", sp->q1, sizeof(sp->q1));

	fputs("key q2:\n", stdout);
	_print_buffer("\t", sp->q2, sizeof(sp->q2));


	/* Output the enclave layout information. */
	fputs("\nPATCHES:\n", stdout);
	fprintf(stdout, "\tOffset: 0x%0x\n", mp->dirs[DIR_PATCH].offset);
	fprintf(stdout, "\tSize:   0x%0x\n\n", mp->dirs[DIR_PATCH].size);

	patch = (struct _patch_entry_t *) S->patches->get(S->patches);
	cnt   = S->patches->size(S->patches) / sizeof(struct _patch_entry_t);

	for (lp= 0; lp < cnt; ++lp) {
		fprintf(stdout, "\tPatch %u:\n", lp);
		fprintf(stdout, "\t\tdestination: 0x%lx\n", patch->dst);
		fprintf(stdout, "\t\tsource: 0x%x\n", patch->src);
		fprintf(stdout, "\t\tsize: 0x%x\n", patch->size);
		++patch;
	}

	fputs("\nLAYOUT:\n", stdout);
	fprintf(stdout, "\tOffset: 0x%0x\n", mp->dirs[DIR_LAYOUT].offset);
	fprintf(stdout, "\tSize:   0x%0x\n\n", mp->dirs[DIR_LAYOUT].size);

	layout = (struct _layout_entry_t *) S->layouts->get(S->layouts);
	cnt = S->layouts->size(S->layouts) / sizeof(struct _layout_entry_t);

	for (lp= 0; lp < cnt; ++lp) {
		fprintf(stdout, "\tLayout %u:\n", lp);
		fprintf(stdout, "\t\tid: 0x%x\n", layout->id);
		fprintf(stdout, "\t\tattributes: 0x%x\n", layout->attributes);
		fprintf(stdout, "\t\tpage count: 0x%x\n", layout->page_count);
		fprintf(stdout, "\t\toffset: 0x%lx\n", layout->rva);
		fprintf(stdout, "\t\tcontent size: 0x%x\n", \
			layout->content_size);
		fprintf(stdout, "\t\tcontent offset: 0x%x\n", \
			layout->content_offset);
		fprintf(stdout, "\t\tsi flags: 0x%lx\n", layout->si_flags);
		++layout;
	}

	
	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a SGXmetadata object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SGXmetadata, this))

{
	STATE(S);


	if ( S->elf != NULL )
		elf_end(S->elf);
	if ( S->fd != -1 )
		close(S->fd);

	WHACK(S->patches);
	WHACK(S->layouts);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a SGXmetadata object.
 *
 * \return	A pointer to the initialized SGXmetadata.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SGXmetadata NAAAIM_SGXmetadata_Init(void)

{
	auto Origin root;

	auto SGXmetadata this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SGXmetadata);
	retn.state_size   = sizeof(struct NAAAIM_SGXmetadata_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SGXmetadata_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->load	    = load;
	this->patch_enclave = patch_enclave;

	this->dump  = dump;
	this->whack = whack;

	return this;
}
