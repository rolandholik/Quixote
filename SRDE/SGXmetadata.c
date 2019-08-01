/** \file
 * This file contains the implementation of an object which is used to
 * manipulate the Software Guard Extensions (SGX) metadata which is
 * integrated in the form of an ELF section into an SGX enclave shared
 * object file.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Magic number identifing valid metadata. */
#define METADATA_MAGIC 0x86a80294635d0e4cULL

#define PREFERRED_MAJOR 1
#define PREFERRED_MINOR 4


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
#include "SGXenclave.h"
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


/**
 * Structure used to extract metadata description header.
 */
struct metadata_hdr {
	uint64_t magic_num;
	uint64_t version;
	uint32_t size;
};


/**
 * Enumeration types describing layout types.  These layout types are
 * based on names for version 2 metadata.
 */
enum layout_types {
	layout_heap_min=1,
	layout_heap_init,
	layout_heap_max,
	layout_tcs,
	layout_td,
	layout_ssa,
	layout_stack_max,
	layout_stack_min,
	layout_thread_group,
	layout_guard,
	layout_heap_dyn_min,
	layout_heap_dyn_init,
	layout_heap_dyn_max,
	layout_tcs_dyn,
	layout_td_dyn,
	layout_ssa_dyn,
	layout_stack_dyn_max,
	layout_stack_dyn_min,
	layout_thread_group_dyn
};


/**
 * Structure definition for describing layout types.
 */
struct layout_description {
	unsigned int id;
	unsigned int type;
	char *name;
};


/**
 * Array of structures for version 1 metadata.
 */
struct layout_description v1_layouts[] = {
	{1, layout_heap_min,		"HEAP"},
	{2, layout_tcs,			"TCS"},
	{3, layout_td,			"TD"},
	{4, layout_ssa,			"SSA"},
	{5, layout_stack_min,		"STACK"},
	{6, layout_thread_group,	"THREAD GROUP"},
	{7, layout_guard,		"GUARD"}
};


/**
 * Array of structures for version 2 metadata.
 */
struct layout_description v2_layouts[] = {
	{1, layout_heap_min,		"HEAP MIN"},
	{2, layout_heap_init,		"HEAP INIT"},
	{3, layout_heap_max,		"HEAP MAX"},
	{4, layout_tcs,			"TCS"},
	{5, layout_td,			"TD"},
	{6, layout_ssa,			"SSA"},
	{7, layout_stack_max,		"STACK MAX"},
	{8, layout_stack_min,		"STACK MIN"},
	{9, layout_thread_group,	"THREAD GROUP"},
	{10, layout_guard,		"GUARD"},
	{11, layout_heap_dyn_min,	"HEAP DYN MIN"},
	{12, layout_heap_dyn_init,	"HEAP DYN INIT"},
	{13, layout_heap_dyn_max,	"HEAP DYN MAX"},
	{14, layout_tcs_dyn,		"TCS DYN"},
	{15, layout_td_dyn,		"TD DYN"},
	{16, layout_ssa_dyn,		"SSA DYN"},
	{17, layout_stack_dyn_max,	"STACK DYN MAX"},
	{18, layout_stack_dyn_min,	"STACK DYN MIN"},
	{19, layout_thread_group_dyn,	"THREAD GROUP DYN"}
};


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

	/* Debug status. */
	_Bool debug;

	/* Enclave file descriptor. */
	int fd;

	/* ELF library descriptor. */
	Elf *elf;

	/* SGX metadata structures. */
	uint8_t	version;
	uint32_t section_size;

	uint8_t *metaptrs[3];
	metadata_t metadata;

	Buffer patches;
	Buffer layouts;

	/* SGX attributes and select structure. */
	uint32_t misc_select;
	sgx_attributes_t attributes;
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

	S->poisoned = false;
	S->debug    = false;

	S->fd  = -1;
	S->elf = NULL;

	S->version	= 0;
	S->section_size = 0;
	memset(S->metaptrs, '\0', sizeof(S->metaptrs));
	memset(&S->metadata, '\0', sizeof(S->metadata));

	S->patches = NULL;
	S->layouts = NULL;

	S->misc_select = 0;
	memset(&S->attributes, '\0', sizeof(S->attributes));

	return;
}


/**
 * External private method.
 *
 * This is an internal helper method which iterates through the notes
 * section and selects a suitable or default copy of the metadata.
 *
 * \param this		A pointer to the object for which metadata is
 *			to be loaded.
 *
 * \param metaptr	A pointer to the metadata block in the notes
 *			section of the enclave shared image.
 *
 * \return	A true value is returned if the object has been
 *		populated with a metadata structure.  A false value
 *		indicates that valid metadata was not located.
 */

static _Bool _load_metadata(CO(SGXmetadata, this), CO(uint8_t, *metaptr))

{
	STATE(S);

	uint8_t *mptr	= (uint8_t *) metaptr,
		curptr	= 0,
		maxptrs = sizeof(S->metaptrs)/sizeof(uint8_t *);

	uint32_t minor,
	         major;

	struct metadata_hdr metahdr;


	/* Verify there is at least one valid metadata block. */
	memcpy(&metahdr, mptr, sizeof(metahdr));
	if ( metahdr.magic_num != METADATA_MAGIC )
		return false;


	/* Scan for a preferred metadata type. */
	while ( 1 ) {
		memcpy(&S->metadata, mptr, metahdr.size);
		this->get_version(this, &major, &minor);

		if ( S->version == 0 ) {
			S->version = major;
			if ( (S->version == 1) && (S->section_size > 4096) ) {
				S->version = 2;
				if ( S->debug )
					fputs("Forcing version 2.\n", stdout);
			}
		}

		if ( curptr < maxptrs )
			S->metaptrs[curptr++] = mptr;
		if ( (major == PREFERRED_MAJOR) && (minor == PREFERRED_MINOR) )
			return true;

		mptr += metahdr.size;
		memcpy(&metahdr, mptr, sizeof(metahdr));
		if ( metahdr.magic_num != METADATA_MAGIC )
			return true;
	}

	return false;
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

	uint8_t *dirp,
		*metaptr;

	uint32_t cnt;

	int index;

	size_t name_index;

	uint32_t name_size;

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
			S->section_size = *((uint32_t *) (data->d_buf + \
							  sizeof(uint32_t)));
			metaptr = data->d_buf + (3 * sizeof(uint32_t)) + \
				name_size;

			if ( !_load_metadata(this, metaptr) )
				ERR(goto done);
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

	retn = true;


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
 * This method implements the loading of the SGX metadata from an
 * enclave which has been preloaded into memory.
 *
 * \param this		A pointer to the object which is to hold the
 *			metadata.
 *
 * \param enclave	A pointer to the memory buffer which holds
 *			the enclave image.
 *
 * \param enclave_size	The size of the enclave memory image.
 *
 * \return	If an error is encountered while loading the metadata
 *		a false value is returned.  A true value is returned
 *		if the object contains valid metadata.
 */

static _Bool load_memory(CO(SGXmetadata, this), char * enclave, \
			 const size_t enclave_size)

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
	if ( (S->elf = elf_memory(enclave, enclave_size)) == NULL )
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
 * External public method.
 *
 * This method implements computing the effective attributes which the
 * enclave will be run under.  It also computes the miscellaneous select
 * mask which appears to be clear on current, SGX1, processor families.
 *
 * \param this		A pointer to the object which represents the
 *			enclave whose attributes are to be computed.
 *
 * \param debug		A boolean flag used to indicate whether or not
 *			the debug flag should be set on the functional
 *			enclave attributes.
 *
 * \return		A true value is returned if the computed
 *			attributes are correct and consistent.  A false
 *			value is returned if there is a functional
 *			issue with the attribute set.
 */

static _Bool compute_attributes(CO(SGXmetadata, this), const _Bool debug)

{
	STATE(S);

	_Bool retn = false;

	uint32_t eax,
		 ebx,
		 ecx,
		 edx;

	uint64_t hardware_xfrm;


	/* Status check the object. */
	if ( S->poisoned )
		return false;


	/*
	 * The following is a sanity check which verifies that the
	 * minimum required set of attributes are needed.  The
	 * target XFRM attributes starts with the XFRM attributes
	 * which are required by the enclave metadata.
	 */
	if ( (S->metadata.attributes.xfrm & 0x3ULL) != 0x3ULL )
		goto done;


	/*
	 * The following section of code uses the CPUID instructions
	 * to determine the type of processor support which is
	 * available for the various components of the attributes.
	 *
	 * First obtain the misc select value from the SGX/Leaf 0
	 * CPUID instruction.
	 */
	__asm("movl %4, %%eax\n\t"
	      "movl %5, %%ecx\n\t"
	      "cpuid\n\t"
	      "movl %%eax, %0\n\t"
	      "movl %%ebx, %1\n\t"
	      "movl %%ecx, %2\n\t"
	      "movl %%edx, %3\n\t"
	      /* Output. */
	      : "=r" (eax), "=r" (ebx), "=r" (ecx), "=r" (edx)
	      /* Input. */
	      : "r" (0x12), "r" (0)
	      /* Clobbers. */
	      : "eax", "ebx", "ecx", "edx");

	S->misc_select  = ebx;
	S->misc_select &= S->metadata.enclave_css.miscselect;


	/*
	 * Obtain the attribute flags from the SGX/Leaf1 CPUID instruction
	 * which detail the enclave capabilities.  The attributes are
	 * two 64-bit quantities.  The first 64 bits represents the
	 * flag values which can be set for the enclave with the second
	 * 64-bit value representing the xfrm capabilities.
	 */
	__asm("movl %4, %%eax\n\t"
	      "movl %5, %%ecx\n\t"
	      "cpuid\n\t"
	      "movl %%eax, %0\n\t"
	      "movl %%ebx, %1\n\t"
	      "movl %%ecx, %2\n\t"
	      "movl %%edx, %3\n\t"
	      /* Output. */
	      : "=r" (eax), "=r" (ebx), "=r" (ecx), "=r" (edx)
	      /* Input. */
	      : "r" (0x12), "r" (1)
	      /* Clobbers. */
	      : "eax", "ebx", "ecx", "edx");

	S->attributes.flags = eax | ((uint64_t) ebx << 32ULL);
	hardware_xfrm = ((uint64_t) edx << 32ULL) | ecx;


	/*
	 * Query for the presence of the XSAVE and OSXSAVE instructions.
	 *	Bit 26 ECX => XSAVE
	 *	Bit 27 ECX => OXSAVE
	 */
	__asm("movl %4, %%eax\n\t"
	      "movl %5, %%ecx\n\t"
	      "cpuid\n\t"
	      "movl %%eax, %0\n\t"
	      "movl %%ebx, %1\n\t"
	      "movl %%ecx, %2\n\t"
	      "movl %%edx, %3\n\t"
	      /* Output. */
	      : "=R" (eax), "=r" (ebx), "=r" (ecx), "=r" (edx)
	      /* Input. */
	      : "r" (0x0), "r" (0x1)
	      /* Clobbers. */
	      : "eax", "ebx", "ecx", "edx");

	if ( (ecx & (1UL << 26)) || (ecx & (1U << 27)) ) {
		/* Have XSAVE variant. */
		__asm("movl %2, %%ecx\n\t"
		      "xgetbv\n\t"
		      "movl %%eax, %0\n\t"
		      "movl %%edx, %1\n\t"
		      /* Output. */
		      : "=r" (ecx), "=r" (edx)
		      /* Input. */
		      : "r" (0x0)
		      /* Clobbers. */
		      : "eax", "ecx", "edx");
		hardware_xfrm |= ((uint64_t) edx << 32ULL) | eax;
	}
	else
		hardware_xfrm = 0x3ULL;


	/*
	 * Set the functional attributes which will be used for the enclave.
	 */
	if ( debug )
		S->metadata.attributes.flags |= 0x2ULL;

	S->attributes.flags &= S->metadata.attributes.flags;
	S->attributes.xfrm   = S->metadata.attributes.xfrm & hardware_xfrm;


	/*
	 * Compare the attributes in the signature structure to the
         * current attribute set.
	 */
	if ( (S->metadata.enclave_css.attribute_mask.xfrm & \
	      S->metadata.attributes.xfrm) !=		    \
	     (S->metadata.enclave_css.attribute_mask.xfrm & \
	      S->metadata.enclave_css.attributes.xfrm) )
		ERR(goto done);

	if ( (S->metadata.enclave_css.attribute_mask.flags & \
	      S->metadata.attributes.flags) !=
	     (S->metadata.enclave_css.attribute_mask.flags & \
	      S->metadata.enclave_css.attributes.flags) )
		ERR(goto done);


	/* Need section to evaluate launch token attributes. */

	retn = true;


done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method is responsible for populating a Software guard Extension
 * Control Structure (SECS) with information which is abstracted from
 * the enclave metadata.
 *
 * This function assumes that it is initializing the structure and
 * will clear the structure before populating it.
 *
 * \param this		A pointer to the object from which the SECS
 *			structure information is to be obtained.
 *
 * \param secs		A pointer to the structure which will be
 *			populated.
 *
 * \return		A true value is returned if the object has
 *			been previously poisoned
 *			attributes are correct and consistent.  A false
 *			value is returned if there is a functional
 *			issue with the attribute set.
 */

static _Bool get_secs(CO(SGXmetadata, this), struct SGX_secs *secs)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		return false;


	/* Initialize the SECS structure. */
	memset(secs, '\0', sizeof(struct SGX_secs));

	secs->size	   = S->metadata.enclave_size;
	secs->base	   = 0;
	secs->ssaframesize = S->metadata.ssa_frame_size;
	secs->miscselect   = S->misc_select;
	secs->attributes   = S->attributes.flags;
	secs->xfrm	   = S->attributes.xfrm;
	secs->isvprodid	   = S->metadata.enclave_css.isv_prodid;
	secs->isvsvn	   = S->metadata.enclave_css.isv_svn;

	retn = true;

	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method which is responsible for
 * populating an enclave signature provided by the caller with the
 * contents of the signature which is in the SGX metadata
 * structure.
 *
 * \param this		A pointer to the object which represents the
 *			metadata holding the signature structure to
 *			be returned.
 *
 * \param sigstruct	A pointer to the structure which will be
 *			populated.
 *
 * \return		A true value is returned if a valid signature
 *			structure has been returned.  A false value
 *			is returned if the object is poisoned.
 */

static _Bool get_sigstruct(CO(SGXmetadata, this), \
			   struct SGX_sigstruct *sigstruct)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		return false;


	/* Copy metadata structure to the user supplied structure. */
	*sigstruct = S->metadata.enclave_css;

	retn = true;

	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method which is responsible for
 * populating an enclave attribute structure with the functional security
 * attributes which have been computed for this enclave.
 *
 * \param this		A pointer to the object which represents the
 *			metadata from which the enclave attributes have
 *			been computed.
 *
 * \param attributes	A pointer to the attributes structure which will
 *			be populated.
 *
 * \return		A true value is returned if a valid attributes
 *			structure has been returned.  A false value
 *			is returned if the object is poisoned.
 */

static _Bool get_attributes(CO(SGXmetadata, this), \
			    sgx_attributes_t *attributes)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Copy metadata structure to the user supplied structure. */
	*attributes = S->attributes;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method which returns the major and
 * minor numbers of the metadata version.
 *
 * \param this		A pointer to the metadata object whose version
 *			information is to be returned.
 *
 * \param major		A pointer to the 32-bit variable which will be
 *			loaded with the major number of the metadata
 *			version.
 *
 * \param minor		A pointer to the 32-bit variable which will be
 *			loaded with the minor number of the metadata
 *			version.
 *
 * \return		A true value is returned if the object has
 *			not been poisoned and the supplied variables
 *			will be loaded with the metadata version.
 *			A false value is returned if the object is
 *			poisoned, in this case the variables will
 *			not be guaranteed to have any valid values.
 */

static _Bool get_version(CO(SGXmetadata, this), uint32_t *major, \
			 uint32_t *minor)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/*
	 * Return the major and minor versions via the supplied pointers.
	 */
	*major = S->metadata.version >> 32;
	*minor = S->metadata.version & UINT32_MAX;

	retn = true;


 done:
	return retn;
}


/**
 * Internal private method.
 *
 * This method implements searching the layout description arrays for
 * version 1 and version 1 metadata to locate the structure that defines
 * the type of layout repreented by the layout id number.
 *
 * \param S		The state of the object whose layout type is
 *			being determined.
 *
 * \param id		The identification number of the layout whose
 *			description is to be located.
 *
 * \return		A true value is returned if the layout description
 *			has been located.  A false value is returned if
 *			location of the layout description fails.
 */

static struct layout_description * _find_layout(CO(SGXmetadata_State, S), \
						const uint16_t id)

{
	uint8_t cnt;

	struct layout_description *layouts;


	/* Setup array size and pointers for available layouts. */
	if ( S->version == 1 ) {
		cnt = sizeof(v1_layouts) / sizeof(struct layout_description);
		layouts = v1_layouts;
	}
	if ( S->version == 2 ) {
		cnt = sizeof(v2_layouts) / sizeof(struct layout_description);
		layouts = v2_layouts;
	}


	/* Search for the desired layout type. */
	while ( cnt-- ) {
		if ( layouts->id == id )
			return layouts;
		++layouts;
	}


	return NULL;
}


/**
 * Internal private method.
 *
 * This method implements the loading of an individual layout
 * definition.
 *
 * \param S		The state of the object whose layout is being
 *			generated.

 * \param layout	A pointer the layout definition which is to
 *			be loaded.
 *
 * \param enclave	The object representing the enclave into which
 *			the layout definition will be loaded.
 *
 * \return		A true value is returned if the loading of the
 *			layout succeeds.  A false value is returned if
 *			the loading of the layout fails.
 */

static _Bool _load_layout(CO(SGXmetadata_State, S),		\
			  CO(struct _layout_entry_t *, layout), \
			  CO(SGXenclave, enclave))

{
	_Bool retn = false;

	uint8_t *offset,
		page[4096];

	uint32_t lp,
		 content_count;

	struct layout_description *layout_description;

	struct SGX_tcs *tcs;

	struct SGX_secinfo secinfo;


	/* Verify object state. */
	if ( S->poisoned )
		ERR(goto done);


	/* Locate the structure defining the type of layout. */
	if ( (layout_description = _find_layout(S, layout->id)) == NULL )
		ERR(goto done);

	if ( S->debug ) {
		fprintf(stdout, "\ttype: %d (%s)\n", layout->id, \
			layout_description->name);
		fprintf(stdout, "\tattributes: 0x%x\n", layout->attributes);
		fprintf(stdout, "\tpages: 0x%x\n", layout->page_count);
		fprintf(stdout, "\trva: 0x%lx\n", layout->rva);
		fprintf(stdout, "\tcontent_size: 0x%x\n", \
			layout->content_size);
		fprintf(stdout, "\tcontent_offset: 0x%x\n", \
			layout->content_offset);
		fprintf(stdout, "\tflags: 0x%lx\n", layout->si_flags);
	}


	/*
	 * Address each layout type as a separate build unit.
	 *
	 * Start with the Task Control Structure.
	 */
	if ( layout_description->type == layout_tcs ) {
		if ( layout->content_size > sizeof(page) )
			ERR(goto done);
		memset(page, '\0', sizeof(page));

		offset  = (uint8_t *) &S->metadata;
		offset += layout->content_offset;
		memcpy(page, offset, layout->content_size);

		tcs = (struct SGX_tcs *) page;
		tcs->ossa    += enclave->get_address(enclave);
		tcs->ofsbase += enclave->get_address(enclave);
		tcs->ogsbase += enclave->get_address(enclave);

		if ( !enclave->add_thread(enclave) )
			ERR(goto done);

		memset(&secinfo, '\0', sizeof(struct SGX_secinfo));
		secinfo.flags = layout->si_flags;

		if ( !enclave->add_page(enclave, page, &secinfo, \
					layout->attributes) )
			ERR(goto done);

		retn = true;
		goto done;
	}


	/* If this is a guard page a hole is punched in the enclave. */
	if ( layout_description->type == layout_guard ) {
		for (lp= 0; lp < layout->page_count; ++lp) {
			if ( !enclave->add_hole(enclave) )
				ERR(goto done);
		}

		retn = true;
		goto done;
	}


	/*
	 * For current purposes we will treat any enclaves with permissions
	 * as pages to be loaded.
	 *
	 * Secondly there are no layouts other then the TCS which have
	 * both a non-zero content offset and size.
	 */
	if ( layout->si_flags == 0 ) {
		retn = true;
		goto done;
	}

	if ( (layout->content_size > 0) && (layout->content_offset > 0) )
		ERR(goto done);


	/*
	 * If the content layout size is non-zero the byte contents of
	 * the size are used to fill the page.
	 */
	memset(page, '\0', sizeof(page));

	if ( layout->content_size > 0 ) {
		offset = page;
		content_count = sizeof(page) / sizeof(layout->content_size);

		for (lp= 0; lp < content_count; ++lp) {
			memcpy(offset, &layout->content_size, \
			       sizeof(layout->content_size));
			offset += sizeof(layout->content_size);
		}
	}

	memset(&secinfo, '\0', sizeof(struct SGX_secinfo));
	secinfo.flags = layout->si_flags;

	for (lp= 0; lp < layout->page_count; ++lp) {
		if ( !enclave->add_page(enclave, page, &secinfo, \
					layout->attributes) )
			ERR(goto done);
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Internal private method.
 *
 * This function implements the loading of a layout group definition.  A
 * group is a previously defined range of individual layout sections
 * which is repeated a sepcified number of times.
 *
 * \param S		The state of the object whose group is to be
 *			loaded.
 *
 * \param layout	A pointer to the layout definitions.   This
 *			will be treated as an array which will be
 *			deferenced over the range specified by the
 *			group.
 * *
 * \param group		The offset within the layout entry of the
 *			group entry.
 *
 * \param enclave	The object representing the enclave into which
 *			the group definition will be loaded.
 *
 * \return		A true value is returned if the loading of the
 *			group succeeds.  A false value is returned if
 *			the loading of the group fails.
 */

static _Bool _load_group(CO(SGXmetadata_State, S), CO(layout_t *, layout), \
			 const uint64_t group, CO(SGXenclave, enclave))

{
	_Bool retn = false;

	uint32_t lp,
		 lp1,
		 start = group - layout[group].group.entry_count,
		 replicates = layout[group].group.load_times;


	for (lp= 0; lp < replicates; ++lp) {
		for (lp1= start; lp1 < group; ++lp1) {
			if ( S->debug )
				fprintf(stdout, "\tGroup layout: %d\n", lp);
			_load_layout(S, &layout[lp1].entry, enclave);
			if ( S->debug )
				fputc('\n', stdout);
		}
	}

	retn = true;


	return retn;
}


/**
 * External public method.
 *
 * This method implements loading the page configurations in the
 * enclave which are specified by the layout structures defined in the
 * SGX metadata.
 *
 * \param this		A pointer to the object which contains the SGX
 *			layouts which are to be loaded.
 *
 * \param enclave	A pointer to the enclave object into which the
 *			page definitions are to be loaded into.
 *
 * \return	If an error is encountered while loading the layou
 *		definitions a false value is returned.  A true value
 *		indicates the enclave was successfully loaded.
 */

static _Bool load_layouts(CO(SGXmetadata, this), CO(SGXenclave, enclave))

{
	STATE(S);

	_Bool retn = false;

	uint32_t lp,
		 cnt;

	layout_t *layout;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	layout = (layout_t *) S->layouts->get(S->layouts);
	cnt = S->layouts->size(S->layouts) / sizeof(layout_t);

	for (lp= 0; lp < cnt; ++lp) {
		if ( S->debug )
			fprintf(stdout, "Layout %u:\n", lp);
		if ( (1 << 12) & layout[lp].entry.id ) {
			if ( !_load_group(S, layout, lp, enclave) )
				ERR(goto done);
		}
		else {
			if ( !_load_layout(S, &layout[lp].entry, enclave) )
				ERR(goto done);
		}
	}

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements setting the debug status of the metadata
 * manager.
 *
 * \param this		A pointer to the object whose debug status is
 *			to be modified.
 *
 * \param debug		The debug status to be set for the object.
 *
 * \return	No return value is defined.
 */

static void debug(CO(SGXmetadata, this), const _Bool debug)

{
	STATE(S);


	S->debug = debug;
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

	char *description;

	uint32_t lp,
		 cnt,
		 maxptrs = sizeof(S->metaptrs)/sizeof(uint8_t *);

	struct metadata_hdr metahdr;

	metadata_t *mp = &S->metadata;

	struct SGX_sigstruct *sp = &mp->enclave_css;

	struct _patch_entry_t *patch;

	struct _layout_entry_t *layout;

	struct layout_description *descn;


	/* Output the enlave header information. */
	fputs("METADATA:\n", stdout);
	fprintf(stdout, "notes size: 0x%x\n", S->section_size);

	fputs("versions: ", stdout);
	for (lp= 0; lp < maxptrs; ++lp) {
		if ( S->metaptrs[lp] != NULL ) {
			memcpy(&metahdr, S->metaptrs[lp], sizeof(metahdr));
			fprintf(stdout, "%lu.%lu", metahdr.version >> 32, \
				metahdr.version & UINT32_MAX);
			if ( (lp < maxptrs-1) && (S->metaptrs[lp+1] != NULL) )
				fputs(", ", stdout);
		}
	}

	fputs("\n\nHEADER:\n", stdout);
	fprintf(stdout, "magic: 0x%lx\n", mp->magic_num);
	fprintf(stdout, "version: 0x%lx (%lu.%lu)\n", mp->version, \
		mp->version >> 32, mp->version & 0xffffffff);
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
		if ( (descn = _find_layout(S, layout->id)) == NULL )
			description = "UNKNOWN";
		else
			description = descn->name;

		fprintf(stdout, "\tLayout %u:\n", lp);
		fprintf(stdout, "\t\tid: 0x%x (%s)\n", layout->id, \
			description);
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
	this->load		 = load;
	this->load_memory	 = load_memory;
	this->patch_enclave	 = patch_enclave;
	this->compute_attributes = compute_attributes;
	this->get_secs		 = get_secs;
	this->get_sigstruct	 = get_sigstruct;
	this->get_attributes	 = get_attributes;
	this->get_version	 = get_version;

	this->load_layouts	 = load_layouts;

	this->debug = debug;
	this->dump  = dump;
	this->whack = whack;

	return this;
}
