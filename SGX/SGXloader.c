/** \file
 * This file contains the implementation of an object which is used to
 * load the binary contents of an Intel Software Guard Extension (SGX)
 * enclave.
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
#include <sys/mman.h>
#include <fcntl.h>

#include <libelf.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXmetadata.h"
#include "SGXloader.h"


/* Object state extraction macro. */
#define STATE(var) CO(SGXloader_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SGXloader_OBJID)
#error Object identifier not defined.
#endif


/**
 * The following structure is used to define an enclave program segment.
 * For simplicity sake the structure uses the ELF program header to
 * save all of the information about the segment.   The physical data
 * is saved in the Buffer object which the structure references.
 */
struct segment {
	uint64_t flags;
	Elf64_Phdr phdr;
	Buffer data;
};


/** SGXloader private state information. */
struct NAAAIM_SGXloader_State
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

	/* Enclave file memory mapping information. */
	void *soimage;
	size_t sosize;

	/* ELF library descriptor. */
	Elf *elf;

	/* SGX metadata. */
	SGXmetadata metadata;

	/* The array of segments. */
	Buffer segments;

	/* A pointer to the TLS segment. */
	struct segment *tls;

	/* A pointer to the dynamic symbol segment. */
	Elf64_Dyn *dynptr;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SGXloader_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SGXloader_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SGXloader_OBJID;


	S->poisoned = false;

	S->soimage = NULL;
	S->sosize  = 0;

	S->metadata = NULL;
	S->segments = NULL;
	S->dynptr   = NULL;

	return;
}


/**
 * Internal private method.
 *
 * This method searches the dynamic symbol table for the tag specified
 * by the caller.
 *
 * \param this		A pointer to the loader object whose dynamic
 *			symbol table is to be searched.
 *
 * \param tag		The tag value to be located.
 *
 * \return	If the dynamic symbol tag is not found a NULL pointer
 *		is returned.  If the entry is found a pointer to the
 *		Elf64_Dyn structure is returned.
 */

static Elf64_Dyn *_get_tag(CO(SGXloader_State, S), Elf64_Sxword tag)

{
	Elf64_Dyn *dptr = S->dynptr;


	while ( dptr->d_tag != DT_NULL ) {
		if ( dptr->d_tag == tag )
			goto done;
		++dptr;
	}
	dptr = NULL;


 done:
	return dptr;
}


/**
 * Internal private method.
 *
 * This method implements saving a PT_LOAD segment.
 *
 * \param this		A pointer to the loader object to the segment is
 *			to be saved.
 *
 * \param phdr		A pointer to the ELF program header which
 *			references the segment to be loaded.
 *
 * \return	If an error is encountered while saving the segment a
 *		false value is returned.  A true value indicates the
 *		segment was saved.
 */

static _Bool _pt_load_segment(CO(SGXloader_State, S), CO(Elf64_Phdr *, phdr))

{
	_Bool retn = false;

	struct segment segment;


	/**
	 * Allocate the buffer for the segment array and clear the segment
	 * description structure.
	 */
	if ( S->segments == NULL )
		INIT(HurdLib, Buffer, S->segments, ERR(goto done));

	memset(&segment, '\0', sizeof(struct segment));


	/**
	 * Translate the ELF page protection flags into their SGX
	 * equivalents.  All pages of PT_LOAD type are considered to
	 * be regular pages.
	 */
	segment.flags = SGX_SECINFO_REG;
	if ( phdr->p_flags & PF_R )
		segment.flags |= SGX_SECINFO_R;
	if ( phdr->p_flags & PF_W )
		segment.flags |= SGX_SECINFO_W;
	if ( phdr->p_flags & PF_X )
		segment.flags |= SGX_SECINFO_X;

	segment.phdr = *phdr;

	INIT(HurdLib, Buffer, segment.data, ERR(goto done));

	if ( !segment.data->add(segment.data, S->soimage + phdr->p_offset, \
				phdr->p_filesz) )
		ERR(goto done);

	if ( !S->segments->add(S->segments, (unsigned char *) &segment, \
			       sizeof(struct segment)) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Internal private method.
 *
 * This method builds a relocation bitmap which details pages in the
 * TEXT section which have relocations and would thus necessitate an
 * enclave page being writable in order to support the runtime
 * patching which is needed.
 *
 * \param this		A pointer to the internal state of the loader
 *			object whose relocation map is to be built.
 *
 * \return	A true value is returned if a text relocation bitmap
 *		is needed and was created.  A false value indicates
 *		no such relocations were present.
 */

static _Bool _build_relocation_map(CO(SGXloader_State, S))

{
	_Bool retn = false;


	/*
	 * Verify there is something to do by first checking to see
	 * if a dynamic symbol table is present.  If this check passes
	 * verify that there are possible TEXT relocations present.
	 */
	if ( S->dynptr == NULL )
		goto done;
	if ( _get_tag(S, DT_TEXTREL) == NULL )
		goto done;

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the loading of the SGX binary data from the
 * enclave file.
 *
 * \param this		A pointer to the object which is to hold the
 *			metadata.
 *
 * \param enclave	A pointer to the null-terminated character
 *			buffer which holds the name of the enclave.
 *
 * \param debug		A boolean value which indicates whether or not
 *			the enclave is to be loaded in debug mode.
 *
 * \return	If an error is encountered while loading the metadata
 *		a false value is returned.  A true value is returned
 *		if the object contains valid metadata.
 */

static _Bool load(CO(SGXloader, this), CO(char *, enclave), const _Bool debug)

{
	STATE(S);

	_Bool retn = false;

	uint32_t segindex;

	size_t phnum;

	struct stat statbuf;

	Elf64_Ehdr *ehdr;

	Elf64_Phdr *phdr;


	/* Sanity check the object. */
	if ( S->poisoned )
		goto done;


	/* Load the SGA metadata. */
	INIT(NAAAIM, SGXmetadata, S->metadata, ERR(goto done));
	if ( !S->metadata->load(S->metadata, enclave) )
		ERR(goto done);
	if ( !S->metadata->compute_attributes(S->metadata, debug) )
		ERR(goto done);


	/* Open the shared object enclave and memory map the file. */
	if ( (S->fd = open(enclave, O_RDWR, 0)) < 0 )
		ERR(goto done);

	if ( fstat(S->fd, &statbuf) == -1 )
		ERR(goto done);
	S->sosize = statbuf.st_size;
	if ( (S->soimage = mmap(NULL, S->sosize, PROT_READ | PROT_WRITE, \
				MAP_PRIVATE, S->fd, 0)) == NULL )
		ERR(goto done);


	/* Patch the enclave shared image. */
	S->metadata->patch_enclave(S->metadata, S->soimage);


	/* Setup and initialize ELF access to the enclave. */
	if ( elf_version(EV_CURRENT) == EV_NONE )
		ERR(goto done);
	if ( (S->elf = elf_begin(S->fd, ELF_C_READ, NULL)) == NULL )
		ERR(goto done);
	if ( (ehdr = elf64_getehdr(S->elf)) == NULL )
		ERR(goto done);


	/*
	 * Iterate through the program segments and save references to
	 * relevant segments.
	 */
	if ( elf_getphdrnum(S->elf, &phnum) == -1 )
		ERR(goto done);
	if ( (phdr = elf64_getphdr(S->elf)) == NULL )
		ERR(goto done);

	for(segindex= 0; segindex < phnum; ++segindex, ++phdr) {
		if ( phdr->p_type == PT_LOAD ) {
			if ( !_pt_load_segment(S, phdr) )
				ERR(goto done);
		}
		if ( phdr->p_type == PT_DYNAMIC )
			S->dynptr = (Elf64_Dyn *) (S->soimage + \
						   phdr->p_offset);
	}

	if ( _build_relocation_map(S) ) {
		fputs("Writable TEXT relocations present but not " \
		      "supported.\n", stdout);
		goto done;
	}

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the loading of the SGX binary data from the
 * enclave file with return of the SGX Enclave Control Structure.  This
 * method allows a single call to load the enclave and return the
 * information needed to create the enclave.
 *
 * \param this		A pointer to the object which is to hold the
 *			metadata.
 *
 * \param enclave	A pointer to the null-terminated character
 *			buffer which holds the name of the enclave.
 *
 * \param secs		A pointer to the structure which will be loaded
 *			with the SECS information.
 *
 * \param debug		A boolean value which indicates whether or not
 *			the enclave is to be loaded in debug mode.
 *
 * \return	If an error is encountered while loading the enclave
 *		a false value is returned.  A true value is returned
 *		if the object contains valid metadata.
 */

static _Bool load_secs(CO(SGXloader, this), CO(char *, enclave), \
		       struct SGX_secs *secs, const _Bool debug)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		return false;


	/* Call the standard load method. */
	if ( !this->load(this, enclave, debug) )
		ERR(goto done);


	/* Get the SECS information from the enclave metadata. */
	if ( !S->metadata->get_secs(S->metadata, secs) )
		ERR(goto done);
	fprintf(stdout, "Loaded secs size: 0x%lx\n", secs->size);


	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements a diagnostic dump of the enclave binaryd ata.
 *
 * \param this		A pointer to the object whose content is to be
 *			dumped.
 *
 * \return	No return value is defined.
 */

static void dump(CO(SGXloader, this))

{
	STATE(S);

	uint32_t lp,
		 segcnt;

	struct segment *segptr;

	Elf64_Dyn *dynptr = S->dynptr;

	Buffer bf;


	segcnt = S->segments->size(S->segments) / sizeof(struct segment);
	segptr = (struct segment *) S->segments->get(S->segments);
	for (lp= 0; lp < segcnt; ++lp, ++segptr) {
		fprintf(stdout, "Segment #%d:\n", lp);
		fprintf(stdout, "\ttype: 0x%x\n", segptr->phdr.p_type);
		fprintf(stdout, "\tflags: 0x%x\n", segptr->phdr.p_flags);
		fprintf(stdout, "\toffset: 0x%lx\n", segptr->phdr.p_offset);
		fprintf(stdout, "\tvaddr: 0x%lx\n", segptr->phdr.p_vaddr);
		fprintf(stdout, "\tfile size: 0x%lx\n", \
			segptr->phdr.p_filesz);
		fprintf(stdout, "\tmem size: 0x%lx\n", segptr->phdr.p_memsz);
		fprintf(stdout, "\talign: 0x%lx\n", segptr->phdr.p_align);
		fprintf(stdout, "\tenclave flags: 0x%lx\n", segptr->flags);

		fprintf(stdout, "\nSegment #%d contents:\n", lp);
		bf = segptr->data;
		bf->hprint(bf);
		fputc('\n', stdout);
	}

	fputs("Dynamic symbol table:\n", stdout);
	while ( dynptr->d_tag != DT_NULL ) {
		fprintf(stdout, "\tTag: 0x%lx\n", dynptr->d_tag);
		++dynptr;
	}

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for an SGXloader object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SGXloader, this))

{
	STATE(S);

	uint32_t lp,
		 segcnt;

	struct segment *segptr;


	if ( S->soimage != NULL )
		munmap(S->soimage, S->sosize);
	if ( S->elf != NULL )
		elf_end(S->elf);
	if ( S->fd != -1 )
		close(S->fd);

	WHACK(S->metadata);

	if ( S->segments != NULL ) {
		segcnt = S->segments->size(S->segments) \
			/ sizeof(struct segment);
		segptr = (struct segment *) S->segments->get(S->segments);
		for (lp= 0; lp < segcnt; ++lp, ++segptr)
			WHACK(segptr->data);
	}
	WHACK(S->segments);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SGXloader object.
 *
 * \return	A pointer to the initialized SGXloader.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SGXloader NAAAIM_SGXloader_Init(void)

{
	auto Origin root;

	auto SGXloader this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SGXloader);
	retn.state_size   = sizeof(struct NAAAIM_SGXloader_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SGXloader_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->load	= load;
	this->load_secs = load_secs;

	this->dump  = dump;
	this->whack = whack;

	return this;
}
