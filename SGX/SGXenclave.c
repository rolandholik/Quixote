/** \file
 * This file contains the implementation of an object which is used to
 * manage a Software Guard Extension (SGX) enclave.  This object is
 * responsible for intereacting with the operating system provided
 * driver which provides access to the ENCLS privileged instructions
 * which are used to manipulate an enclave at the hardware level.
 */

/**************************************************************************
 * (C)Copyright 2016, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local defines. */
#define DEVICE "/dev/isgx"


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
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXenclave.h"
#include "SGXloader.h"
#include "SGXsigstruct.h"


/* Object state extraction macro. */
#define STATE(var) CO(SGXenclave_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SGXenclave_OBJID)
#error Object identifier not defined.
#endif


/* Prototype for SGX bootstrap function. */
extern int boot_sgx(struct SGX_tcs *, long fn, const void *, void *, void *);


/** SGXenclave private state information. */
struct NAAAIM_SGXenclave_State
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

	/* The enclave loader object. */
	SGXloader loader;

	/* The SGX Enclave Control Structure. */
	struct SGX_secs secs;

	/* The processor security version the enclave is based on. */
	uint8_t cpu_svn[16];

	/* The enclave start address and the virtual page count. */
	unsigned long int enclave_address;
	uint64_t page_cnt;

	/*
	 * The set of available execution threads are stored as TCS
	 * pages in the following Buffer object.  The thread_cnt
	 * variable holds the current slot which is available.
	 *
	 * Support will need to be integrated for implementing binding
	 * policies which 'lock' a particular thread to a specific
	 * context of execution in the enclave.
	 */
	size_t thread_cnt;
	Buffer threads;
};


/*
 * The following functions are 'bridge' functions which are used to
 * handle OCALL events.  They are currently located here in order to
 * simplify testing and implementation of enclave functionality.
 */
void push_ocall_frame(unsigned int *frame_ptr)

{
	return;
}
void pop_ocall_frame()

{
	return;
}

#if 0
int sgx_ocall(unsigned int ocall_slot, void *ocall_table, void *ocall_data, \
	      void *thread)

{
	fprintf(stdout, "Enclave requested OCALL slot: %i\n", ocall_slot);
	return 0;
}
#endif


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SGXenclave_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SGXenclave_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SGXenclave_OBJID;


	S->poisoned = false;
	S->debug    = false;

	S->fd = -1;

	S->loader  = NULL;

	memset(&S->secs,   '\0', sizeof(struct SGX_secs));
	memset(S->cpu_svn, '\0', sizeof(S->cpu_svn));

	S->enclave_address = 0;
	S->page_cnt	   = 0;

	S->thread_cnt = 0;
	S->threads    = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements a comprehensive setup and initialization of
 * an enclave.  It is designed to reduce the amount of boilerplate
 * code needed in an application to get an enclave to the point where
 * it can be called.   This also includes configuring a global
 * exception handler.
 *
 * \param this		A pointer to the enclave object that is to be
 *			setup.
 *
 * \param name		A pointer to a null terminated buffer
 *			containing the pathname to the enclave to
 *			be loaded.
 *
 * \param token		A pointer to a null terminated buffer
 *			containing the pathname to the file containing
 *			the initialization token.
 *
 * \param debug		A boolean flag valued used to indicate whether
 *			or not the enclave is to be initialized in
 *			debug mode.
 *
 * \return	A boolean value is returned to indicate whether or not
 *		setup of the enclave was successful.  A false value
 *		indicates the setup failed while a true value
 *		indicates the enclave is initialized and ready to be
 *		called.
 */

static _Bool setup(CO(SGXenclave, this), CO(char *, name), CO(char *, token), \
		  const _Bool debug)

{
	_Bool retn = false;

	struct SGX_einittoken *einit = NULL;

	Buffer bufr = NULL;

	File token_file = NULL;


	/* Install the SGX exception handler. */
	if ( !sgx_configure_exception() )
		ERR(goto done);


	/* Load the initialization token. */
	if ( (token != NULL) && (token[0] != '\0') ) {
		INIT(HurdLib, Buffer, bufr, ERR(goto done));
		INIT(HurdLib, File, token_file, ERR(goto done));

		token_file->open_ro(token_file, token);
		if ( !token_file->slurp(token_file, bufr) )
			ERR(goto done);
		einit = (void *) bufr->get(bufr);
	}


	/* Load and initialize the enclave. */
	if ( !this->open_enclave(this, DEVICE, name, debug) )
		ERR(goto done);

	if ( !this->create_enclave(this) )
		ERR(goto done);

	if ( !this->load_enclave(this) )
		ERR(goto done);

	if ( !this->init_enclave(this, einit) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(token_file);

	return retn;

}


/**
 * External public method.
 *
 * This method opens the SGX interface device and loads the SGX
 * metadata and program segment data.
 *
 * \param this		A pointer to the object which is to hold the
 *			metadata.
 *
 * \param device	A pointer to a null-terminated buffer which
 *			contains the path specification for the SGX
 *			device node.
 *
 * \param enclave	A pointer to a null-terminated buffer which
 *			contains the path specification to the shared
 *			object implementation of the enclave.
 *
 * \param debug		A boolean flag used to indicate whether or not
 *			the enclave is to be initialized in debug mode.
 *
 * \return	If an error is encountered while opening the enclave a
 *		false value is returned.   A true value indicates the
 *		enclave is ready for creation.
 */

static _Bool open_enclave(CO(SGXenclave, this), CO(char *, device), \
			  CO(char *, enclave), _Bool debug)

{
	STATE(S);

	_Bool retn = false;


	/* Open the SGX device node. */
	if ( (S->fd = open(device, O_RDWR)) < 0 )
		ERR(goto done);

	/* Load the SGX metadata and shared object file. */
	INIT(NAAAIM, SGXloader, S->loader, ERR(goto done));
	if ( S->debug )
		S->loader->debug(S->loader, true);
	if ( !S->loader->load_secs(S->loader, enclave, &S->secs, debug) )
		ERR(goto done);

	/* Initialize the thread control arena. */
	INIT(HurdLib, Buffer, S->threads, ERR(goto done));

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method opens the SGX interface device and loads the SGX
 * metadata and program segment data from a memory image.
 *
 * \param this		A pointer to the object which is to hold the
 *			metadata.
 *
 * \param device	A pointer to a null-terminated buffer which
 *			contains the path specification for the SGX
 *			device node.
 *
 * \param enclave	A pointer to a memory buffer which contains
 *			the enclave image.
 *
 * \param enclave_size	The size of the membory buffer containing
 *			the enclave image.
 *
 * \param debug		A boolean flag used to indicate whether or not
 *			the enclave is to be initialized in debug mode.
 *
 * \return	If an error is encountered while opening the enclave a
 *		false value is returned.   A true value indicates the
 *		enclave is ready for creation.
 */

static _Bool open_enclave_memory(CO(SGXenclave, this), CO(char *, device),  \
				 const char * enclave, size_t enclave_size, \
				 _Bool debug)

{
	STATE(S);

	_Bool retn = false;


	/* Open the SGX device node. */
	if ( (S->fd = open(device, O_RDWR)) < 0 )
		ERR(goto done);

	/* Load the SGX metadata and shared object file. */
	INIT(NAAAIM, SGXloader, S->loader, ERR(goto done));
	if ( S->debug )
		S->loader->debug(S->loader, true);
	if ( !S->loader->load_secs_memory(S->loader, enclave, enclave_size, \
					  &S->secs, debug) )
		ERR(goto done);

	/* Initialize the thread control arena. */
	INIT(HurdLib, Buffer, S->threads, ERR(goto done));

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method creates the SGX enclave based on information in the
 * SGX Enclave Control Structure (SECS).
 *
 * \param this		A pointer to the object representing the
 *			enclave to be created.
 *
 * \return	If an error is encountered while creating the enclave
 *		a false value is returned.   A true value indicates the
 *		enclave was successfully created.
 */

static _Bool create_enclave(CO(SGXenclave, this))

{
	STATE(S);

	_Bool retn = false;

	void *address;

	struct SGX_create_param create_param;


	/* Verify object status and ability to create enclave. */
	if ( S->poisoned )
		ERR(goto done);

	/* Create an appropriate memory mapping for the enclave. */
	if ( (address = mmap(NULL, S->secs.size,		 \
			     PROT_READ | PROT_WRITE | PROT_EXEC, \
			     MAP_SHARED, S->fd, 0)) == NULL )
		ERR(goto done);
	S->secs.base = (uint64_t) address;


	/* Create the enclave based on the SECS parameters. */
	create_param.secs = &S->secs;

	if ( ioctl(S->fd, SGX_IOCTL_ENCLAVE_CREATE, &create_param) < 0 )
		ERR(goto done);
	if ( S->debug ) {
		fputs("Enclave created:\n", stdout);
		fprintf(stdout, "\tSize: 0x%lx\n", S->secs.size);
		fprintf(stdout, "\tStart: 0x%lx\n", S->secs.base);
	}
	S->enclave_address = S->secs.base;

	retn = true;


 done:

	return retn;
}


/**
 * External public method.
 *
 * This method loads a previously created enclave using the contents
 * of the shared enclave image.
 *
 * \param this		A pointer to the object representing the enclave
 *			which is being loaded.
 *
 * \return	If an error is encountered while loading the enclave
 *		a false value is returned.   A true value indicates the
 *		enclave was successfully loaded.
 */

static _Bool load_enclave(CO(SGXenclave, this))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object. */
	if ( S->poisoned )
		ERR(goto done);


	/* Load the TEXT portion of the enclave. */
	if ( !S->loader->load_segments(S->loader, this) )
		ERR(goto done);

	/* Load the layout portion of the enclave. */
	if ( !S->loader->load_layouts(S->loader, this) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Internal private function.
 *
 * This function implements the computation of the set of processor
 * features which will be available to the enclave.
 *
 * The processor capabilities are encoded into a 64-bit vector using
 * bit positions which are agreed to between the Trusted Enclave code
 * and this code.
 *
 * The original Intel code used what appeared to be boilerplate code
 * to compute the feature set from scratch.  This seemed to be
 * unnecessarily redundant since at a minimum this code will be
 * running on a processor with Skylake or better capabilities.  If the
 * processor is a 'GenuineIntel' processor a value consistent with our
 * Skylake reference platforms is returned.
 *
 * No arguments are specified.
 *
 * \return	This function returns the set of processor
 *		capabilities encoded in bit positions which are
 *		interrogated by the trusted enclave code.
 */

static uint64_t _cpu_info(void)

{
	uint32_t eax,
		 ebx,
		 ecx,
		 edx;

	uint64_t cpu_info = 0x00000001ULL;


	/* Determine if this is an Intel CPU. */
	__asm("movl %4, %%eax\n\t"
	      "cpuid\n\t"
	      "movl %%eax, %0\n\t"
	      "movl %%ebx, %1\n\t"
	      "movl %%ecx, %2\n\t"
	      "movl %%edx, %3\n\t"
	      /* Output. */
	      : "=r" (eax), "=r" (ebx), "=r" (ecx), "=r" (edx)
	      /* Input. */
	      : "r" (0x0)
	      /* Clobbers. */
	      : "eax", "ebx", "ecx", "edx");
	if ( eax == 0 )
		return cpu_info;
	if ( !((ebx == 0x756e6547) && (ecx == 0x6c65746e) && \
	       (edx == 0x49656e69)) )
		return cpu_info;


	/*
	 * If this is an Intel processor and an enclave has been loaded
	 * assume a basic Skylake feature set.
	 */
	return 0xe9fffff;
}


/**
 * Internal private method.
 *
 * This method is responsible for executing the enclave initialize
 * code.  This code is implemented in the -1 enclave execution slot
 * and implements basic initialization of the enclave.
 *
 * \param this	A pointer to the enclave whose initialization thread
 *		is to be run.
 *
 * \param rc	A pointer to an integer variable which will hold
 *		the return value from the enclave bootstrap code.
 *
 * \return	If a failure is detected in the initialization process
 *		a false value is returned.  A true value indicates the
 *		enclave was initialized.
 */

static _Bool _init_enclave(CO(SGXenclave, this), int *rc)

{
	STATE(S);

	_Bool retn = false;

	struct SGX_sdk_info {
		uint64_t cpu_features;
		int version;
	} info;


	info.version	  = 0;
	info.cpu_features = _cpu_info();

	if ( !this->boot_slot(this, -1, NULL, &info, rc) )
		ERR(goto done);

	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method initializes an enclave which has previously been
 * loaded.  This initialization step is the final step in preparing an
 * enclave for execution.  For a non-launch enclave an initialization
 * token generated by the launch token is needed for the
 * initialization process.
 *
 * \param this		A pointer to the object representing the enclave
 *			which will be initialized.
 *
 * \param token		A pointer to a launch token which has been
 *			initialized for this enclave.
 *
 * \return		If an error is encountered while initializing
 *			the enclave a false value is returned.  A true
 *			value indicates the enclave was successfully
 *			loaded.
 */

static _Bool init_enclave(CO(SGXenclave, this), struct SGX_einittoken *token)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct SGX_sigstruct sigstruct;

	struct SGX_init_param init_param;


	/* Verify object. */
	if ( S->poisoned )
		ERR(goto done);


	/*
	 * Get the signature structure from the enclave metadata and
	 * initialize the EINIT token.
	 */
	if ( !S->loader->get_sigstruct(S->loader, &sigstruct) )
		ERR(goto done);


	/* Populate the initialization control structure. */
	memset(&init_param, '\0', sizeof(struct SGX_init_param));
	init_param.addr	      = S->enclave_address;
	init_param.einittoken = token;
	init_param.sigstruct  = &sigstruct;

	if ( (rc = ioctl(S->fd, SGX_IOCTL_ENCLAVE_INIT, &init_param)) != 0 )
		ERR(goto done);


	/* Run the enclave initialization routine. */
	if ( !_init_enclave(this, &rc) )
		ERR(goto done);


	/* Update SECS structure based on initialized enclave. */
	S->secs.attributes |= 1;
	if ( token != NULL ) {
		memcpy(S->secs.mrsigner, token->mr_signer.m, \
		       sizeof(S->secs.mrsigner));
		memcpy(S->secs.mrenclave, token->mr_enclave.m, \
		       sizeof(S->secs.mrenclave));
		memcpy(S->cpu_svn, token->cpusvnle, sizeof(S->cpu_svn));
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}



/**
 * External public method.
 *
 * This method implements the initialization of the Intel Launch
 * Enclave (LE) which is distributed in binary form only.  The ability
 * to load and seal the LE is a necessary pre-requisite for support of
 * loading independently developed enclaves.  These enclaves require
 * an processor specific EINITTOKEN which the LE is used to generate.
 *
 * \param this		A pointer to the object representing the
 *			launch enclave which is to be loaded.
 *
 * \return		If an error is encountered while initializing
 *			the launch enclave a false value is returned.
 *			A true value indicates the enclave was
 *			successfully loaded.
 */

static _Bool init_launch_enclave(CO(SGXenclave, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct SGX_sigstruct sigstruct;

	struct SGX_einittoken einittoken;

	struct SGX_init_param init_param;

	SGXsigstruct LEsigstruct = NULL;


	/* Verify object. */
	if ( S->poisoned )
		ERR(goto done);


	/*
	 * Use the binary SIGSTRUCT provided by Intel to support
	 * loading of the Launch Enclave.
	 */
	INIT(NAAAIM, SGXsigstruct, LEsigstruct, ERR(goto done));
	if ( !LEsigstruct->get_LE(LEsigstruct, &sigstruct) )
		ERR(goto done);

	memset(&einittoken, '\0', sizeof(struct SGX_einittoken));


	/* Populate the initialization control structure. */
	memset(&init_param, '\0', sizeof(struct SGX_init_param));
	init_param.addr	      = S->enclave_address;
	init_param.einittoken = &einittoken;
	init_param.sigstruct  = &sigstruct;

	if ( (rc = ioctl(S->fd, SGX_IOCTL_ENCLAVE_INIT, &init_param)) != 0 )
		ERR(goto done);


	/* Run the enclave initialization routine. */
	if ( !_init_enclave(this, &rc) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(LEsigstruct);

	return retn;
}


/**
 * External public method.
 *
 * This method adds a page to the enclave.  The final arguement to the
 * method call specifies whether or not the enclave measurement is
 * extended with the contents of the page.
 *
 * The nature of the flags which define whether or not the contents of
 * the page should be extended into the enclave measurement is
 * confusing.  The Intel SDK assigns meaning to two bit positions in
 * the flags arguement.  One bit indicates the page is to be added and
 * the second indicates whether the contents of the page should be
 * extended into the enclave measurement.
 *
 * In contrast the kernel driver only acts on the page addition flag
 * and treats this as an indication the contents of the page is NOT to
 * be extended into the enclave measurement.
 *
 * \param this		A pointer to the object representing the enclave
 *			which is having a page added to it.
 *
 * \param page		A pointer to a memory buffer containing the
 *			page which is to be added.
 *
 * \param secinfo	A pointer to the data structure which defines
 *			the security characteristics of the page which
 *			is to be added.
 *
 * \param flags		A bit encoding of the flags which define the type
 *			of page insertion which will be carried out.
 *
 * \return	If an error is encountered while adding the page a false
 *		value is returned.   A true value indicates the
 *		enclave was successfully loaded.
 */

static _Bool add_page(CO(SGXenclave, this), CO(uint8_t *, page), \
		      struct SGX_secinfo *secinfo, const uint8_t flags)

{
	STATE(S);

	_Bool retn = false;

	struct SGX_add_param add_param;


	/* Verify object. */
	if ( S->poisoned )
		ERR(goto done);


	/* Initialize the page addition parameters and add page. */
	memset(&add_param, '\0', sizeof(add_param));
	add_param.addr	    = S->enclave_address + (4096 * S->page_cnt);
	add_param.user_addr = (unsigned long) page;
	add_param.secinfo   = secinfo;

	if ( flags & SGX_PAGE_EXTEND )
		add_param.mrmask |= 0xFFFF;

	if ( ioctl(S->fd, SGX_IOCTL_ENCLAVE_ADD_PAGE, &add_param) < 0 ) {
		perror("page add error");
		ERR(goto done);
	}
	S->page_cnt += 1;

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method adds a 'hole' in the enclave.  Its implementation was
 * inspired by the fact that the Intel SDK uses a sparse virtual
 * memory map to implement 'guard' pages between the memory arenas.
 *
 * A 'hole' is a page in the enclave which does not have its virtual
 * address mapped to a page in the Enclave Page Cache.  References to
 * any addresses in this page range generate the equivalent of a page
 * fault which generates an asynchronous enclave exit event.
 *
 * \param this	The object representing the enclave which is to have
 *		a hole punched into it.

 * \return	If an error is encountered while adding the hole a false
 *		value is returned.   A true value indicates the
 *		hole was successfully punched.
 */

static _Bool add_hole(CO(SGXenclave, this))

{
	STATE(S);


	/* Verify object status. */
	if ( S->poisoned )
		ERR(return false);

	++S->page_cnt;

	return true;
}


/**
 * External public method.
 *
 * This method returns the current relative virtual address of the
 * enclave represented by this object.  The relative virtual address
 * is the byte displacement from the start of the enclave to the
 * next page which will be added to enclave.
 *
 * \param this	The object representing the enclave whose
 *		a hole punched into it.

 * \return	The functions returns the current size of the enclave
 *		which is the allocated page count of the enclave
 *		multipled by the page size of the enclave.
 */

static unsigned long int get_address(CO(SGXenclave, this))

{
	STATE(S);


	/* Verify object status. */
	if ( S->poisoned )
		ERR(return false);

	return S->page_cnt * 4096;
}


/**
 * External public method.
 *
 * This method adds a thread entry to the enclave.  The total number
 * of execution threads which are supported by an enclave are defined
 * when the layout metadata is built during the signing process.
 *
 * There is one Task Control Structure (TCS) defined for each exection
 * thread.  The SGXloader object calls back into this method to
 * designate that the next page added will be a TCS definition page.
 * This function captures the virtual address of this incoming page
 * as a TCS definition page.  This virtual address is used in the
 * dispatch function which generates the ECALL into the enclave.
 *
 * \param this		A pointer to the object representing the
 *			enclave which is having a thread added to it.
 *
 * \return	If an error is encountered while adding the thread a
 *		false value is returned.  A true value indicates the
 *		thread was successfully added.
 */

static _Bool add_thread(CO(SGXenclave, this))

{
	STATE(S);

	_Bool retn = false;

	unsigned long int addr;


	/* Object verification. */
	if ( S->poisoned )
		ERR(goto done);


	addr = S->enclave_address + (S->page_cnt * 4096);
	if ( !S->threads->add(S->threads, (unsigned char *) &addr, \
			      sizeof(unsigned long int)) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor method for returning an
 * available thread slot.
 *
 * \param this		A pointer to the object representing the enclave
 *			which which a thread is being requested from.
 *
 * \param tcs		A pointer to a variable which will be loaded with
 *			the virtual address of a candidate task control
 *			structure.
 *
 * \return	If a thread is not available a false value is
 *		returned.  A true value indicates the supplied
 *		structure contains a valid thread definition.
 */

static _Bool get_thread(CO(SGXenclave, this), unsigned long int *tcs)

{
	STATE(S);

	_Bool retn = false;

	unsigned long int *ap,
			  addr;

	size_t num_threads;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/*
	 * Verify a thread slot is available.  A lack of slots is
	 * not treated as a condition to poison the enclave since the
	 * caller may elect to wait for a slot to become available.
	 */
	num_threads = S->threads->size(S->threads) / sizeof(unsigned long int);
	if ( S->thread_cnt >= num_threads )
		return false;


	/* Copy the TCS into the caller supplied buffer. */
	ap  = (unsigned long int *) S->threads->get(S->threads);
	ap += S->thread_cnt;

	addr = *ap;
	memcpy(tcs, &addr, sizeof(unsigned long int));

	++S->thread_cnt;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Internal private function.
 *
 * This function is responsible for saving the current floating point
 * state of the processor.  It is called immediately before enclave
 * execution is requested.
 *
 * \param save_area	A pointer to a user supplied byte buffer which
 *			will be loaded with the floating point state.
 *
 * \return	No return value is defined.
 */


static void _save_fp_state(uint8_t *save_area)

{
	uint8_t *save;

	uint32_t eax,
		 ebx,
		 ecx,
		 edx;

	uint64_t hardware_xfrm;


	/* Obtain the platform XFRM status. */
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
		hardware_xfrm = ((uint64_t) edx << 32ULL) | eax;
	}
	else
		hardware_xfrm = 0x3ULL;


	/* Flush floating point exceptions. */
	__asm("fwait");


	/* Save the floating point status in the supplied buffer. */
	save = (uint8_t *) (((size_t) save_area + (16-1)) & ~(16-1));
	__asm("fxsaveq (%0)\n\t"
	      /* Output. */
	      :
	      /* Input. */
	      : "r" (save)
	      /* Clobbers. */
	      : "memory");


	/* Clear the YMM registers if needed. */
	if ( hardware_xfrm & 0x4 )
		__asm("vzeroupper\n\t");

	return;
}


/**
 * Internal private function.
 *
 * This function is responsible for restoring the floating point state
 * of the processor which was previously saved by the _save_fp_state
 * function.
 *
 * \param save_area	A pointer to a user supplied byte buffer which
 *			contains the floating point state to be
 *			restored.
 *
 * \return	No return value is defined.
 */


static void _restore_fp_state(uint8_t *save_area)

{
	uint8_t *sp = (uint8_t *) (((size_t) save_area + (16-1)) & ~(16-1));


	__asm("fxsaveq (%0)\n\t"
	      /* Output. */
	      :
	      /* Input. */
	      : "r" (sp));

	return;
}


/**
 * External public method.
 *
 * This method implements calling an enclave execution slot.
 * When an enclave is constructed a series of execution 'slots' are
 * defined which contain points to the ECALL routines which are
 * defined for this enclave.  The enclave defined routines begin
 * number with slot 0.
 *
 * In addition there are three default execution slots which implement
 * the following:
 *
 *	-1 -> Enclave initialization.
 *	-2 -> Enclave OCALL return.
 *	-3 -> Enclave exception handling.
 *
 * \param this		A pointer to the object representing the enclave
 *			whose execution slot is to be called.
 *
 * \param slot		The number of the execution slot which is to
 *			be invoked.
 *
 * \param ocall		A pointer to the OCALL API definition table
 *			for the slot which will be called.
 *
 * \param ecall		A pointer to the ECALL API definition table
 *			for the slot which will be called.
 *
 * \return	If execution of a slot fails a false value is returned
 *		and the enclave is poisoned.  A true value indicates
 *		the execution was successful.
 */

static _Bool boot_slot(CO(SGXenclave, this), int slot, CO(void *, ocall), \
		       void *ecall, int *retc)

{
	STATE(S);

	_Bool retn = false;

	uint8_t xsave_buffer[528];

	int rc;

	struct SGX_tcs *tcs = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);

	/* Get an available thread slot. */
	if ( !this->get_thread(this, (unsigned long int *) &tcs) )
		ERR(goto done);

	/* Invoke the enclave slot. */
	_save_fp_state(xsave_buffer);
	rc = boot_sgx(tcs, slot, ocall, ecall, this);
	_restore_fp_state(xsave_buffer);
	*retc = rc;
	--S->thread_cnt;
	if ( rc != 0 ) {
		fprintf(stderr, "Enter enclave returns: %d\n", rc);
		ERR(goto done);
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the invocation of OCALL processing which is
 * requested by an enclave which has had a slot 'booted' by this object.
 *
 * This method is called by the sgx_ocall function which simply serves
 * as a thin interface layer between the assembler based trampoline
 * code which mediates access into and out of an enclave.

 * \param this		A pointer to the object representing the enclave
 *			which is having an ocall invoked on it.
 *
 * \param slot		The number of the execution slot which is being
 *			invoked.
 *
 * \param ocall		A pointer to the OCALL API definition table.
 *
 * \param interface	The data structure which is being used to
 *			convey data from the enclave to this
 *			untrusted excecution slot.
 *
 * \return	This method returns the return code generated by the
 *		OCALL code which is requested.
 */

static int boot_ocall(CO(SGXenclave, this), int slot, CO(void *, ocall), \
		      CO(void *, interface))

{
	const struct {
		size_t nr_ocall;
		void *table[];
	} *ocall_table;

	int (*ocall_function)(const void *);


	ocall_table    = ocall;
	ocall_function = ocall_table->table[slot];

	return ocall_function(interface);
}


/**
 * External public method.
 *
 * This method implements returning the target information for
 * an enclave so a report can be generated against it.
 *
 * \param this	A pointer to the enclave object for which target
 *		information is to be returned.
 *
 * \param tgt	A pointer to the target information structure which
 *		is to be populated.
 *
 * \return	If an error is encountered while generating the target
 *		information a false value is returned.  A true value
 *		indicates the object contains valid information about
 *		the enclave.
 */

static void get_target_info(CO(SGXenclave, this), struct SGX_targetinfo *tgt)

{
	STATE(S);


	/* Populate the target information. */
	memset(tgt, '\0', sizeof(struct SGX_targetinfo));

	tgt->miscselect = S->secs.miscselect;
	memcpy(tgt->mrenclave.m, S->secs.mrenclave, sizeof(S->secs.mrenclave));
	memcpy(&tgt->attributes, &S->secs.attributes, sizeof(tgt->attributes));


	return;
}


/**
 * External public method.
 *
 * This method implements the retrieval of the SGX attributes from the
 * enclave represented by the object.  This is a passthrough accessor
 * call to the SGX loader object.
 *
 * \param this	A pointer to the object representing the enclave
 *		whose attributes are to be returned.
 *
 * \return	If an error is encountered while retrieving the attributes
 *		a false value is returned.  A true value is returned
 *		if a valid attribute structure is being returned to the
 *		caller.
 */

static _Bool get_attributes(CO(SGXenclave, this), sgx_attributes_t *attributes)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Get the signature structure from the enclave metadata. */
	if ( !S->loader->get_attributes(S->loader, attributes) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the retrieval of the enclave control
 * information for the enclave that was loaded.
 *
 * \param this	A pointer to the object representing the enclave
 *		whose token is to be returned.
 *
 * \param secs	A pointer to an enclave control structure that will be
 *		populated with the values for the loaded enclave.
 *
 * \return	No return value is defined.
 */

static void get_secs(CO(SGXenclave, this), struct SGX_secs *secs)

{
	STATE(S);

	*secs  = S->secs;
	return;
}


/**
 * External public method.
 *
 * This method implements an accessor method for returning the platform
 * security version of an enclave.  This is a structure which contains
 * the security version of the enclave and the processor security
 * version.
 *
 * \param this	A pointer to the object representing the enclave
 *		whose security version is to be returned.
 *
 * \param psvn	A pointer to the structure which will be populated
 *		with the security version information.
 *
 * \return	No return value is defined.
 */

static void get_psvn(CO(SGXenclave, this), struct SGX_psvn *psvn)

{
	STATE(S);

	psvn->isv_svn = S->secs.isvsvn;
	memcpy(psvn->cpu_svn, S->cpu_svn, sizeof(psvn->cpu_svn));
	return;
}


/**
 * External public method.
 *
 * This method implements setting the debug status of the enclave.
 * Enabling debug in the enclave also causes debug status to be set
 * on the metadata manager and the loader.
 *
 * \param this		A pointer to the object whose debug status is
 *			to be modified.
 *
 * \param debug		The debug status to be set for the object.
 *
 * \return	No return value is defined.
 */

static void debug(CO(SGXenclave, this), const _Bool debug)

{
	STATE(S);


	S->debug = debug;
	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for an SGXenclave object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SGXenclave, this))

{
	STATE(S);


	if ( S->enclave_address != 0 )
		munmap((void *) S->enclave_address, S->secs.size);
	if ( S->fd != -1 )
		close(S->fd);

	WHACK(S->threads);
	WHACK(S->loader);


	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SGXenclave object.
 *
 * \return	A pointer to the initialized SGXenclave.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SGXenclave NAAAIM_SGXenclave_Init(void)

{
	auto Origin root;

	auto SGXenclave this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SGXenclave);
	retn.state_size   = sizeof(struct NAAAIM_SGXenclave_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SGXenclave_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->setup = setup;

	this->open_enclave	  = open_enclave;
	this->open_enclave_memory = open_enclave_memory;
	this->create_enclave = create_enclave;
	this->load_enclave   = load_enclave;

	this->init_enclave	  = init_enclave;
	this->init_launch_enclave = init_launch_enclave;

	this->add_page	  = add_page;
	this->add_hole	  = add_hole;
	this->get_address = get_address;

	this->add_thread = add_thread;
	this->get_thread = get_thread;

	this->boot_slot	 = boot_slot;
	this->boot_ocall = boot_ocall;

	this->get_target_info = get_target_info;
	this->get_attributes  = get_attributes;
	this->get_secs	      = get_secs;
	this->get_psvn	      = get_psvn;

	this->debug = debug;
	this->whack = whack;

	return this;
}
