/** \file
 * This file implements an object used to locate the organization which
 * orginates a user identity.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <String.h>

#include "NAAAIM.h"
#include "OrgSearch.h"
#include "IDtoken.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_OrgSearch_OBJID)
#error Object identifier not defined.
#endif


/**
 * The following structure is used to control each subordinate process.
 */

struct pcontrol {
	_Bool found;
	unsigned int cnt;
	unsigned const char *start;
	unsigned char id[NAAAIM_IDSIZE];
};


/** OrgSearch private state information. */
struct NAAAIM_OrgSearch_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Number of identities in the block. */
	unsigned int idcnt;

	/* Memory block containing the organizational identities. */
	unsigned char *idblock;

	/* Matching organizational identity. */
	Buffer matched;

	/* Owner of the shared memory object. */
	pid_t shmowner;

	/* Name of POSIX shared memory object. */
	String shmname;

	/* File descriptor to the shared memory object. */
	int shmfd;

	/*
	 * Number of subordinate processes to run and an array of
	 * structures to control each process.
	 */
	unsigned int processes;
	struct pcontrol *pcontrol;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_OrgSearch_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const OrgSearch_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_OrgSearch_OBJID;

	S->poisoned	= false;
	S->idcnt	= 0;
	S->idblock 	= NULL;

	S->shmowner	= 0;
	S->shmname	= NULL;
	S->shmfd       	= -1;
	S->processes	= 0;
	S->pcontrol	= NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements loading an ASCII organization file into a
 * memory buffer which will be iterated over to find the originating
 * identity.
 *
 * \param this		The organizational identity origin object which is
 *			to be searched.
 *
 * \param infile	The name of the text file containing the
 *			originating identities.
 *
 * \return		The number of originating identities loaded is
 *			returned to the caller.  A value of zero
 *			indicates there was a problem with the load.
 *			successful.
 */

static unsigned int load(const OrgSearch const this, const char * const infile)

{
	auto const OrgSearch_State const S = this->state;

	auto unsigned int retn = 0;

	auto char bufr[256];

	auto unsigned char *idbp;

	auto unsigned int size;

	auto FILE *fp = NULL;

	auto Buffer hex = NULL;


	/*
	 * Open the file and count the entries in the file in order to
	 * optimize the memory allocation of the buffer.
	 */
	if ( (fp = fopen(infile, "r")) == NULL ) {
		S->poisoned = true;
		goto done;
	}
	while ( fgets(bufr, sizeof(bufr), fp) != NULL )
		++S->idcnt;

	size = S->idcnt * sizeof(unsigned char) * NAAAIM_IDSIZE;
	if ( (S->idblock = malloc(size)) == NULL )
		goto done;
	idbp = S->idblock;


	/*
	 * Reset the input stream and read the file.  Treat the first
	 * field in the file as a hexademically coded identity and
	 * copy the binary form into the identity block.
	 */
	if ( (hex = HurdLib_Buffer_Init()) == NULL )
		goto done;

	rewind(fp);
	while ( fscanf(fp, "%64s ", bufr) == 1 ) {
		if ( !hex->add_hexstring(hex, bufr) )
			goto done;
		memcpy(idbp, hex->get(hex), hex->size(hex));
		idbp += NAAAIM_IDSIZE;
		hex->reset(hex);
	}

	retn = S->idcnt;

	
 done:
	if ( retn == false )
		S->poisoned = true;

	if ( fp != NULL )
		fclose(fp);
	if ( hex != NULL )
		hex->whack(hex);

	return retn;
}


/**
 * Internal private function.
 *
 * This function implements a search over a segment of the originating
 * identity list.  This function is designed to be called by the
 * search and parallel_search functions.
 *
 * \param token		The identity token containing the identity to
 *			be searched for.
 *
 * \param matchbufr	A buffer containing the identity to be
 *			matched.
 *
 * \param idbp		The character pointer for the starting
 *			position position of the search.
 *
 * \param cnt		The number of entries to be searched.
 *
 * \return		A boolean value is returned to indicate the
 *			success or failure of the search.  A true
 *			value indicates the search was successful.
 */

static _Bool _search_segment(const IDtoken const token,	  \
			     const Buffer const matchbufr, \
			     unsigned const char * idbp, unsigned int cnt)

{
	auto _Bool retn = false;

	auto unsigned int lp;


	/* Iterate through memory block looking for a match. */
	for (lp= 0; lp < cnt; ++lp) {
		if ( !matchbufr->add(matchbufr, idbp, NAAAIM_IDSIZE) )
			goto done;
		if ( token->matches(token, matchbufr) ) {
			retn = true;
			goto done;
		}
		idbp += NAAAIM_IDSIZE;
		matchbufr->reset(matchbufr);
	}


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements searching for the identity which originated
 * the organizational key and identity provided in the form of an
 * identity token object.
 * 
 * \param this		The organizational identity origin object which is
 *			to be searched.
 *
 * \param token		The identity token containing the identity to
 *			be searched for.
 *
 * \return		A boolean file is used to indicate whether or
 *			not the serach was successful.  A true value
 *			indicates a match was found.  If an error occured
 *			during he search the object is poisoned.  The
 *			poisoned method should be called to verify
 *			whether or not the failure was caused by an
 *			operational problem.
 */

static _Bool search(const OrgSearch const this, const IDtoken const token)

{
	auto const OrgSearch_State const S = this->state;

	auto _Bool retn = false;

	auto int status,
		 wretn;

	auto unsigned int lp = 0,
			  processes_left;

	auto pid_t pid,
		   slaves[S->processes];


	S->matched->reset(S->matched);

	/* Run a single threaded search. */
	if ( S->shmowner == 0 ) {
		if ( _search_segment(token, S->matched, S->idblock, S->idcnt) )
			return true;
		else
			return false;
	}


	/* Dispatch search to multiple subordinate processes. */
	fputs(".Using multi-processor search.\n", stderr);
	for (lp= 0; lp < S->processes; ++lp)
		S->pcontrol[lp].found = false;

	for (lp= 0; lp < S->processes; ++lp) {
		pid = fork();
		if ( pid == -1 ) {
			fputs("!Error on fork.\n", stderr);
			return false;
		}

		/* Child process. */
		if ( pid == 0 ) {
			if ( !_search_segment(token, S->matched,     \
					      S->pcontrol[lp].start, \
					      S->pcontrol[lp].cnt) )
				_exit(1);

			S->pcontrol[lp].found = true;
			memcpy(S->pcontrol[lp].id,	    \
			       S->matched->get(S->matched), \
			       S->matched->size(S->matched));
			_exit(0);
		}

		/* Parent process. */
		slaves[lp] = pid;
	}

	/* Parent process - wait for children. */
	processes_left = S->processes;
	while ( processes_left > 0 ) {
		wretn = waitpid(0, &status, 0);
		--processes_left;

		for (lp= 0; lp < S->processes; ++lp)
			if ( slaves[lp] == wretn )
				slaves[lp] = 0;

		if ( WIFEXITED(status) )
			fprintf(stderr, ".Search process %u terminated, " \
				"status = %d\n", wretn, WEXITSTATUS(status));
		if ( WIFSIGNALED(status) ) {
			fprintf(stderr, ".Search process %u terminated " \
				"early.\n", wretn);
			continue;
		}
		if ( WEXITSTATUS(status) != 0 )
			continue;

		for (lp= 0; lp < S->processes; ++lp)
			if ( S->pcontrol[lp].found ) {
				S->matched->add(S->matched,	    \
						S->pcontrol[lp].id, \
						NAAAIM_IDSIZE);
				retn = true;
			}

		if ( retn == true )
			for (lp= 0; lp < S->processes; ++lp)
				if ( slaves[lp] != 0 )
					kill(slaves[lp], SIGTERM);
	}


	return retn;
}


/**
 * External public method.
 *
 * This method sets up the object to dispatch searches across multiple
 * subordinate processes.  A posix shared memory area is used to
 * communicate between the subordinate process and the parent process.
 *
 * The shared memory is used to create an array of structures each
 * of which is used by one subordinate process.  The structure contains
 * a flag to indicate if the process found a match and the originating
 * identity.
 *
 * \param this	The object which is to be setup for parallel search.
 *
 * \param slots	The number of search slots to be craeted.  One process
 *		will be forked for each slot.
 *
 * \return	A boolean value is used to indicate whether or not
 *		setup succeeded.  A false value indicates failure to
 *		setup parallel search capability.
 */

static _Bool setup_parallel(const OrgSearch const this, unsigned int slots)

{
	auto const OrgSearch_State const S = this->state;

	auto char *err = NULL,
		  name[NAME_MAX];

	auto unsigned const char *start = S->idblock;

	auto unsigned int lp,
			  increment,
			  cnt	    = 0;

	auto struct pcontrol pcontrol[slots];


	/* Distribute search count over processors. */
	increment = S->idcnt / slots;
	if ( (S->idcnt % slots) != 0 )
		++increment;


	/* Dispatch searches to processors. */
	--slots;
	for (lp= 0; lp < slots; ++lp) {
		pcontrol[S->processes].found = false;
		pcontrol[S->processes].cnt   = increment;
		pcontrol[S->processes].start = start;
		memset(pcontrol[S->processes].id, '\0', \
		       sizeof(pcontrol[S->processes].id));

		start += (increment * NAAAIM_IDSIZE);
		cnt   += increment;
		++S->processes;
	}
	
	if ( (S->idcnt - cnt) != 0 ) {
		pcontrol[S->processes].found = false;
		pcontrol[S->processes].cnt   = S->idcnt - cnt;
		pcontrol[S->processes].start = start;
		++S->processes;
	}


	/*
	 * Allocate a POSIX shared memory segment and initialize the
	 * array of structures it will represent.
	 */
	S->shmowner = getpid();

	snprintf(name, sizeof(name), "/%s-%d", "OrgSearch", getpid());
	if ( (S->shmname = HurdLib_String_Init_cstr(name)) == NULL ) {
		err = "Error initialized shared memory name.";
		goto done;
	}

	if ( (S->shmfd = shm_open(name, O_RDWR | O_CREAT, \
				  S_IRUSR | S_IWUSR)) == -1 ) {
		err = "Error opening shared memory segment.";
		goto done;
	}

	lp = S->processes * sizeof(struct pcontrol);
	if ( ftruncate(S->shmfd, lp) == -1 ) {
		err = "Error setting shared memory segment size.";
		goto done;
	}

	if ( (S->pcontrol = mmap(NULL, lp, PROT_READ | PROT_WRITE, \
				 MAP_SHARED, S->shmfd, 0)) == MAP_FAILED ) {
		err = "Error mapping shared memory segment.";
		goto done;
	}

	for (lp= 0; lp < S->processes; ++lp)
		S->pcontrol[lp] = pcontrol[lp];


 done:
	if ( err != NULL ) {
		fprintf(stderr, "!%s\n", err);
		return false;
	}
		
	return true;
}


/**
 * External public method.
 *
 * This method implements retrieving the organizaional identity which
 * was matched.
 *
 * \param this	A pointer to the object from which the matching identity
 *		is to be retrieved.
 *
 * \param bufr	The Buffer object into which the identity is to be
 *		loaded.
 *
 * \return	A return value is used to indicate whether or not the
 *		retrieval was successful.  A true value indicates success.
 */

static _Bool get_match(const OrgSearch const this, const Buffer const bufr)

{
	auto const OrgSearch_State const S = this->state;

	auto _Bool retn = false;


	if ( S->poisoned )
		goto done;

	if ( !bufr->add_Buffer(bufr, S->matched) )
		goto done;

	retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	return retn;
}
	
	
/**
 * External public method.
 *
 * This method implements a destructor for a OrgSearch object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const OrgSearch const this)

{
	auto const OrgSearch_State const S = this->state;


	if ( S->idblock != NULL )
		free(S->idblock);
	if ( S->matched != NULL )
		S->matched->whack(S->matched);

	if ( S->shmfd != -1 )
		close(S->shmfd);
	if ( S->pcontrol != NULL )
		munmap(S->pcontrol, \
		       S->processes * sizeof(struct pcontrol));
	if ( (S->shmowner == getpid()) && (S->shmname != NULL) )
		shm_unlink(S->shmname->get(S->shmname));
	S->shmname->whack(S->shmname);
	
	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a OrgSearch object.
 *
 * \return	A pointer to the initialized OrgSearch.  A null value
 *		indicates an error was encountered in object generation.
 */

extern OrgSearch NAAAIM_OrgSearch_Init(void)

{
	auto Origin root;

	auto OrgSearch this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_OrgSearch);
	retn.state_size   = sizeof(struct NAAAIM_OrgSearch_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_OrgSearch_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	if ( (this->state->matched = HurdLib_Buffer_Init()) == NULL ) {
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->load	     = load;
	this->search	     = search;
	this->setup_parallel = setup_parallel;
	this->get_match	     = get_match;

	this->whack = whack;

	return this;
}
