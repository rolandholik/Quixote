/** \file
 * This file contains an implementation of an SGX specific signal handler.
 * Exception handling is unique for SGX since the architectural model
 * generates a signal/exception in response to error conditions as well
 * as requests for service by an enclave.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local definitions. */

/* Needed to get symbolic names for register definitions. */
#define _GNU_SOURCE

/* ECALL slot number for the enclave exception handler. */
#define ECMD_EXCEPT -3

/* Definitions for the enclave exception return codes. */
#define SE_EENTER  2
#define SE_ERESUME 3


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/ucontext.h>

#include <HurdLib.h>

#include <NAAAIM.h>

#include "SGX.h"
#include "SRDEenclave.h"


/**
 * Static state variable to indicate the SGX exception handler has
 * been installed.
 */
static _Bool Handler_installed = false;


/*
 * Prototypes for the assembler functions returning the address of the
 * Asynchronous Enclave eXit (AEX) handler and for entering an enclave.
 */
extern uint64_t boot_sgx_get_exit_handler(void);
extern int boot_sgx(struct SGX_tcs *, long fn, const void *, void *, void *);


/**
 * Private function.
 *
 * This function implements the SGX exception handler.  This function
 * determines whether or not the exception that was generated is
 * suitable for exception handling by the enclave.  If so the original
 * call information is retrieved based on the stack base pointer
 * register (RBP) value at the time the enclave was called.
 *
 * The original Task Control Segment (TCS) pointer, the OCALL table
 * pointer and the enclave object are retrieved by referencing values
 * downward in the stack from the RBP pointer.  These three data elements
 * are used to re-enter the enclave with a request to execute the enclave
 * exception handler.
 *
 * The enclave will indicate whether or not the exception was handled
 * and if execution is to continue.  Execution will be aborted if
 * the enclave indicates this is an unhandled exception.  If the
 * enclave indicates the exception has been handled the signal
 * handler will return allowing the normal execution path to continue.
 *
 * \param signal	The number of the signal which caused the
 *			handler to execute.
 *
 * \param siginfo	A pointer to the structure that contains
 *			information regarding the signal that was
 *			generated.
 *
 * \param private	A pointer to exception specific data.
 */

void exception_handler(int signal, siginfo_t *siginfo, void *private)

{
	_Bool fatal_signal = true;

	int retc;

	uint64_t rip,
		 rax,
		 rbp,
		 exit_handler_address;

	void *tcs   = NULL,
	     *ocall = NULL;

	ucontext_t *sigcontext;

	SRDEenclave enclave = NULL;


	/* Display untrapped faults and abort. */
	switch ( signal ) {
		case SIGFPE:
			fputs("SGXrdk: Enclave floating point exception.\n", \
			      stderr);
			break;
		case SIGSEGV:
			fputs("SGXrdk: Enclave segmentation fault.\n", stderr);
			break;
		case SIGBUS:
			fputs("SGXrdk: Enclave bus fault.\n", stderr);
			break;
		case SIGTRAP:
			fputs("SGXrdk: Enclave trap.\n", stderr);
			break;
		default:
			fatal_signal = false;
			break;
	}

	if ( fatal_signal )
		exit(1);


	/*
	 * The private data pointer points to a signal context structure
	 * that contains the synthetic state created by the enclave
	 * exception.  The synthetic register values are used to obtain
	 * the information needed to re-enter the enclave to initiate
	 * the exception processing.
	 */
	sigcontext = private;
	rip = sigcontext->uc_mcontext.gregs[REG_RIP];
	rax = sigcontext->uc_mcontext.gregs[REG_RAX];
	rbp = sigcontext->uc_mcontext.gregs[REG_RBP];

	exit_handler_address = boot_sgx_get_exit_handler();


	/* Detect and handle a standard enclave exception. */
	if ( (rip == exit_handler_address) && (rax == SE_ERESUME) ) {
		tcs	= (void *) *(uint64_t *) (rbp - 6*8);
		ocall   = (void *) *(uint64_t *) (rbp - 7*8);
		enclave = *((SRDEenclave *) (rbp - 8*8));

		retc = boot_sgx(tcs, ECMD_EXCEPT, ocall, NULL, enclave);
		if ( retc != 0 ) {
			fputs("SGXrdk: Fatal enclave exception, aborting " \
			      "enclave.\n", stderr);
			exit(1);
		}
	}


	return;
}


/**
 * Internal public function.
 *
 * This method installs the signal handling infrastructure.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of installing the signal handler.  A false
 *		value
 */

_Bool sgx_configure_exception(void)

{
	_Bool retn = false;

	struct sigaction signal_action;


	/* Only install the handler once. */
	if ( Handler_installed )
		return true;


	/* Initialize structures. */
	memset(&signal_action, '\0', sizeof(struct sigaction));

	if ( sigemptyset(&signal_action.sa_mask) == -1 )
		ERR(goto done);
	if ( sigprocmask(SIG_SETMASK, NULL, &signal_action.sa_mask) == -1 )
		ERR(goto done);


	/* Configure the handler. */
	signal_action.sa_flags     = SA_SIGINFO | SA_NODEFER | SA_RESTART;
	signal_action.sa_sigaction = exception_handler;

	if ( sigaction(SIGSEGV, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGFPE, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGILL, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGBUS, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGTRAP, &signal_action, NULL) == -1 )
		goto done;

	retn	    	  = true;
	Handler_installed = true;


 done:
	return retn;
}
