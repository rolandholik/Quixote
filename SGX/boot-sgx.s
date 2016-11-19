/** \file
 * This file contains the interface code which allows C code to call
 * the enclave entry code.  This code also handles enclave return and
 * differentiates between enclave exit, an outcall (OCALL) and
 * asynchronous exits.
 */

/**************************************************************************
 * (C)Copyright 2016, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/*
 * General assembler information useful for reading this file.
 *
 * The x86_64 Application Binary Interface (ABI) specifies that the
 * first six arguements to a function be passed in the following
 * registers:
 *
 *	rdi, rsi, rdx, rcx, r8, r9
 *
 * Any remaining parameters are passed by pushing them onto the stack
 * in reverse order.  This causes the parameters to be in their call
 * order on the stack, ie from lower to higher memory positions.
 *
 * A function must preserve the contents of the following over a
 * call:
 *
 *	rbx, rsp, rbp, r12, r13, r14, r15
 *
 * The following registers can be used as scratch registers in the
 * function:
 *
 *	rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11
 *
 * Values are returned from a function in the rax register.  A 128
 * bit value is returned by loading the higher order 64-bit word in
 * the rdx register.
 *
 * The following suffixes are used to denote the size of instructions:
 *
 *	b = byte (8 bit)
 *	s = short (16 bit)
 *	w = word (16 bit) word
 *	l = long (32 bit) double word
 *	q = quad (64 bit) quad word
 */
	
		
	/*
	 * The following function is the call point for enclave
	 * entry.
	 *
	 * Arguements:
	 *
	 *	rdi:	Enclave Task Control Structure (TCS) address.
	 *	rsi:	Enclave API slot.
	 *	rdx:	Address of OCALL API definition.
	 *	rcx:	Address of ECALL API definition for the API slot.
	 *	r8:	Pointer to the OCALL handler function.
	 */
	
	.text

	.global	boot_sgx
	.type	boot_sgx,@function
	
boot_sgx:
	# Save the base pointer and set the new base pointer.
	pushq	%rbp
	movq	%rsp, %rbp

	# Preserve registers which must remain invariant.  The final
	# subtraction is to align the stack pointer on a 16-byte
	# boundary for the call into the enclave.
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	sub	$-8, %rsp

	# The first arguement to this function is the address of the
	# task control structure.  Move this into the RBX register
	# which is the implicit location assumed by the ENCLU.EENTER
	# function.
	mov	%rdi, %rbx

	# The slot number of the API call is the first arguement to
	# the ENCLU.EENTER 'function' call.
	movslq	%esi, %rdi

	# The slot API is the second arguement to the current function
	# call.
	mov	%rcx, %rsi
	
	# The address to be called in the event of an asynchronous
	# enclave exit event is placed in the RCX register.  RIP based
	# addressing is used to get the address in a position independent
	# fashion.
	lea	.Laep_handler(%rip), %rcx
	
	# The EENTER leaf code is loaded into the RAX register and
	# the ENCLU.EENTER instruction is executed via a byte encoded
	# instruction sequence.
	mov	$2, %rax
	.byte	0x0f, 0x01, 0xd7

	# The next instruction executed after an ENCLU.EENTER instruction
	# will either be secondary to an ENCLU.EEXIT instruction or if
	# the enclave has issued an OCALL.  The exit reason is encoded
	# in the RDI register.
	#
	# A value of -1 in RDI indicates this is an ENCLU.EEXIT and
	# the return value from the enclave is in the RSI register.
	cmp	$-1, %rdi
	jne	1f
	movq	%rsi, %rax
	jmp	.Ldone

	# The return value from the enclave indicates that the enclave
	# is request processing of an OCALL.  We currently return an
	# error until we can get OCALL processing wired up.
1:	movq	$-2, %rax

	
.Ldone:	
	# Restore the registers which were preserved.
	movq	 (-0x8)(%rbp), %rbx
	movq	(-0x20)(%rbp), %r12
	movq	(-0x28)(%rbp), %r13
	movq	(-0x30)(%rbp), %r14
	movq	(-0x38)(%rbp), %r15

	# Restore the stack and base pointer and return to the caller.
	mov	%rbp, %rsp
	popq	%rbp
	ret


	/*
	 * In the event of an asynchronous enclave event we simply
	 * call back into the enclave with an ENCLU.EENTER
	 */
.Laep_handler:
	.byte	0x0f, 0x01, 0xd7


	/*
	 * Define the size of the boot_sgx 'function'.
	 */
	.size	boot_sgx, .-boot_sgx
