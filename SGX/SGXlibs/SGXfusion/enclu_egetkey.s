/** \file
 * This file contains the interface code which allows C code to execute
 * the ENCLU[EGETKEY] instruction.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
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
	 * The following function is the call point for the
	 * instruction.
	 *
	 * Arguements:
	 *
	 *	rdi:	Pointer to the SGX_keyrequest structure.
	 *	rsi:	Pointer to the buffer which will be loaded
	 *		with the key.
	 */

	.text

	.global	enclu_egetkey
	.type	enclu_egetkey,@function

enclu_egetkey:
	# Save the base pointer and set the new base pointer.
	pushq	%rbp
	movq	%rsp, %rbp

	# Save contents of registers which must be invariant.
	pushq	%rbx


	# Setup the instruction call registers.
	#
	# RBX:	Address of SGX_keyrequest structure.
	# RCX:	Address of buffer to contain key.
	movq	%rdi, %rbx
	movq	%rsi, %rcx


	# The EGETKEY leaf code is loaded into the RAX register and
	# the ENCLU.EGETKEY instruction is executed via a byte encoded
	# instruction sequence.
	mov	$1, %rax
	.byte	0x0f, 0x01, 0xd7


	# Restore the saved register.
	popq	%rbx

	# Restore the stack and base pointer and return to the caller.
	mov	%rbp, %rsp
	popq	%rbp
	ret

	/*
	 * Define the size of the enclu_egetkey 'function'.
	 */
	.size	enclu_egetkey, .-enclu_egetkey
