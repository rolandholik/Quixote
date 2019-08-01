/** \file
 * This file contains the interface code which allows C code to execute
 * the rdrand instruction.  The rdrand instruction generates a
 * hardware generated random number.  If successful the random bytes
 * are copied into the buffer specified by the caller.
 *
 * The processor instruction is documented to potentially not be able
 * to generate the requested amount of randomness.  In this case a
 * false value is returned to the caller.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
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
	 * instruct.
	 *
	 * Arguements:
	 *
	 *	rdi:	Pointer to a buffer which is 8 bytes long.
	 */

	.text

	.global	rdrand
	.type	rdrand,@function

rdrand:
	# Save the base pointer and set the new base pointer.
	pushq	%rbp
	movq	%rsp, %rbp


	# Execute the rdrand instruction and check for valid
	# randomness.
	rdrand	%rax
	jc	.Lrandom_ok
	xor	%rax, %rax
	jmp	.Ldone


.Lrandom_ok:
	movq	%rax, (%rdi)
	movq	$1, %rax


.Ldone:
	# Restore the stack and base pointer and return to the caller.
	mov	%rbp, %rsp
	popq	%rbp
	ret
