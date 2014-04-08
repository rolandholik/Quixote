/** \file
 * This file provides the implementation of an object which provides
 * methods for implementing ephemeral key exchange based on Daniel
 * Bernstein's curve25519 elliptic curve.
 *
 * The implementation was taken from the 64-bit C based reference
 * implement available from Google code and which serves as the
 * most common reference implementation.
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 *
 * Copyright on the imported implementation is as follows:
 *
 * Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 * 
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here:
 *
 *	 http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation.
 **************************************************************************/


/* Include files. */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "RandomBuffer.h"
#include "Curve25519.h"

/* State extraction macro. */
#define STATE(var) CO(Curve25519_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Curve25519_OBJID)
#error Object identifier not defined.
#endif


/** Curve25519 private state information. */
struct NAAAIM_Curve25519_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/** The private portion of the keypair. */
	Buffer private;

	/** The public portion of the keypair. */
	Buffer public;
};


typedef uint8_t u8;
typedef uint64_t limb;
typedef limb felem[5];
/*
 * This is a special gcc mode for 128-bit integers. It's implemented on 64-bit
 * platforms only as far as I know.
 */
typedef unsigned uint128_t __attribute__((mode(TI)));

#undef force_inline
#define force_inline __attribute__((always_inline))


/**
 * Internal private function.
 *
 * Sum two numbers: output += in
 */
static inline void force_inline fsum(limb *output, const limb *in)

{
	output[0] += in[0];
	output[1] += in[1];
	output[2] += in[2];
	output[3] += in[3];
	output[4] += in[4];
}


/**
 * Internal private function.
 *
 * Multiply a number by a scalar: output = in * scalar
 */

static inline void force_inline fscalar_product(felem output, const felem in, \
						const limb scalar)
{
	uint128_t a;

	a = ((uint128_t) in[0]) * scalar;
	output[0] = ((limb)a) & 0x7ffffffffffff;

	a = ((uint128_t) in[1]) * scalar + ((limb) (a >> 51));
	output[1] = ((limb)a) & 0x7ffffffffffff;

	a = ((uint128_t) in[2]) * scalar + ((limb) (a >> 51));
	output[2] = ((limb)a) & 0x7ffffffffffff;

	a = ((uint128_t) in[3]) * scalar + ((limb) (a >> 51));
	output[3] = ((limb)a) & 0x7ffffffffffff;

	a = ((uint128_t) in[4]) * scalar + ((limb) (a >> 51));
	output[4] = ((limb)a) & 0x7ffffffffffff;

	output[0] += (a >> 51) * 19;
}


/**
 * Internal private function.
 *
 * Find the difference of two numbers: output = in - output
 * (note the order of the arguments!)
 *
 * Assumes that out[i] < 2**52
 * On return, out[i] < 2**55
 */

static inline void force_inline fdifference_backwards(felem out, \
						      const felem in) {
  /* 152 is 19 << 3 */
  static const limb two54m152 = (((limb)1) << 54) - 152;
  static const limb two54m8 = (((limb)1) << 54) - 8;

  out[0] = in[0] + two54m152 - out[0];
  out[1] = in[1] + two54m8 - out[1];
  out[2] = in[2] + two54m8 - out[2];
  out[3] = in[3] + two54m8 - out[3];
  out[4] = in[4] + two54m8 - out[4];
}

/**
 * Internal private function.
 *
 *
 * Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * Assumes that in[i] < 2**55 and likewise for in2.
 * On return, output[i] < 2**52
 */

static inline void force_inline fmul(felem output, const felem in2, \
				     const felem in)

{
	uint128_t t[5];
	limb r0,r1,r2,r3,r4,s0,s1,s2,s3,s4,c;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];

	s0 = in2[0];
	s1 = in2[1];
	s2 = in2[2];
	s3 = in2[3];
	s4 = in2[4];

	t[0]  =  ((uint128_t) r0) * s0;
	t[1]  =  ((uint128_t) r0) * s1 + ((uint128_t) r1) * s0;
	t[2]  =  ((uint128_t) r0) * s2 + ((uint128_t) r2) * s0 + ((uint128_t) r1) * s1;
	t[3]  =  ((uint128_t) r0) * s3 + ((uint128_t) r3) * s0 + ((uint128_t) r1) * s2 + ((uint128_t) r2) * s1;
	t[4]  =  ((uint128_t) r0) * s4 + ((uint128_t) r4) * s0 + ((uint128_t) r3) * s1 + ((uint128_t) r1) * s3 + ((uint128_t) r2) * s2;

	r4 *= 19;
	r1 *= 19;
	r2 *= 19;
	r3 *= 19;

	t[0] += ((uint128_t) r4) * s1 + ((uint128_t) r1) * s4 + ((uint128_t) r2) * s3 + ((uint128_t) r3) * s2;
	t[1] += ((uint128_t) r4) * s2 + ((uint128_t) r2) * s4 + ((uint128_t) r3) * s3;
	t[2] += ((uint128_t) r4) * s3 + ((uint128_t) r3) * s4;
	t[3] += ((uint128_t) r4) * s4;

	r0 = (limb)t[0] & 0x7ffffffffffff; c = (limb)(t[0] >> 51);
	t[1] += c;      r1 = (limb)t[1] & 0x7ffffffffffff; c = (limb)(t[1] >> 51);
	t[2] += c;      r2 = (limb)t[2] & 0x7ffffffffffff; c = (limb)(t[2] >> 51);
	t[3] += c;      r3 = (limb)t[3] & 0x7ffffffffffff; c = (limb)(t[3] >> 51);
	t[4] += c;      r4 = (limb)t[4] & 0x7ffffffffffff; c = (limb)(t[4] >> 51);
	r0 +=   c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
	r1 +=   c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
	r2 +=   c;

	output[0] = r0;
	output[1] = r1;
	output[2] = r2;
	output[3] = r3;
	output[4] = r4;
}


/**
 * Internal private function.
 */

static inline void force_inline fsquare_times(felem output, const felem in, \
					      limb count)

{
	uint128_t t[5];
	limb r0,r1,r2,r3,r4,c;
	limb d0,d1,d2,d4,d419;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];

	do {
		d0 = r0 * 2;
		d1 = r1 * 2;
		d2 = r2 * 2 * 19;
		d419 = r4 * 19;
		d4 = d419 * 2;

		t[0] = ((uint128_t) r0) * r0 + ((uint128_t) d4) * r1 + (((uint128_t) d2) * (r3     ));
		t[1] = ((uint128_t) d0) * r1 + ((uint128_t) d4) * r2 + (((uint128_t) r3) * (r3 * 19));
		t[2] = ((uint128_t) d0) * r2 + ((uint128_t) r1) * r1 + (((uint128_t) d4) * (r3     ));
		t[3] = ((uint128_t) d0) * r3 + ((uint128_t) d1) * r2 + (((uint128_t) r4) * (d419   ));
		t[4] = ((uint128_t) d0) * r4 + ((uint128_t) d1) * r3 + (((uint128_t) r2) * (r2     ));

		r0 = (limb)t[0] & 0x7ffffffffffff; c = (limb)(t[0] >> 51);
		t[1] += c;      r1 = (limb)t[1] & 0x7ffffffffffff; c = (limb)(t[1] >> 51);
		t[2] += c;      r2 = (limb)t[2] & 0x7ffffffffffff; c = (limb)(t[2] >> 51);
		t[3] += c;      r3 = (limb)t[3] & 0x7ffffffffffff; c = (limb)(t[3] >> 51);
		t[4] += c;      r4 = (limb)t[4] & 0x7ffffffffffff; c = (limb)(t[4] >> 51);
		r0 +=   c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
		r1 +=   c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
		r2 +=   c;
	} while(--count);

	output[0] = r0;
	output[1] = r1;
	output[2] = r2;
	output[3] = r3;
	output[4] = r4;
}


/**
 * Internal private function.
 *
 * Load a little-endian 64-bit number
 */

static limb load_limb(const u8 *in)

{
	return
		((limb)in[0]) |
		(((limb)in[1]) << 8) |
		(((limb)in[2]) << 16) |
		(((limb)in[3]) << 24) |
		(((limb)in[4]) << 32) |
		(((limb)in[5]) << 40) |
		(((limb)in[6]) << 48) |
		(((limb)in[7]) << 56);
}


/**
 * Internal private function.
 */

static void store_limb(u8 *out, limb in)

{
	out[0] = in & 0xff;
	out[1] = (in >> 8) & 0xff;
	out[2] = (in >> 16) & 0xff;
	out[3] = (in >> 24) & 0xff;
	out[4] = (in >> 32) & 0xff;
	out[5] = (in >> 40) & 0xff;
	out[6] = (in >> 48) & 0xff;
	out[7] = (in >> 56) & 0xff;
}


/**
 * Internal private function.
 *
 * Take a little-endian, 32-byte number and expand it into polynomial
 * form .
*/
static void fexpand(limb *output, const u8 *in)

{
	output[0] = load_limb(in) & 0x7ffffffffffff;
	output[1] = (load_limb(in+6) >> 3) & 0x7ffffffffffff;
	output[2] = (load_limb(in+12) >> 6) & 0x7ffffffffffff;
	output[3] = (load_limb(in+19) >> 1) & 0x7ffffffffffff;
	output[4] = (load_limb(in+24) >> 12) & 0xfffffffffffff;
}


/**
 * Internal private function.
 *
 * Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static void fcontract(u8 *output, const felem input)

{
	uint128_t t[5];

	t[0] = input[0];
	t[1] = input[1];
	t[2] = input[2];
	t[3] = input[3];
	t[4] = input[4];

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

	/* now t is between 0 and 2^255-1, properly carried.
	 * case 1: between 0 and 2^255-20. case 2: between 2^255-19
	 *  and 2^255-1.
	 */

	t[0] += 19;

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

	/* now between 19 and 2^255-1 in both cases, and offset by 19. */

	t[0] += 0x8000000000000 - 19;
	t[1] += 0x8000000000000 - 1;
	t[2] += 0x8000000000000 - 1;
	t[3] += 0x8000000000000 - 1;
	t[4] += 0x8000000000000 - 1;

	/* now between 2^255 and 2^256-20, and offset by 2^255. */

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[4] &= 0x7ffffffffffff;

	store_limb(output,    t[0] | (t[1] << 51));
	store_limb(output+8,  (t[1] >> 13) | (t[2] << 38));
	store_limb(output+16, (t[2] >> 26) | (t[3] << 25));
	store_limb(output+24, (t[3] >> 39) | (t[4] << 12));
}


/**
 * Internal private function.
 *
 * Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   x2 z3: long form
 *   x3 z3: long form
 *   x z: short form, destroyed
 *   xprime zprime: short form, destroyed
 *   qmqp: short form, preserved
 */

static void fmonty(limb *x2, limb *z2, /* output 2Q */
		   limb *x3, limb *z3, /* output Q + Q' */
		   limb *x, limb *z,   /* input Q */
		   limb *xprime, limb *zprime, /* input Q' */
		   const limb *qmqp /* input Q - Q' */)

{
	limb origx[5], origxprime[5], zzz[5], xx[5], zz[5], xxprime[5],
		zzprime[5], zzzprime[5];

	memcpy(origx, x, 5 * sizeof(limb));
	fsum(x, z);
	fdifference_backwards(z, origx);  // does x - z

	memcpy(origxprime, xprime, sizeof(limb) * 5);
	fsum(xprime, zprime);
	fdifference_backwards(zprime, origxprime);
	fmul(xxprime, xprime, z);
	fmul(zzprime, x, zprime);
	memcpy(origxprime, xxprime, sizeof(limb) * 5);
	fsum(xxprime, zzprime);
	fdifference_backwards(zzprime, origxprime);
	fsquare_times(x3, xxprime, 1);
	fsquare_times(zzzprime, zzprime, 1);
	fmul(z3, zzzprime, qmqp);

	fsquare_times(xx, x, 1);
	fsquare_times(zz, z, 1);
	fmul(x2, xx, zz);
	fdifference_backwards(zz, xx);  // does zz = xx - zz
	fscalar_product(zzz, zz, 121665);
	fsum(zzz, xx);
	fmul(z2, zz, zzz);
}


/**
 * Internal private function.
 *
 *
 * Maybe swap the contents of two limb arrays (@a and @b), each @len elements
 * long. Perform the swap iff @swap is non-zero.
 *
 * This function performs the swap without leaking any side-channel
 * information.
 */

static void swap_conditional(limb a[5], limb b[5], limb iswap)

{
	unsigned i;
	const limb swap = -iswap;

	for (i = 0; i < 5; ++i) {
		const limb x = swap & (a[i] ^ b[i]);
		a[i] ^= x;
		b[i] ^= x;
	}
}


/**
 * Internal private function.
 *
 * Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 * resultx/resultz: the x coordinate of the resulting curve point
 * (short form)
 *   n: a little endian, 32-byte number
 *   q: a point of the curve (short form)
 */

static void cmult(limb *resultx, limb *resultz, const u8 *n, const limb *q)

{
	limb a[5] = {0}, b[5] = {1}, c[5] = {1}, d[5] = {0};
	limb *nqpqx = a, *nqpqz = b, *nqx = c, *nqz = d, *t;
	limb e[5] = {0}, f[5] = {1}, g[5] = {0}, h[5] = {1};
	limb *nqpqx2 = e, *nqpqz2 = f, *nqx2 = g, *nqz2 = h;

	unsigned i, j;

	memcpy(nqpqx, q, sizeof(limb) * 5);

	for (i = 0; i < 32; ++i) {
		u8 byte = n[31 - i];
		for (j = 0; j < 8; ++j) {
			const limb bit = byte >> 7;

			swap_conditional(nqx, nqpqx, bit);
			swap_conditional(nqz, nqpqz, bit);
			fmonty(nqx2, nqz2,
			       nqpqx2, nqpqz2,
			       nqx, nqz,
			       nqpqx, nqpqz,
			       q);
			swap_conditional(nqx2, nqpqx2, bit);
			swap_conditional(nqz2, nqpqz2, bit);

			t = nqx;
			nqx = nqx2;
			nqx2 = t;
			t = nqz;
			nqz = nqz2;
			nqz2 = t;
			t = nqpqx;
			nqpqx = nqpqx2;
			nqpqx2 = t;
			t = nqpqz;
			nqpqz = nqpqz2;
			nqpqz2 = t;

			byte <<= 1;
		}
	}

	memcpy(resultx, nqx, sizeof(limb) * 5);
	memcpy(resultz, nqz, sizeof(limb) * 5);
}


/**
 * Internal private function.
 *
 * Shamelessly copied from djb's code, tightened a little
 */

static void crecip(felem out, const felem z)

{
	felem a,t0,b,c;

	/* 2 */ fsquare_times(a, z, 1); // a = 2
	/* 8 */ fsquare_times(t0, a, 2);
	/* 9 */ fmul(b, t0, z); // b = 9
	/* 11 */ fmul(a, b, a); // a = 11
	/* 22 */ fsquare_times(t0, a, 1);
	/* 2^5 - 2^0 = 31 */ fmul(b, t0, b);
	/* 2^10 - 2^5 */ fsquare_times(t0, b, 5);
	/* 2^10 - 2^0 */ fmul(b, t0, b);
	/* 2^20 - 2^10 */ fsquare_times(t0, b, 10);
	/* 2^20 - 2^0 */ fmul(c, t0, b);
	/* 2^40 - 2^20 */ fsquare_times(t0, c, 20);
	/* 2^40 - 2^0 */ fmul(t0, t0, c);
	/* 2^50 - 2^10 */ fsquare_times(t0, t0, 10);
	/* 2^50 - 2^0 */ fmul(b, t0, b);
	/* 2^100 - 2^50 */ fsquare_times(t0, b, 50);
	/* 2^100 - 2^0 */ fmul(c, t0, b);
	/* 2^200 - 2^100 */ fsquare_times(t0, c, 100);
	/* 2^200 - 2^0 */ fmul(t0, t0, c);
	/* 2^250 - 2^50 */ fsquare_times(t0, t0, 50);
	/* 2^250 - 2^0 */ fmul(t0, t0, b);
	/* 2^255 - 2^5 */ fsquare_times(t0, t0, 5);
	/* 2^255 - 21 */ fmul(out, t0, a);
}


/**
 * Internal private function.
 *
 * This function was originally the main entry point of the program.
 * It is preserved as the callpoint for the object oriented interface
 * to key generation.
 *
 * \param mypublic	A pointer to a character buffer which will
 *			receive key output.
 *
 * \param secret	A pointer to a character buffer containing the
 *			private key value.
 *
 * \param base		A pointer to a character buffer containing the
 *			basepoint for the curve.
 *
 * \return		No return value is defined.
 */

static void curve25519_donna(uint8_t *mypublic, const uint8_t *secret, \
			     const uint8_t *basepoint)

{
	limb bp[5], x[5], z[5], zmone[5];
	uint8_t e[32];
	int i;

	for (i = 0; i < 32; ++i)
		e[i] = secret[i];

	e[0]  &= 248;
	e[31] &= 127;
	e[31] |= 64;

	fexpand(bp, basepoint);
	cmult(x, z, e, bp);
	crecip(zmone, z);
	fmul(z, x, zmone);
	fcontract(mypublic, z);

	return;
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Curve25519_State
 * structure which holds state information for each instantiated
 * object.
 *
 * This object starts out in poisoned status and the call to the
 * ->generate method activates the object.
 *
 * \param S	A pointer to the object containing the state
 *		information which is to be initialized.
 */

static void _init_state(CO(Curve25519_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Curve25519_OBJID;

	S->poisoned = false;
	S->private  = NULL;
	S->public   = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements generation of a public/private keypair.
 * This function must be called before any subsequent calls to other
 * methods.
 *
 * \param this	A pointer to the object which is to have a keypair
 *		generated.
 */

static _Bool generate(CO(Curve25519, this))

{
	STATE(S);

	_Bool retn = false;

	uint8_t public[32],
		private[32],
		bp[32] = {9};

	Buffer b;

	RandomBuffer rnd = NULL;


	/* Generate and save the private key. */
	INIT(NAAAIM, RandomBuffer, rnd, goto done);
	if ( !rnd->generate(rnd, sizeof(private)) )
		goto done;
	b = rnd->get_Buffer(rnd);

	memcpy(private, b->get(b), sizeof(private));
	if ( !S->private->add_Buffer(S->private, b) )
		goto done;

	/* Generate the key pair. */
	curve25519_donna(public, private, bp);

	/* Save the public key. */
	if ( S->public->add(S->public, public, sizeof(public)) )
		retn = true;

 done:
	if ( !retn ) 
		S->poisoned = false;

	WHACK(rnd);
	return retn;
}


/**
 * External public method.
 *
 * This method implements computation of a shared secret based on
 * the private key entrained in the object and a provided public
 * key.
 *
 * \param this	The object which is to have a shared secret generated
 *		from.
 *
 * \param pub	An object containing the public key which the shared
 *		secret is to be generated from.
 *
 * \param key	The object into which the key is to be loaded.
 *
 * \return	A boolean value is used to indicate the status of
 *		key generation.  A false value indicates a failure
 *		which will be secondary to input parameters or status
 *		of the object.  A true value indicates the key is
 *		valid.
 */

static _Bool compute(CO(Curve25519, this), CO(Buffer, pub), CO(Buffer, key))

{
	STATE(S);

	_Bool retn = false;

	uint8_t shared[32],
		private[32],
		public[32];


	/* Arguement check. */
	if ( S->poisoned )
		goto done;
	if ( (pub == NULL) || pub->poisoned(pub) || (pub->size(pub) != 32) )
		goto done;
	if ( (key == NULL) || key->poisoned(key) )
		goto done;

	/* Load public/private values and call the generator. */
	memcpy(private, S->private->get(S->private), sizeof(private));
	memcpy(public, pub->get(pub), sizeof(public));
	curve25519_donna(shared, private, public);

	/* Copy the shared key to the object provided by the caller. */
	if ( key->add(key, shared, sizeof(shared)) )
		retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements retrieval of the public key from the object.
 *
 * \param this	The object from which the public key is to be retrieved.
 *
 * \return	A null value is returned if the object is poisoned or
 *		if a key has not been generatd.
 */

static Buffer get_public(CO(Curve25519, this))

{
	STATE(S);

	Buffer pub = S->public;


	/* Arguement checks. */
	if ( S->poisoned )
		return NULL;
	if ( pub->poisoned(pub) || (pub->size(pub) != 32) )
		return NULL;

	/* Return the public key. */
	return pub;
}


/**
 * External public method.
 *
 * This method implements access to the status of the curve
 * generation logic.
 *
 * \param this	A pointer to the object which is to be queried.
 */

static _Bool poisoned(CO(Curve25519, this))

{
	return this->state->poisoned;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Curve25519 object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(Curve25519, this))

{
	STATE(S);

	WHACK(S->private);
	WHACK(S->public);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a Curve25519 object.
 *
 * \return	A pointer to the initialized Curve25519.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Curve25519 NAAAIM_Curve25519_Init(void)

{
	Origin root;

	Curve25519 this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_Curve25519);
	retn.state_size   = sizeof(struct NAAAIM_Curve25519_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Curve25519_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->private, goto err);
	INIT(HurdLib, Buffer, this->state->public,  goto err);

	/* Method initialization. */
	this->generate	 = generate;
	this->compute	 = compute;
	this->get_public = get_public;

	this->poisoned = poisoned;
	this->whack    = whack;

	return this;


 err:
	WHACK(this->state->private);
	WHACK(this->state->public);
	return NULL;
}
