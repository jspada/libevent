/* Portable arc4random implementation based on OpenBSD's arc4random.c
 * Portable version by Chris Davis, adapted for Libevent by Nick Mathewson
 * Extended by Joseph Spadavecchia, June 2013
 * Copyright (c) 2010 Chris Davis, Niels Provos, and Nick Mathewson
 * Copyright (c) 2010-2013 Niels Provos and Nick Mathewson
 *
 */

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Arc4 random number generator for OpenBSD.
 *
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * Here the stream cipher has been modified always to include the time
 * when initializing the state.  That makes it impossible to
 * regenerate the same random sequence twice, so this can't be used
 * for encryption, but will generate good random numbers.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 */

#include <inttypes.h>

#ifndef ARC4RANDOM_UINT32
#define ARC4RANDOM_UINT32 uint32_t
#endif

#ifndef __ARC4RANDOM_H__
#define __ARC4RANDOM_H__

#ifdef _WIN32
#define getpid _getpid
#define pid_t int
#endif

struct arc4_stream {
	unsigned char i;
	unsigned char j;
	unsigned char s[256];
	int initialized;
	pid_t stir_pid;
	int count;
	int seeded_ok;
};

/*
 * Initialise and stir arc4random data context rs
 */
int arc4random_init_r(struct arc4_stream *rs);

/*
 * Returns a pseudorandom number in the range of 0 to 2^32 - 1.
 */
ARC4RANDOM_UINT32 arc4random_r(struct arc4_stream *rs);

/*
 * Fills buf of length n bytes with ARC4 pseudorandom data.
 */
void arc4random_buf_r(struct arc4_stream *rs, void *buf, size_t n);

/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
unsigned int arc4random_uniform_r(struct arc4_stream *rs, unsigned int upper_bound);

/*
 * Permute ARC4 S-Boxes using entropy sources, such as /dev/urandom.
 */
int arc4random_stir_r(struct arc4_stream *rs);

/*
 * Permute ARC4 S-Boxes using buf of length n.
 */
void arc4random_addrandom_r(struct arc4_stream *rs, const unsigned char *buf, int n);

#endif /*__ARC4RANDOM_H__ */
