/*
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* This file has our secure PRNG code.  On platforms that have arc4random(),
 * we just use that.  Otherwise, we include arc4random.c as a bunch of static
 * functions, and wrap it lightly.  We don't expose the arc4random*() APIs
 * because A) they aren't in our namespace, and B) it's not nice to name your
 * APIs after their implementations.  We keep them in a separate file
 * so that other people can rip it out and use it for whatever.
 */

#include "event2/event-config.h"
#include "evconfig-private.h"

#include <limits.h>

#include "util-internal.h"
#include "evthread-internal.h"
#include "mm-internal.h"
#include "arc4random-internal.h"

#ifdef EVENT__DISABLE_THREAD_SUPPORT
	#define RNG_LOCK(rng)
	#define RNG_UNLOCK(rng)
#else
	#define RNG_LOCK(rng) if (EVTHREAD_LOCKING_ENABLED()) \
				EVLOCK_LOCK(rng->lock, 0)
	#define RNG_UNLOCK(rng) if (EVTHREAD_LOCKING_ENABLED()) \
					EVLOCK_UNLOCK(rng->lock, 0)
#endif

struct evutil_secure_rng {
	struct arc4_stream state;
#ifndef EVENT__DISABLE_THREAD_SUPPORT
	void *lock;
#endif
};

struct evutil_secure_rng *
evutil_secure_rng_new(void)
{
	struct evutil_secure_rng *rng;

	if ((rng = mm_calloc(1, sizeof(struct evutil_secure_rng))) == NULL) {
		event_warn("%s: calloc", __func__);
		return NULL;
	}

#ifndef EVENT__DISABLE_THREAD_SUPPORT
	if (EVTHREAD_LOCKING_ENABLED())
		EVTHREAD_ALLOC_LOCK(rng->lock, 0);

	/*
	 * We don't need to lock because no other thread could have a
	 * handle to this context yet.
	 */
#endif

	if (arc4random_init_r(&rng->state) == -1) {
		event_warn("%s: rng init", __func__);
		evutil_secure_rng_free(rng);
        }

	return rng;
}

void
evutil_secure_rng_free(struct evutil_secure_rng *rng)
{
	if (!rng) {
		event_warnx("%s: no rng to free", __func__);
		return;
	}

#ifndef EVENT__DISABLE_THREAD_SUPPORT
	if (EVTHREAD_LOCKING_ENABLED()) {
		if (rng->lock) {
			EVTHREAD_FREE_LOCK(rng->lock, 0);
			rng->lock = NULL;
		}
	}
#endif

	mm_free(rng);
}

int
evutil_secure_rng_init_r(struct evutil_secure_rng *rng)
{
	int ret;

	if (!rng) {
		event_warnx("%s: no rng to init", __func__);
		return -1;
	}

	RNG_LOCK(rng);
	ret = arc4random_init_r(&rng->state);
	RNG_UNLOCK(rng);

	return ret;
}

void
evutil_secure_rng_get_bytes_r(struct evutil_secure_rng *rng, void *buf, size_t n)
{
	if (!rng) {
		event_warnx("%s: no rng to get_bytes", __func__);
		return;
	}

	RNG_LOCK(rng);
	arc4random_buf_r(&rng->state, buf, n);
	RNG_UNLOCK(rng);
}

void
evutil_secure_rng_add_bytes_r(struct evutil_secure_rng *rng, const char *buf, size_t n)
{
	if (!rng) {
		event_warnx("%s: no rng to add_bytes", __func__);
		return;
	}

	RNG_LOCK(rng);
	arc4random_addrandom_r(&rng->state, (unsigned char*)buf,
	    n>(size_t)INT_MAX ? INT_MAX : (int)n);
	RNG_UNLOCK(rng);
}

/*
 * Global rng compatibility interface
 *
 */

#ifdef EVENT__HAVE_ARC4RANDOM

/*
 * BSD and OSX have their own ARC4 implementation, which is
 * threadsafe, so use this when available.
 */

#include <stdlib.h>
#include <string.h>

#ifndef EVENT__DISABLE_THREAD_SUPPORT
int
evutil_secure_rng_global_setup_locks_(const int enable_locks)
{
	return 0;
}
#endif

void
evutil_free_secure_rng_globals_(void)
{
	/* Do nothing */
}

int
evutil_secure_rng_init(void)
{
	/* call arc4random() now to force it to self-initialize */
	(void) arc4random();
	return 0;
}

void
evutil_secure_rng_get_bytes(void *buf, size_t n)
{
#if defined(EVENT__HAVE_ARC4RANDOM_BUF) && !defined(__APPLE__)
	return arc4random_buf(buf, n);
#else
	unsigned char *b = buf;

#if defined(EVENT__HAVE_ARC4RANDOM_BUF)
	/* OSX 10.7 introducd arc4random_buf, so if you build your program
	 * there, you'll get surprised when older versions of OSX fail to run.
	 * To solve this, we can check whether the function pointer is set,
	 * and fall back otherwise.  (OSX does this using some linker
	 * trickery.)
	 */
	if (arc4random_buf != NULL) {
		return arc4random_buf(buf, n);
	}
#endif
	/* Make sure that we start out with b at a 4-byte alignment; plenty
	 * of CPUs care about this for 32-bit access. */
	if (n >= 4 && ((ev_uintptr_t)b) & 3) {
		ev_uint32_t u = arc4random();
		int n_bytes = 4 - (((ev_uintptr_t)b) & 3);
		memcpy(b, &u, n_bytes);
		b += n_bytes;
		n -= n_bytes;
	}
	while (n >= 4) {
		*(ev_uint32_t*)b = arc4random();
		b += 4;
		n -= 4;
	}
	if (n) {
		ev_uint32_t u = arc4random();
		memcpy(b, &u, n);
	}
#endif
}

void
evutil_secure_rng_add_bytes(const char *buf, size_t n)
{
	arc4random_addrandom((unsigned char*)buf,
	    n>(size_t)INT_MAX ? INT_MAX : (int)n);
}

#else /* Not EVENT__HAVE_ARC4RANDOM */

/*
 * The system does not provide arc4random, so we use our own
 * implementation.
 *
 * The global_rng.state will be auto initialised and stired by the
 * first evutil_secure_rng_* call
 *
 * N.B. evthread_use_pthreads() must be called prior to using
 * global_rng in multithreaded code.
 *
 */

static struct evutil_secure_rng global_rng;

#ifndef EVENT__DISABLE_THREAD_SUPPORT
int
evutil_secure_rng_global_setup_locks_(const int enable_locks)
{
	EVTHREAD_SETUP_GLOBAL_LOCK(global_rng.lock, 0);
	return 0;
}
#endif

void
evutil_free_secure_rng_globals_(void)
{
#ifndef EVENT__DISABLE_THREAD_SUPPORT
	if (global_rng.lock) {
		EVTHREAD_FREE_LOCK(global_rng.lock, 0);
		global_rng.lock = NULL;
	}
#endif
}

int
evutil_secure_rng_init(void)
{
	return evutil_secure_rng_init_r(&global_rng);
}

void
evutil_secure_rng_get_bytes(void *buf, size_t n)
{
	evutil_secure_rng_get_bytes_r(&global_rng, buf, n);
}

void
evutil_secure_rng_add_bytes(const char *buf, size_t n)
{
	evutil_secure_rng_add_bytes_r(&global_rng, buf, n);
}

#endif /* EVENT__HAVE_ARC4RANDOM */
