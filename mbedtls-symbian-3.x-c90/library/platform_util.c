/*
 * Common and shared functions used by multiple modules in the Mbed TLS
 * library.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Ensure gmtime_r is available even with -std=c99; must be defined before
 * mbedtls_config.h, which pulls in glibc's features.h. Harmless on other platforms
 * except OpenBSD, where it stops us accessing explicit_bzero.
 */
#if !defined(_POSIX_C_SOURCE) && !defined(__OpenBSD__)
#define _POSIX_C_SOURCE 200112L
#endif

#if !defined(_GNU_SOURCE)
/* Clang requires this to get support for explicit_bzero */
#define _GNU_SOURCE
#endif

#include "common.h"

#include "mbedtls/platform_util.h"
#include "mbedtls/platform.h"
#include "mbedtls/threading.h"

#include <stddef.h>

#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1 /* Ask for the C11 gmtime_s() and memset_s() if available */
#endif
#include <string.h>

#if defined(_WIN32) && !defined(__SYMBIAN32__)
#include <windows.h>
#endif

// Detect platforms known to support explicit_bzero()
#if defined(__GLIBC__) && (__GLIBC__ >= 2) && (__GLIBC_MINOR__ >= 25)
#define MBEDTLS_PLATFORM_HAS_EXPLICIT_BZERO 1
#elif (defined(__FreeBSD__) && (__FreeBSD_version >= 1100037)) || defined(__OpenBSD__)
#define MBEDTLS_PLATFORM_HAS_EXPLICIT_BZERO 1
#endif

#if !defined(MBEDTLS_PLATFORM_ZEROIZE_ALT)

#undef HAVE_MEMORY_SANITIZER
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#define HAVE_MEMORY_SANITIZER
#endif
#endif

/*
 * Where possible, we try to detect the presence of a platform-provided
 * secure memset, such as explicit_bzero(), that is safe against being optimized
 * out, and use that.
 *
 * For other platforms, we provide an implementation that aims not to be
 * optimized out by the compiler.
 *
 * This implementation for mbedtls_platform_zeroize() was inspired from Colin
 * Percival's blog article at:
 *
 * http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
 *
 * It uses a volatile function pointer to the standard memset(). Because the
 * pointer is volatile the compiler expects it to change at
 * any time and will not optimize out the call that could potentially perform
 * other operations on the input buffer instead of just setting it to 0.
 * Nevertheless, as pointed out by davidtgoldblatt on Hacker News
 * (refer to http://www.daemonology.net/blog/2014-09-05-erratum.html for
 * details), optimizations of the following form are still possible:
 *
 * if (memset_func != memset)
 *     memset_func(buf, 0, len);
 *
 * Note that it is extremely difficult to guarantee that
 * the memset() call will not be optimized out by aggressive compilers
 * in a portable way. For this reason, Mbed TLS also provides the configuration
 * option MBEDTLS_PLATFORM_ZEROIZE_ALT, which allows users to configure
 * mbedtls_platform_zeroize() to use a suitable implementation for their
 * platform and needs.
 */
//SYMBIAN ONLY: Elf2e32 doesn't support function imports from external libraries.
//#if !defined(MBEDTLS_PLATFORM_HAS_EXPLICIT_BZERO) && !defined(__STDC_LIB_EXT1__) //&& !defined(_WIN32)
//static void *(*const volatile memset_func)(void *, int, size_t) = memset;
//#endif

EXPORT_C void mbedtls_platform_zeroize(void *buf, size_t len)
{
    MBEDTLS_INTERNAL_VALIDATE(len == 0 || buf != NULL);

    if (len > 0) {
#if defined(MBEDTLS_PLATFORM_HAS_EXPLICIT_BZERO)
        explicit_bzero(buf, len);
#if defined(HAVE_MEMORY_SANITIZER)
        /* You'd think that Msan would recognize explicit_bzero() as
         * equivalent to bzero(), but it actually doesn't on several
         * platforms, including Linux (Ubuntu 20.04).
         * https://github.com/google/sanitizers/issues/1507
         * https://github.com/openssh/openssh-portable/commit/74433a19bb6f4cef607680fa4d1d7d81ca3826aa
         */
        __msan_unpoison(buf, len);
#endif
#elif defined(__STDC_LIB_EXT1__)
        memset_s(buf, len, 0, len);
//#elif defined(_WIN32)
//        SecureZeroMemory(buf, len);
#else
        memset(buf, 0, len);
#endif
    }
}
#endif /* MBEDTLS_PLATFORM_ZEROIZE_ALT */

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)
#include <time.h>
#if !defined(_WIN32) && (defined(unix) || \
    defined(__unix) || defined(__unix__) || (defined(__APPLE__) && \
    defined(__MACH__)))
#include <unistd.h>
#endif /* !_WIN32 && (unix || __unix || __unix__ ||
        * (__APPLE__ && __MACH__)) */

#if !((defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L) ||     \
    (defined(_POSIX_THREAD_SAFE_FUNCTIONS) &&                     \
    _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L))
/*
 * This is a convenience shorthand macro to avoid checking the long
 * preprocessor conditions above. Ideally, we could expose this macro in
 * platform_util.h and simply use it in platform_util.c, threading.c and
 * threading.h. However, this macro is not part of the Mbed TLS public API, so
 * we keep it private by only defining it in this file
 */
#if !(defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)) || \
    (defined(__MINGW32__) && !defined(__MINGW64_VERSION_MAJOR))
#define PLATFORM_UTIL_USE_GMTIME
#endif

#endif /* !( ( defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L ) || \
             ( defined(_POSIX_THREAD_SAFE_FUNCTIONS ) && \
                _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L ) ) */

EXPORT_C struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt,
                                     struct tm *tm_buf)
{
#if defined(_WIN32) && !defined(PLATFORM_UTIL_USE_GMTIME)
#if defined(__STDC_LIB_EXT1__)
    return (gmtime_s(tt, tm_buf) == 0) ? NULL : tm_buf;
#else
    /* MSVC and mingw64 argument order and return value are inconsistent with the C11 standard */
    return (gmtime_s(tm_buf, tt) == 0) ? tm_buf : NULL;
#endif
#elif !defined(PLATFORM_UTIL_USE_GMTIME)
    return gmtime_r(tt, tm_buf);
#else
    struct tm *lt;

#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_lock(&mbedtls_threading_gmtime_mutex) != 0) {
        return NULL;
    }
#endif /* MBEDTLS_THREADING_C */

    lt = gmtime(tt);

    if (lt != NULL) {
        memcpy(tm_buf, lt, sizeof(struct tm));
    }

#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_unlock(&mbedtls_threading_gmtime_mutex) != 0) {
        return NULL;
    }
#endif /* MBEDTLS_THREADING_C */

    return (lt == NULL) ? NULL : tm_buf;
#endif /* _WIN32 && !EFIX64 && !EFI32 */
}
#endif /* MBEDTLS_HAVE_TIME_DATE && MBEDTLS_PLATFORM_GMTIME_R_ALT */

#if defined(MBEDTLS_TEST_HOOKS)
void (*mbedtls_test_hook_test_fail)(const char *, int, const char *);
#endif /* MBEDTLS_TEST_HOOKS */

/*
 * Provide external definitions of some inline functions so that the compiler
 * has the option to not inline them
 */
//extern inline void mbedtls_xor(unsigned char *r,
//                               const unsigned char *a,
//                               const unsigned char *b,
//                               size_t n);
//
//extern inline uint16_t mbedtls_get_unaligned_uint16(const void *p);
//
//extern inline void mbedtls_put_unaligned_uint16(void *p, uint16_t x);
//
//extern inline uint32_t mbedtls_get_unaligned_uint32(const void *p);
//
//extern inline void mbedtls_put_unaligned_uint32(void *p, uint32_t x);
//
//extern inline uint64_t mbedtls_get_unaligned_uint64(const void *p);
//
//extern inline void mbedtls_put_unaligned_uint64(void *p, uint64_t x);

void mbedtls_xor(unsigned char *r, const unsigned char *a, const unsigned char *b, size_t n)
{
    size_t i = 0;
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS)
    for (; (i + 4) <= n; i += 4) {
        uint32_t x = mbedtls_get_unaligned_uint32(a + i) ^ mbedtls_get_unaligned_uint32(b + i);
        mbedtls_put_unaligned_uint32(r + i, x);
    }
#endif
    for (; i < n; i++) {
        r[i] = a[i] ^ b[i];
    }
}

uint16_t mbedtls_get_unaligned_uint16(const void *p)
{
    uint16_t r;
    memcpy(&r, p, sizeof(r));
    return r;
}

/**
 * Write the unsigned 16 bits integer to the given address, which need not
 * be aligned.
 *
 * \param   p pointer to 2 bytes of data
 * \param   x data to write
 */
void mbedtls_put_unaligned_uint16(void *p, uint16_t x)
{
    memcpy(p, &x, sizeof(x));
}

/**
 * Read the unsigned 32 bits integer from the given address, which need not
 * be aligned.
 *
 * \param   p pointer to 4 bytes of data
 * \return  Data at the given address
 */
uint32_t mbedtls_get_unaligned_uint32(const void *p)
{
    uint32_t r;
    memcpy(&r, p, sizeof(r));
    return r;
}

/**
 * Write the unsigned 32 bits integer to the given address, which need not
 * be aligned.
 *
 * \param   p pointer to 4 bytes of data
 * \param   x data to write
 */
void mbedtls_put_unaligned_uint32(void *p, uint32_t x)
{
    memcpy(p, &x, sizeof(x));
}

/**
 * Read the unsigned 64 bits integer from the given address, which need not
 * be aligned.
 *
 * \param   p pointer to 8 bytes of data
 * \return  Data at the given address
 */
uint64_t mbedtls_get_unaligned_uint64(const void *p)
{
    uint64_t r;
    memcpy(&r, p, sizeof(r));
    return r;
}

/**
 * Write the unsigned 64 bits integer to the given address, which need not
 * be aligned.
 *
 * \param   p pointer to 8 bytes of data
 * \param   x data to write
 */
void mbedtls_put_unaligned_uint64(void *p, uint64_t x)
{
    memcpy(p, &x, sizeof(x));
}

uint16_t mbedtls_bswap16(uint16_t x)
{
    return
        (x & 0x00ff) << 8 |
        (x & 0xff00) >> 8;
}

uint32_t mbedtls_bswap32(uint32_t x)
{
    return
        (x & 0x000000ff) << 24 |
        (x & 0x0000ff00) <<  8 |
        (x & 0x00ff0000) >>  8 |
        (x & 0xff000000) >> 24;
}

uint64_t mbedtls_bswap64(uint64_t x)
{
    return
        (x & 0x00000000000000ffULL) << 56 |
        (x & 0x000000000000ff00ULL) << 40 |
        (x & 0x0000000000ff0000ULL) << 24 |
        (x & 0x00000000ff000000ULL) <<  8 |
        (x & 0x000000ff00000000ULL) >>  8 |
        (x & 0x0000ff0000000000ULL) >> 24 |
        (x & 0x00ff000000000000ULL) >> 40 |
        (x & 0xff00000000000000ULL) >> 56;
}
