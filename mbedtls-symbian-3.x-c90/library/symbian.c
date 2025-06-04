#include "common.h"

#ifdef __SYMBIAN32__

#include <unistd.h>

extern int __aeabi_uidivmod(unsigned int a, unsigned int b);
extern int __aeabi_idivmod(int a, int b);
int __aeabi_idiv(int a, int b)
{
	return __aeabi_idivmod(a, b);
}

int __aeabi_uidiv(unsigned int a, unsigned int b)
{
	return __aeabi_uidivmod(a, b);
}

#endif

#ifdef MBEDTLS_ENTROPY_HARDWARE_ALT

#include <stdlib.h>

EXPORT_C int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    uint32_t rnd = 0, i;
    for (i = 0; i < len; ++i) {
        if (i % 4 == 0)
            rnd = rand();
        output[i] = rnd;
        rnd >>= 8;
    }
    *olen += len;
    return 0;
}

#endif

#if defined(ESTLIB)
#ifndef STB_SPRINTF_IMPLEMENTATION
#define STB_SPRINTF_IMPLEMENTATION
#include <stb_sprintf.h>
#endif
#include <stdarg.h>

EXPORT_C int vsnprintf(char *buf, size_t  n, char const *fmt, va_list va)
{
	return stbsp_vsnprintf(buf, (int)n, fmt, va);
}

EXPORT_C int snprintf(char *s, size_t n, const char* fmt, ...)
{
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = stbsp_vsnprintf(s, (int)n, fmt, ap);
    va_end(ap);
    return ret;
}

#endif
