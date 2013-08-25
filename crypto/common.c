/* Copyright (c) 2013 Cameron Harper
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * */
#ifndef COMMON_C
#define COMMON_C

#include <stdint.h>

#if !defined(NULL)
#define NULL 0
#endif

#ifndef __WORD_SIZE
#define __WORD_SIZE 1
#endif

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1
#endif
#if __WORD_SIZE == 1
#undef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 0
#endif

#if __WORD_SIZE == 1
typedef uint8_t __word_t;
#elif __WORD_SIZE == 2
typedef uint16_t __word_t;
#elif __WORD_SIZE == 4
typedef uint32_t __word_t;
#elif __WORD_SIZE == 8
typedef uint64_t __word_t;
#else
#error "unknown word size"
#endif

#ifdef __USE_STRING

#include <string.h>

#define MEMCPY memcpy
#define MEMSET memset
#define MEMCMP memcmp

#else

/* local memcpy */
inline static void __memcpy(void *s1, const void *s2, uint8_t n)
{
    uint8_t *out = (uint8_t *)s1;
    const uint8_t *in = (uint8_t *)s2;

    while(n--)
        *out++ = *in++;
}

/* local memset */
inline static void __memset(void *s, const uint8_t c, uint8_t n)
{
    uint8_t *out = (uint8_t *)s;
    
    while(n--)
        *out++ = c;
}

/* local memcmp (only indicates same or not same) */
inline static int __memcmp(const void *s1, const void *s2, uint8_t n)
{
    const uint8_t *in1 = (uint8_t *)s1;
    const uint8_t *in2 = (uint8_t *)s2;
    
    while(n--){
        if(*in1++ != *in2++)
            return -1;
    }

    return 0;
}

#define MEMCPY __memcpy
#define MEMSET __memset
#define MEMCMP __memcmp

#endif

/* block size but in words */
#define WORD_BLOCK  (AES_BLOCK_SIZE / sizeof(__word_t))

/* xor acc with mask; word aligned 128bit values */
inline static void xor128(__word_t *acc, __word_t *mask)
{
    int i;
    
    for(i=0; i < WORD_BLOCK; i++)
        acc[i] ^= mask[i];
}

/* copy from to to; word aligned 128bit values */
inline static void copy128(__word_t *to, __word_t *from)
{
    int i;
    
    for(i=0; i < WORD_BLOCK; i++)
        to[i] = from[i];
}


#endif
