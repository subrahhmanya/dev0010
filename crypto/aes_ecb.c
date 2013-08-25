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

#include "aes.h"
#include "common.c"

int aes_ecb_init(aes_ctxt *aes, const uint8_t *k, int k_size)
{
    return aes_init(aes, k, k_size);
}

void aes_ecb_encipher(aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint32_t size)
{
    uint8_t s[AES_BLOCK_SIZE];

    while(1){

        xor128((__word_t *)s, (__word_t *)s);

        MEMCPY(s, in, (size > sizeof(s))?sizeof(s):size);
        aes_encr(aes, s);
        MEMCPY(out, s, (size > sizeof(s))?sizeof(s):size);
    
        if(size <= sizeof(s))
            return;

        size -= sizeof(s);
        in += sizeof(s);
        out += sizeof(s);
    }
}

void aes_ecb_decipher(aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint32_t size)
{
    uint8_t s[AES_BLOCK_SIZE];

    while(1){

        xor128((__word_t *)s, (__word_t *)s);

        MEMCPY(s, in, (size > sizeof(s))?sizeof(s):size);
        aes_decr(aes, s);
        MEMCPY(out, s, (size > sizeof(s))?sizeof(s):size);
    
        if(size <= sizeof(s))
            return;

        size -= sizeof(s);
        in += sizeof(s);
        out += sizeof(s);
    }
}
