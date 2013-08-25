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

#define WRAP_BLOCK (AES_BLOCK_SIZE >> 1)

static const unsigned char default_iv[] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
};

int aes_wrap_init(aes_ctxt *aes, const uint8_t *k, int k_size)
{
    return aes_init(aes, k, k_size);
}

int aes_wrap_encipher(aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint16_t in_size, const uint8_t *iv)
{
    uint8_t B[AES_BLOCK_SIZE], *R;
    uint16_t i, j, t = 1;
    
    if((in_size % 8) || (in_size < 8))
        return -1;

    if(!iv)
        iv = default_iv;

    for(i=in_size; i; i-=8){

        MEMCPY(out + i, in + i - 8, 8);        
    }

    MEMCPY(B, iv, 8);
    
    for(j=0; j < 6; j++){

        R = out + 8;
        
        for(i=0; i < (in_size >> 3); i++){

            MEMCPY(B + 8, R, 8);

            aes_encr(aes, B);

            B[7] ^= t;
            B[6] ^= (t >> 8);
            t++;

            MEMCPY(R, B + 8, 8);
            
            R += 8;            
        }
    }

    MEMCPY(out, B, 8);
    return 0;
}

int aes_wrap_decipher(aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint32_t in_size, const uint8_t *iv)
{
    uint8_t B[AES_BLOCK_SIZE], *R;
    uint16_t i, j, t, n = (in_size >> 3) - 1;
    
    if((in_size % 8) || (in_size < 16))
        return -1;

    if(!iv)
        iv = default_iv;

    MEMCPY(B, in, 8);

    for(i=8; i < in_size; i+=8){

        MEMCPY(out + i - 8, in + i, 8);        
    }

    t =  6 * n;

    for(j=0; j < 6; j++){

        R = out + in_size - 16;
    
        for(i=0; i < n; i++){

            MEMCPY(B + 8, R, 8);

            B[7] ^= t;
            B[6] ^= (t >> 8);
            t--;

            aes_decr(aes, B);

            MEMCPY(R, B + 8, 8);
            
            R -= 8;            
        }
    }

    if(MEMCMP(B, iv, 8))
        return -1;
    else
        return 0;
}

