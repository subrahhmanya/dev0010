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

static const uint8_t counter_init[] =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

inline static __word_t swapw(__word_t w)
{
#if __WORD_SIZE == 1    
    return w;
#elif __WORD_SIZE == 2
    return ((w >> 8) & 0xff) | ((w << 8) & 0xff00);    
#elif __WORD_SIZE == 4
    return  ((w << 24) & 0xff000000)    |
            ((w <<  8) & 0xff0000)      |
            ((w >>  8) & 0xff00)        |
            ((w >> 24) & 0xff);
#else
    return  ((w << 56) & 0xff00000000000000)    |
            ((w << 40) & 0xff000000000000)      |
            ((w << 24) & 0xff0000000000)        |
            ((w <<  8) & 0xff00000000)          |
            ((w >>  8) & 0xff000000)            |
            ((w >> 24) & 0xff0000)              |
            ((w >> 40) & 0xff00)                |
            ((w >> 56) & 0xff);            
#endif
}

#if __LITTLE_ENDIAN

#define R   0xe1

#if __WORD_SIZE == 1
#define TST_MSB 0x01
#define LSB 0x80
#elif __WORD_SIZE == 2
#define TST_MSB 0x0100
#define LSB 0x8000
#elif __WORD_SIZE == 4
#define TST_MSB 0x01000000
#define LSB 0x80000000
#else
#define TST_MSB 0x0100000000000000
#define LSB 0x8000000000000000
#endif

#else

#define TST_MSB 0x01

#if __WORD_SIZE == 1
#define R 0xe1
#define LSB 0x80
#elif __WORD_SIZE == 2
#define R 0xe100
#define LSB 0x8000
#elif __WORD_SIZE == 4
#define R 0xe1000000
#define LSB 0x80000000
#else
#define R 0xe100000000000000
#define LSB 0x8000000000000000
#endif

#endif

/* Table-less galois multiplication in a 128bit field
 *
 * XX = XX . YY
 *
 * algorithm:
 * 
 * Z <- 0, V <- X
 * for i to 127 do
 *   if Yi == 1 then
 *     Z <- Z XOR V
 *   end if
 *   if V127 = 0 then
 *     V <- rightshift(V)
 *   else
 *     V <- rightshit(V) XOR R
 *   end if
 * end for
 * return Z
 * 
 * */
static void galois_mul128(__word_t *XX, const __word_t *YY)
{
    __word_t ZZ[WORD_BLOCK];
    __word_t VV[WORD_BLOCK];
    __word_t y, t, tt, vmsb, carry;

    int i, j, k;
    
    xor128(ZZ, ZZ);
    copy128(VV, XX);

    for(i=0; i < WORD_BLOCK; i++){

        y = YY[i];

        for(j=0; j < (sizeof(y)*8); j++){

            if(y & LSB)
                xor128(ZZ, VV);
            
            /* MSbit of vector */
            vmsb = VV[WORD_BLOCK-1] & TST_MSB;
            carry = 0x0;
            
            /* rightshift vector */
            for(k=0; k < WORD_BLOCK; k++){

                t = VV[k];        
#if __LITTLE_ENDIAN
                t = swapw(t);        
#endif
                tt = t;
                tt >>= 1;
                tt |= carry;
#if __LITTLE_ENDIAN
                tt = swapw(tt);        
#endif        
                carry = (t & 0x1)?LSB:0x0;
                VV[k] = tt;
            }

            if(vmsb)
                VV[0] ^= R;                
            
            y <<= 1;            
        }
    }

    copy128(XX, ZZ);
}

/* Increment the counter */
static void increment(uint8_t *counter)
{
    if(++(counter[AES_BLOCK_SIZE-1]))
        return;
    if(++(counter[AES_BLOCK_SIZE-2]))
        return;
    if(++(counter[AES_BLOCK_SIZE-3]))
        return;
    counter[AES_BLOCK_SIZE-4]++;        
}


/* Internal GCM
 *
 * mode:
 * 0: Encipher Mode
 * 1: Decipher Mode
 * 2: GHASH mode
 *
 * *aes AES key schedule context
 * *IV initialisation vector
 * IV_size size of *IV in bytes
 * mode function mode
 * *out cipher output buffer
 * *in cipher input buffer
 * size size of *in or *out in bytes
 * *aad additional non-ciphered data for authentication
 * aad_size size of *aad
 * *XX GMAC output
 * 
 * */
static void gcm(    

    const aes_ctxt *aes,

    const uint8_t *IV,
    uint32_t IV_size,

    int mode,

    uint8_t *out, const uint8_t *in, uint32_t size,
    const uint8_t *aad, uint32_t aad_size,

    __word_t *XX)     
{
    __word_t icount[WORD_BLOCK];
    __word_t tcount[WORD_BLOCK];
    __word_t count[WORD_BLOCK];

    __word_t part[WORD_BLOCK];
    __word_t HH[WORD_BLOCK];
    uint8_t sz[AES_BLOCK_SIZE];

    /* only implementation error within this file would cause this */
    if(mode > 2)
        return;

    /* generate the hash subkey */
    xor128(HH, HH);
    aes_encr(aes, (uint8_t *)HH);
#if __LITTLE_ENDIAN
    int i;
    for(i=0; i < WORD_BLOCK; i++)
        HH[i] = swapw(HH[i]);
#endif

    /* GHASH mode does not need an IV */
    if(mode != 2){

        if(IV_size == GCM_IV_SIZE){

            MEMCPY(icount, counter_init, sizeof(icount));
            MEMCPY(icount, IV, GCM_IV_SIZE);
        }
        /* GHASH(H, {}, IV) */
        else{

            gcm(aes, NULL, 0, 2, NULL, IV, IV_size, NULL, 0, icount);            
        }

        copy128(count, icount);
    }

    /* create zero block */
    xor128(XX, XX);

    /* [aad_size]64 || [size]64 */
    sz[0] = 0x0;
    sz[1] = 0x0;
    sz[2] = 0x0;
    sz[3] = aad_size >> (32-3); /* (x8 bits) */   
    sz[4] = aad_size >> (24-3);
    sz[5] = aad_size >> (16-3); 
    sz[6] = aad_size >> (8-3);
    sz[7] = aad_size << 3;
    sz[8] = 0x0;
    sz[9] = 0x0;
    sz[10] = 0x0;
    sz[11] = size >> (32-3);
    sz[12] = size >> (24-3);
    sz[13] = size >> (16-3);
    sz[14] = size >> (8-3);
    sz[15] = size << 3; 
    
    if(aad_size){

        while(1){

            xor128(part, part);
            MEMCPY(part, aad, ((aad_size < sizeof(part))?aad_size:sizeof(part)));

            xor128(XX, part);
            galois_mul128(XX, HH);

            if(aad_size <= sizeof(part))
                break;

            aad += sizeof(part);
            aad_size -= sizeof(part);
        }
    }
        
    if(size){

        while(1){

            if(mode != 2){
                increment((uint8_t *)count);
                copy128(tcount, count);
                aes_encr(aes, (uint8_t *)tcount);  
            }

            xor128(part, part);
            MEMCPY(part, in, ((size < sizeof(part))?size:sizeof(part)));
            
            /* deciphering or hashing */
            if((mode == 1) || (mode == 2)){

                xor128(XX, part);
                galois_mul128(XX, HH);
            }

            /* deciphering or enciphering */
            if(mode != 2){
                xor128(part, tcount);
                MEMCPY(out, part, (size < sizeof(part))?size:sizeof(part));
            }

            /* enciphering */
            if(mode == 0){

                /* zero garbage in unused block portion */
                if(size < sizeof(part)){
                    MEMSET(((uint8_t *)part) + size, 0x0, sizeof(part) - size);
                }

                xor128(XX, part);
                galois_mul128(XX, HH);
            }
            
            if(size <= sizeof(part))
                break;

            in += sizeof(part);
            out += sizeof(part);
            size -= sizeof(part);
        }
    }

    /* GHASH output with size */
    xor128(XX, (__word_t *)sz);
    galois_mul128(XX, HH);

    /* XOR initial counter with GHASH output */
    if(mode != 2){
        aes_encr(aes, (uint8_t *)icount);  
        xor128(XX, icount);
    }

    xor128(HH, HH);    
}
    
void aes_gcm_encipher(

    const aes_ctxt *aes,

    const uint8_t *IV,
    uint32_t IV_size,

    uint8_t *out,
    const uint8_t *in,
    uint32_t size,

    const uint8_t *aad,
    uint32_t aad_size,

    uint8_t *T,
    int T_size)
{
    __word_t XX[WORD_BLOCK];

    gcm(aes, IV, IV_size, 0, out, in, size, aad, aad_size, XX);

    if(T){
        MEMCPY(T, XX, (T_size < GCM_TAG_SIZE)?T_size:GCM_TAG_SIZE);
    }
}

int aes_gcm_decipher(

    const aes_ctxt *aes,
    
    const uint8_t *IV,
    uint32_t IV_size,

    uint8_t *out,
    const uint8_t *in,
    uint32_t size,

    const uint8_t *aad,
    uint32_t aad_size,

    const uint8_t *T,
    int T_size)
{
    __word_t XX[WORD_BLOCK];

    if(T_size > GCM_TAG_SIZE)
        return -1;

    gcm(aes, IV, IV_size, 1, out, in, size, aad, aad_size, XX);

    if(MEMCMP(XX, T, T_size))
        return -1;

    return 0;
}

int aes_gcm_init(aes_ctxt *aes, const uint8_t *k, int k_size)
{
    return aes_init(aes, k, k_size);
}
