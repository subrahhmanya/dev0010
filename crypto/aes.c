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

#ifndef AES_CONST
#define AES_CONST
#endif

#ifndef SBOX
    #define SBOX(C) sbox[(C)]
#endif
#ifndef RSBOX
    #define RSBOX(C) rsbox[(C)]
#endif
#ifndef RCON
    #define RCON(C) rcon[(C)]
#endif

#define KEY(R, C) aes->k[p + R + (C<<2) ]
#define STATE(R, C) s[R + (C<<2) ]
#define GALOIS_MUL2(B) (((B) & 0x80) ? (((B) << 1) ^ 0x1b ) : ((B) << 1))

#if AES_ENCR

static const uint8_t sbox[] AES_CONST = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const unsigned char rcon[] AES_CONST = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

int aes_init(aes_ctxt *aes, const uint8_t *k, int k_size)
{
    uint16_t i, p, j, b;
    uint8_t swap, *key;
    
    switch(k_size){
    case 16:
        aes->r = 10;
        b = 176;
        break;
    case 24:
        aes->r = 12;
        b = 208;
        break;
    case 32:
        aes->r = 14;
        b = 240;
        break;         
    default:
        return -1;
    }
    
    MEMCPY(aes->k, k, k_size);
    key = aes->k; 

    p = k_size;

    for(i = 1; p < b; i++, p += 4){

        swap = key[p - 4];
        key[p + 0] = SBOX( key[p - 3] ) ^ key[p - k_size] ^ RCON(i);
        key[p + 1] = SBOX( key[p - 2] ) ^ key[p - k_size + 1];
        key[p + 2] = SBOX( key[p - 1] ) ^ key[p - k_size + 2];
        key[p + 3] = SBOX( swap       ) ^ key[p - k_size + 3];

        for(j=0; j < 12; j++, p++)
            key[p + 4] = key[p] ^ key[p - k_size + 4];

        if((p + 4) == b)
            break;

        if(k_size == 24){

            for(j=0; j < 8; j++, p++)
                key[p + 4] = key[p] ^ key[p - k_size + 4];
        }
        else if(k_size == 32){

            for(j=0; j < 4; j++, p++)
                key[p + 4] = sbox[ key[p] ] ^ key[p - k_size + 4];

            for(j=0; j < 12; j++, p++)
                key[p + 4] = key[p] ^ key[p - k_size + 4];
        }

    }

    return 0;
}

void aes_encr(const aes_ctxt *aes, uint8_t *s)
{
    int r, i;
    uint16_t p;
    uint8_t a, b, c, d;

    /* add round key, sbox and shiftrows */
    for(r = 0, p = 0; r < aes->r; r++, p += 16){

        /* add round key, sbox, left shift row */

        /* row 1 */
        STATE(0, 0) = SBOX( STATE(0, 0) ^ KEY(0,0) );
        STATE(0, 1) = SBOX( STATE(0, 1) ^ KEY(0,1) );
        STATE(0, 2) = SBOX( STATE(0, 2) ^ KEY(0,2) );
        STATE(0, 3) = SBOX( STATE(0, 3) ^ KEY(0,3) );

        /* row 2, left shift 1 */
        a = SBOX( STATE(1, 0) ^ KEY(1,0) );
        STATE(1, 0) = SBOX( STATE(1, 1) ^ KEY(1,1) );
        STATE(1, 1) = SBOX( STATE(1, 2) ^ KEY(1,2) );
        STATE(1, 2) = SBOX( STATE(1, 3) ^ KEY(1,3) );
        STATE(1, 3) = a;

        /* row 3, left shift 2 */
        a = SBOX( STATE(2, 0) ^ KEY(2, 0) );
        b = SBOX( STATE(2, 1) ^ KEY(2, 1) );
        STATE(2, 0) = SBOX( STATE(2, 2) ^ KEY(2, 2) );
        STATE(2, 1) = SBOX( STATE(2, 3) ^ KEY(2, 3) );
        STATE(2, 2) = a;
        STATE(2, 3) = b;

        /* row 4, left shift 3 */
        a = SBOX( STATE(3, 3) ^ KEY(3, 3) );
        STATE(3, 3) = SBOX( STATE(3, 2) ^ KEY(3, 2) );
        STATE(3, 2) = SBOX( STATE(3, 1) ^ KEY(3, 1) );
        STATE(3, 1) = SBOX( STATE(3, 0) ^ KEY(3, 0) );
        STATE(3, 0) = a;

        if((r+1) == aes->r){

            p += 16;

            /* final add round key */
            for(i=0; i < 16; i++)
                s[i] ^= aes->k[p+i];
            
            return;
        }
         
        /* mix columns */
        for(i=0; i < 16; i += 4){

            a = s[i + 0];
            b = s[i + 1];
            c = s[i + 2];
            d = s[i + 3];

            /* 2a + 3b + 1c + 1d 
             * 1a + 2b + 3c + 1d
             * 1a + 1b + 2c + 3d
             * 3a + 1b + 1c + 2d
             *
             * */
            s[i + 0] ^= (a ^ b ^ c ^ d) ^ GALOIS_MUL2( (a ^ b) );
            s[i + 1] ^= (a ^ b ^ c ^ d) ^ GALOIS_MUL2( (b ^ c) );
            s[i + 2] ^= (a ^ b ^ c ^ d) ^ GALOIS_MUL2( (c ^ d) );
            s[i + 3] ^= (a ^ b ^ c ^ d) ^ GALOIS_MUL2( (d ^ a) );
        }
    }   
}

#endif


#ifdef AES_DECR

static const uint8_t rsbox[] AES_CONST = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

void aes_decr(const aes_ctxt *aes, uint8_t *s)
{
    int r, i;
    uint16_t p;
    uint8_t a, b, c, d, e, x, y;

    p = (((uint16_t)aes->r) << 4);
    r = aes->r;

    /* add round key */
    for(i=0; i < 16; i++)
        s[i] ^= aes->k[p+i];

    /* add round key, sbox and shiftrows */
    for(p -= 16; r; r--, p -= 16){

        if(r < aes->r){

            /* inverse mix columns */
            for(i=0; i < 16; i += 4){

                a = s[i + 0];
                b = s[i + 1];
                c = s[i + 2];
                d = s[i + 3];

                /* 2a + 2b + 2c + 2d */
                e = GALOIS_MUL2( (a ^ b ^ c ^ d) );

                /* 13a + 9b + 13c + 9d */
                x = GALOIS_MUL2( (e ^ a ^ c) );                
                x = (a ^ b ^ c ^ d) ^ GALOIS_MUL2( x );

                /* 9a + 13b + 9c + 13d */
                y = GALOIS_MUL2( (e ^ b ^ d) );                
                y = (a ^ b ^ c ^ d) ^ GALOIS_MUL2( y );
                
                
                /* 14a + 11b + 13c + 9d
                 * 9a + 14b + 11c + 13d
                 * 13a + 9b + 14c + 11d
                 * 11a + 13b + 9c + 14d
                 *
                 * */
                s[i + 0] ^= x ^ GALOIS_MUL2( (a ^ b) );
                s[i + 1] ^= y ^ GALOIS_MUL2( (b ^ c) );
                s[i + 2] ^= x ^ GALOIS_MUL2( (c ^ d) );
                s[i + 3] ^= y ^ GALOIS_MUL2( (d ^ a) );
            }
        }

        /* right shift row, reverse-sbox, add round key */

        /* row 1 */
        STATE(0, 0) = RSBOX( STATE(0, 0) ) ^ KEY(0,0);
        STATE(0, 1) = RSBOX( STATE(0, 1) ) ^ KEY(0,1);
        STATE(0, 2) = RSBOX( STATE(0, 2) ) ^ KEY(0,2);
        STATE(0, 3) = RSBOX( STATE(0, 3) ) ^ KEY(0,3);

        /* row 2, right shift 1 */
        a = RSBOX( STATE(1, 3) ) ^ KEY(1,0);
        STATE(1, 3) = RSBOX( STATE(1, 2) ) ^ KEY(1,3);
        STATE(1, 2) = RSBOX( STATE(1, 1) ) ^ KEY(1,2);
        STATE(1, 1) = RSBOX( STATE(1, 0) ) ^ KEY(1,1);
        STATE(1, 0) = a;

        /* row 3, right shift 2 */
        a = RSBOX( STATE(2, 0) ) ^ KEY(2, 2);
        b = RSBOX( STATE(2, 1) ) ^ KEY(2, 3);
        STATE(2, 0) = RSBOX( STATE(2, 2) ) ^ KEY(2, 0);
        STATE(2, 1) = RSBOX( STATE(2, 3) ) ^ KEY(2, 1);
        STATE(2, 2) = a;
        STATE(2, 3) = b;

        /* row 4, right shift 3 */
        a = RSBOX( STATE(3, 0) ) ^ KEY(3, 3) ;
        STATE(3, 0) = RSBOX( STATE(3, 1) ) ^ KEY(3, 0);
        STATE(3, 1) = RSBOX( STATE(3, 2) ) ^ KEY(3, 1);
        STATE(3, 2) = RSBOX( STATE(3, 3) ) ^ KEY(3, 2);
        STATE(3, 3) = a;
    }
}

#endif

#undef KEY
#undef STATE
#undef GALOIS_MUL2
