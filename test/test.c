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
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include <aes.h>

static void hex_to_string(FILE *log, char *hdr, const unsigned char *str, int size)
{
    int i;

    if(!log)
        return;

    fprintf(log, "%s", hdr);
    for(i=0; i < size; i++)
        fprintf(log, "%02X", *(str+i));

    fprintf(log, "\n");
    fflush(log);
}

static int string_to_hex(const char *input, uint8_t **output)
{
    size_t i;
    unsigned int v;

    if(strlen(input) & 0x1){
        fprintf(stderr, "string_to_hex() expecting an even number of characters to convert to hex\n");
        return -1;
    }

    if(!(*output = malloc(strlen(input)))){

        fprintf(stderr, "string_to_hex() malloc()\n");
        return -1;        
    }

    for(i=0; i < strlen(input); i+=2){
        sscanf(input+i, "%02x", &v);
        (*output)[(i>>1)] = v;
    }

    return (strlen(input)>>1);
}

int test__gcm(FILE *in)
{
    int ret;

    aes_ctxt aes;

    uint8_t *key = NULL;
    uint8_t *pt = NULL;
    uint8_t *ct = NULL;
    uint8_t *iv = NULL;
    uint8_t *aad = NULL;
    uint8_t *outbuf = NULL;
    uint8_t *tag = NULL;

    uint8_t tagbuf[16];
    
    int keylen;
    int ptlen = 0;
    int ctlen = 0;
    int tmpsize = 0;
    int aadlen = 0;
    int ivlen = 0;
    int taglen = 0;

    int state = 0;
    int count = 0;
    int fail = 0;

    char *line = NULL;
    size_t linesize = 0;

    tmpsize = 1024;
    char *tmp = malloc(tmpsize);

    while((ret = getline(&line, &linesize, in)) >= 0){

        if(tmpsize < linesize){

            tmpsize = linesize;
            tmp = realloc(tmp, tmpsize);
        }
    
        switch(state){
        case 0:

            free(key);
            free(pt);
            free(ct);
            free(iv);
            free(outbuf);
            free(aad);

            key = NULL; ct = NULL; pt = NULL; iv = NULL; outbuf = NULL; aad = NULL;

            if(sscanf(line, "Key = %s\n", tmp) == 1){

                if((ret = string_to_hex(tmp, &key)) < 0){
                    fail = -1;
                    goto abort;
                }

                keylen = ret;
            }
            else
                continue;

            state++;
            break;

        case 1:

            if(sscanf(line, "IV = %s\n", tmp) == 1){

                if((ret = string_to_hex(tmp, &iv)) < 0){
                    fail = -1;
                    goto abort;
                }

                ivlen = ret;
            }
            else{
                fprintf(stderr, "test__gcm() expecting IV\n");
                fail = -1;                
                goto abort;
            }

            state++;
            break;

        case 2:

            state++;

            if(sscanf(line, "PT = %s\n", tmp) == 1){

                if((ret = string_to_hex(tmp, &pt)) < 0){

                    goto abort;
                }

                ptlen = ret;
            }
            else{
                ptlen = 0;
                continue;
            }

            break;

        case 3:

            state++;

            if(sscanf(line, "AAD = %s\n", tmp) == 1){

                if((ret = string_to_hex(tmp, &aad)) < 0){

                    goto abort;
                }

                aadlen = ret;                
            }
            else{
                aadlen = 0;
                continue;
            }
            
            break;

        case 4:

            state++;

            if(sscanf(line, "CT = %s\n", tmp) == 1){

                if((ret = string_to_hex(tmp, &ct)) < 0){

                    goto abort;
                }

                ctlen = ret;                
            }
            else{
                ctlen = 0;
                continue;
            }

            break;

        case 5:

            if(sscanf(line, "Tag = %s\n", tmp) == 1){

                if((ret = string_to_hex(tmp, &tag)) < 0){

                    goto abort;
                }

                taglen = ret;                
            }
            else{
                fprintf(stderr, "test__gcm() expecting Tag\n");
                fail = -1;
                goto abort;
            }

            state++;
            
            if(aes_gcm_init(&aes, key, keylen)){

                fprintf(stderr, "test__gcm() keylen = %iB\n", keylen);
                fail = -1;
                goto abort;
            }

            count++;

            if(ptlen)
                outbuf = malloc(ptlen);
            else
                outbuf = NULL;
            
            aes_gcm_encipher(&aes, iv, ivlen, outbuf, pt, ptlen, aad, aadlen, tagbuf, sizeof(tagbuf));

            if(memcmp(outbuf, ct, ptlen) || memcmp(tagbuf, tag, taglen)){

                fprintf(stderr, "FAIL aes_gcm_encipher()\n");
                hex_to_string(stderr, "Key: ", key, keylen);
                hex_to_string(stderr, "IV: ", iv, ivlen);
                hex_to_string(stderr, "PT: ", pt, ptlen);
                hex_to_string(stderr, "CT: ", ct, ctlen);
                hex_to_string(stderr, "Tag: ", tag, taglen);
                hex_to_string(stderr, "CT output: ", outbuf, ctlen);
                hex_to_string(stderr, "Tag output: ", tagbuf, taglen);
                fprintf(stderr, "\n");

                fail++;
            }

            if(aes_gcm_decipher(&aes, iv, ivlen, outbuf, ct, ptlen, aad, aadlen, tagbuf, taglen) || 
                    memcmp(outbuf, pt, ptlen)){

                fprintf(stderr, "FAIL aes_gcm_decipher()\n");
                hex_to_string(stderr, "Key: ", key, keylen);
                hex_to_string(stderr, "IV: ", iv, ivlen);
                hex_to_string(stderr, "PT: ", pt, ptlen);
                hex_to_string(stderr, "CT: ", ct, ctlen);
                hex_to_string(stderr, "Tag: ", tag, taglen);
                hex_to_string(stderr, "CT output: ", outbuf, ctlen);
                hex_to_string(stderr, "Tag output: ", tagbuf, taglen);
                fprintf(stderr, "\n");

                fail++;
            }
            

            state = 0;
        }                 
    }

abort:

    free(key);
    free(pt);
    free(ct);
    free(iv);
    free(aad);
    free(outbuf);
    free(tag);

    free(line);
    free(tmp);

    return fail;    
}

int test__ecb(FILE *in)
{
    int ret;

    char *line = NULL;
    size_t linesize = 0;

    aes_ctxt aes;

    uint8_t *key = NULL;
    uint8_t *pt = NULL;
    uint8_t *ct = NULL;
    
    int keylen;
    int ptlen = 0;
    int ctlen = 0;
    int tmpsize = 0;

    int encrypt = 0;

    int state = 0;
    int count = 0;
    int fail = 0;

    tmpsize = 1024;
    char *tmp = malloc(tmpsize);
    
    while((ret = getline(&line, &linesize, in)) >= 0){

        if(tmpsize < linesize){

            tmpsize = linesize;
            tmp = realloc(tmp, tmpsize);
        }
    
        switch(state){
        case 0:

            free(key);
            free(pt);
            free(ct);

            key = NULL; ct = NULL; pt = NULL;

            if(sscanf(line, "KEY = %s\n", tmp) == 1){

                if((ret = string_to_hex(tmp, &key)) < 0){
                    fail = -1;
                    goto abort;
                }

                keylen = ret;
            }
            else
                continue;

            state++;
            break;

        case 1:

            if(sscanf(line, "PLAINTEXT = %s\n", tmp) == 1){

                if((ret = string_to_hex(tmp, &pt)) < 0){

                    goto abort;
                }

                ptlen = ret;
                encrypt = 1;
            }
            else if(sscanf(line, "CIPHERTEXT = %s\n", tmp) == 1){

                if((ret = string_to_hex(tmp, &ct)) < 0){
                    fail = -1;
                    goto abort;
                }

                ctlen = ret;
                encrypt = 0;
            }
            else{
                fail = -1;
                goto abort;
            }
                
            state++;
            break;

        case 2:
        
            if(sscanf(line, "PLAINTEXT = %s\n", tmp) == 1){

                if((ret = string_to_hex(tmp, &pt)) < 0){
                    fail = -1;
                    goto abort;
                }

                ptlen = ret;
            }
            else if(sscanf(line, "CIPHERTEXT = %s\n", tmp) == 1){

                if((ret = string_to_hex(tmp, &ct)) < 0){
                    fail = -1;
                    goto abort;
                }

                ctlen = ret;
            }
            else{
                fail = -1;
                goto abort;
            }

            if(aes_ecb_init(&aes, key, keylen)){

                fprintf(stderr, "aes_ecb_init() keylen = %iB\n", keylen);
                fail = -1;
                goto abort;
            }

            count++;

            if(encrypt){

                aes_ecb_encipher(&aes, (uint8_t *)line, pt, ptlen);

                if(memcmp(line, ct, ctlen)){

                    fprintf(stderr, "FAIL aes_ecb_encipher()\n");
                    hex_to_string(stderr, "key: ", key, keylen);
                    hex_to_string(stderr, "pt: ", pt, ptlen);
                    hex_to_string(stderr, "ct: ", ct, ctlen);                    
                    hex_to_string(stderr, "output: ", (uint8_t *)line, ctlen);
                    fprintf(stderr, "\n");

                    fail++;
                }
            }
            else{

                aes_ecb_decipher(&aes, (uint8_t *)line, ct, ctlen);

                if(memcmp(line, pt, ptlen)){

                    fprintf(stderr, "FAIL aes_ecb_decipher()\n");
                    hex_to_string(stderr, "key: ", key, keylen);
                    hex_to_string(stderr, "ct: ", ct, ctlen);
                    hex_to_string(stderr, "pt: ", pt, ptlen);
                    hex_to_string(stderr, "output: ", (uint8_t *)line, ctlen);
                    fprintf(stderr, "\n");

                    fail++;
                }
            }

            state = 0;

        }                 
    }

abort:

    free(line);
    free(tmp);
    free(ct);
    free(pt);
    free(key);

    return fail;    
}

int test__wrap(void)
{
    struct {

        int keklen;
        int inlen;
        int outlen;
        
        uint8_t iv[8];

        uint8_t kek[32];
        uint8_t in[32];
        uint8_t out[32+8];

    } nist[] = {

        /* 128bit KEK, 128bit key*/
        {
            16,
            16,
            24,

            {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6},

            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
            {0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5}
        },
        /* 192bit KEK, 128bit key*/
        {
            24,
            16,
            24,

            {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6},

            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
            {0x96, 0x77, 0x8B, 0x25, 0xAE, 0x6C, 0xA4, 0x35, 0xF9, 0x2B, 0x5B, 0x97, 0xC0, 0x50, 0xAE, 0xD2, 0x46, 0x8A, 0xB8, 0xA1, 0x7A, 0xD8, 0x4E, 0x5D}
        },
        /* 256bit KEK, 128bit key*/
        {
            32,
            16,
            24,

            {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6},

            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
            {0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2, 0x63, 0xE9, 0x77, 0x79, 0x05, 0x81, 0x8A, 0x2A, 0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7}
        },
        /* 192bit KEK, 192bit key*/
        {
            24,
            24,
            32,

            {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6},

            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
            {0x03, 0x1D, 0x33, 0x26, 0x4E, 0x15, 0xD3, 0x32, 0x68, 0xF2, 0x4E, 0xC2, 0x60, 0x74, 0x3E, 0xDC, 0xE1, 0xC6, 0xC7, 0xDD, 0xEE, 0x72, 0x5A, 0x93, 0x6B, 0xA8, 0x14, 0x91, 0x5C, 0x67, 0x62, 0xD2}
        },
        /* 256bit KEK, 192bit key*/
        {
            32,
            24,
            32,

            {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6},

            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
            {0xA8, 0xF9, 0xBC, 0x16, 0x12, 0xC6, 0x8B, 0x3F, 0xF6, 0xE6, 0xF4, 0xFB, 0xE3, 0x0E, 0x71, 0xE4, 0x76, 0x9C, 0x8B, 0x80, 0xA3, 0x2C, 0xB8, 0x95, 0x8C, 0xD5, 0xD1, 0x7D, 0x6B, 0x25, 0x4D, 0xA1}
        },
        /* 256bit KEK, 256bit key*/
        {
            32,
            32,
            40,

            {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6},

            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
            {0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B, 0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21}
        }
    };

    uint8_t in[1024];
    uint8_t out[1024];
    int i;
    aes_ctxt aes;
    int fail = 0;

    for(i=0; i < (sizeof(nist) / sizeof(*nist)); i++){

        aes_wrap_init(&aes, nist[i].kek, nist[i].keklen);
            
        //non-overlap
        memcpy(in, nist[i].in, nist[i].inlen);

        aes_wrap_encipher(&aes, out, in, nist[i].inlen, nist[i].iv);

        if(memcmp(out, nist[i].out, nist[i].outlen)){

            fprintf(stderr, "FAIL aes_wrap_encipher() non-overlap\n");
            fail++;
        }
        
        memcpy(in, nist[i].out, nist[i].outlen);

        if(aes_wrap_decipher(&aes, out, in, nist[i].outlen, nist[i].iv) || memcmp(out, nist[i].in, nist[i].inlen)){

            fprintf(stderr, "FAIL aes_wrap_decipher() non-overlap\n");
            fail++;
        }

        //overlap
        memcpy(in, nist[i].in, nist[i].inlen);

        aes_wrap_encipher(&aes, in, in, nist[i].inlen, nist[i].iv);

        if(memcmp(in, nist[i].out, nist[i].outlen)){

            fprintf(stderr, "FAIL aes_wrap_encipher() overlap\n");
            fail++;
        }
        
        memcpy(in, nist[i].out, nist[i].outlen);

        if(aes_wrap_decipher(&aes, in, in, nist[i].outlen, nist[i].iv) || memcmp(in, nist[i].in, nist[i].inlen)){

            fprintf(stderr, "FAIL aes_wrap_decipher() overlap\n");
            fail++;
        }
    }


    return fail;        
}

int main(int argc, char **argv)
{
    int i, ret = 0, fail = 0;
    FILE *in;

    const char *ecb_vectors[] = {
        "vectors/ECBGFSbox128.rsp",
        "vectors/ECBGFSbox192.rsp",
        "vectors/ECBGFSbox256.rsp",
        "vectors/ECBKeySbox128.rsp",
        "vectors/ECBKeySbox192.rsp",
        "vectors/ECBKeySbox256.rsp",
        "vectors/ECBVarKey128.rsp",
        "vectors/ECBVarKey192.rsp",
        "vectors/ECBVarKey256.rsp",
        "vectors/ECBVarTxt128.rsp",
        "vectors/ECBVarTxt192.rsp",
        "vectors/ECBVarTxt256.rsp"
    };

    

    for(i=0; i < (sizeof(ecb_vectors) / sizeof(*ecb_vectors)); i++){

                        
        if((in = fopen(ecb_vectors[i], "r"))){

            ret = test__ecb(in);
            fclose(in);

            if(!ret)
                fprintf(stdout, "test__ecb() \"%s\" PASS\n", ecb_vectors[i]);

            fail += ret;
        }
        else{

            fprintf(stderr, "cannot open %s\n", ecb_vectors[i]);
        }
    }

    const char *gcm_enc_vectors[] = {
        "vectors/gcmEncryptExtIV128.rsp",
        "vectors/gcmEncryptExtIV192.rsp",
        "vectors/gcmEncryptExtIV256.rsp"
    };

    for(i=0; i < (sizeof(gcm_enc_vectors) / sizeof(*gcm_enc_vectors)); i++){

                        
        if((in = fopen(gcm_enc_vectors[i], "r"))){

            ret = test__gcm(in);
            fclose(in);

            if(!ret)
                fprintf(stdout, "test__gcm() \"%s\" PASS\n", gcm_enc_vectors[i]);

            fail += ret;
        }
        else{

            fprintf(stderr, "cannot open %s\n", gcm_enc_vectors[i]);
        }
    }

    if(!test__wrap()){

        fprintf(stdout, "test__wrap() PASS\n");
        fail++;
    }
    
    if(fail)
        exit(EXIT_FAILURE);
    else
        exit(EXIT_SUCCESS);        
}

