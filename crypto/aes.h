/**
 * @file
 * 
 * @defgroup mAES/aes AES Implementation
 * @{
 * 
 * @license
 *
 * Copyright (c) 2013 Cameron Harper
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
 *
 *
 * */
#ifndef AES_H
#define AES_H

#include <stdint.h>

#define AES_BLOCK_SIZE  16      /**< cipher block size (same for all k_size) */

#define AES128_KEY_SIZE 16      /**< k_size for AES128 */
#define AES192_KEY_SIZE 24      /**< k_size for AES196 */
#define AES256_KEY_SIZE 32      /**< k_size for AES256 */

/** AES context */
typedef struct {

    uint8_t k[240]; /**< expanded key */
    int r;          /**< number of rounds */
    
} aes_ctxt;

/** initialise aes_ctxt
 *
 * @param *aes aes context
 * @param *k pointer to key
 * @param k_size size of *k in bytes
 * 
 * */
int aes_init(aes_ctxt *aes, const uint8_t *k, int k_size);

/** encrypt state of AES_BLOCK_SIZE bytes
 *
 * @param *aes aes context
 * @param *s AES_BLOCK_SIZE bytes of state
 * 
 * */
void aes_encr(const aes_ctxt *aes, uint8_t *s);

/** decrypt state of AES_BLOCK_SIZE bytes
 *
 * @param *aes aes context
 * @param *s AES_BLOCK_SIZE bytes of state
 *
 * */
void aes_decr(const aes_ctxt *aes, uint8_t *s);



/** @defgroup mAES/aes/ecb AES ECB
 *
 * Direct application of the block cipher.
 *
 * - No alignment requirements
 * - handles multiple blocks and will zero pad incomplete blocks
 * 
 * @{ */


/** call to initialise AES context prior to using ecb functions
 *
 * @param *aes aes context
 * @param *k pointer to key
 * @param k_size size of *k in bytes
 *
 * */
int aes_ecb_init(aes_ctxt *aes, const uint8_t *k, int k_size);

/** AES ECB encipher
 *
 * @param *aes AES context
 * @param *out output buffer
 * @param *in buffer (may be aligned with *out)
 * @param size size of *in (octets)
 *
 * */
void aes_ecb_encipher(aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint32_t size);

/** AES ECB decipher
 *
 * @param *aes AES context
 * @param *out output buffer
 * @param *in buffer (may be aligned with *out)
 * @param size size of *in (octets)
 *
 * */
void aes_ecb_decipher(aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint32_t size);

/** @} */

/** @defgroup mAES/aes/gcm AES GCM
 *
 * Stream cipher with authentication from single key and single pass.
 * NIST 800-38D
 * 
 * @{ */

/** largest possible authentication tag size */
#define GCM_TAG_SIZE        AES_BLOCK_SIZE

/** nominal IV size (for efficiency) */
#define GCM_IV_SIZE         12


/** Call to initialise AES context prior to using GCM functions
 *
 * @param *aes returned AES key schedule context
 * @param *k key to expand
 * @param k_size size of *k in octets (expected 16, 24 or 32)
 *
 * @return 0 success; -1 failure
 *
 * */
int aes_gcm_init(aes_ctxt *aes, const uint8_t *k, int k_size);

/** AES GCM Decipher
 *
 * AES context must be initialised prior to calling this function. This allows
 * the same function call to be used for different AES key sizes.
 * 
 * This function may be called with:
 * 1. in and out defined, aad defined
 * 2. in and out null, aad defined
 * 3. in and out defined, aad null
 * 
 * T is always optional. Valid T_size is (0..GCM_TAG_SIZE) octets.
 * If (T_size == 0) then no authentication will be performed.
 *
 * @param *aes AES context
 *
 * @param *IV initialisation vector
 * @param *IV_size size of initialisation vector (octets)
 *
 * @param *out output buffer
 * @param *in buffer (may be aligned with *out)
 * @param size size of *in (octets)
 *
 * @param *aad additional data authenticated but not ciphered
 * @param aad_size size of *aad (octets)
 *
 * @param *T optional authentication tag input buffer
 * @param T_size size of *T (0..GCM_TAG_SIZE octets)
 *
 * */
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
    int T_size);

/** AES GCM Encipher
 *
 * AES context must be initialised prior to calling this function. This allows
 * the same function call to be used for different AES key sizes.
 *
 * This function may be called with:
 * 1. in and out defined, aad defined
 * 2. in and out null, aad defined
 * 3. in and out defined, aad null
 * 
 * T is always optional. Valid T_len is (0..GCM_TAG_SIZE) octets.
 *
 * @param *aes AES context
 *
 * @param *IV initialisation vector
 * @param *IV_size size of initialisation vector (octets)
 *
 * @param *out output buffer
 * @param *in input buffer (may be aligned with *out)
 * @param size size of *in (octets)
 *
 * @param *aad additional data authenticated but not ciphered
 * @param aad_size size of *aad (octets)
 *
 * @param *T optional authentication tag output buffer
 * @param T_size size of *T (0..GCM_TAG_SIZE octets)
 *
 * @return (0) valid result; (-1) invalid result or T_size
 *
 * */
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
    int T_size);

/** @} */

/** @defgroup mAES/aes/wrap AES key wrap
 *
 * Implementation of the NIST AES key wrap specification.
 * 
 * @{ */

/** Call to initialise AES context prior to using key wrap function
 *
 * @param *aes returned AES key schedule context
 * @param *k key to expand
 * @param k_size size of *k in octets (expected 16, 24 or 32)
 *
 * @return 0 success; -1 failure
 *
 * */
int aes_wrap_init(aes_ctxt *aes, const uint8_t *k, int k_size);


/** Wrap input
 *
 * - input must be a multiple of 8 bytes and at least 8 bytes
 * - output buffer must be large enough to accommodate (in_size + 8) bytes
 * - output may be the same memory address as input
 * - iv may be NULL to use the default IV
 *
 * @param *aes AES context
 * @param *out output buffer
 * @param *in input buffer
 * @param in_size size of *in (bytes)
 * @param *iv 8 byte IV field (NULL for default)
 *
 * @return 0 success; -1 failure
 * 
 * */
int aes_wrap_encipher(aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint16_t in_size, const uint8_t *iv);

/** Unwrap input
 * 
 * - input must be a multiple of 8 bytes and at least 16 bytes
 * - output buffer must be large enough to accommodate (in_size - 8) bytes
 * - output may be the same memory address as input
 * - iv may be NULL to use the default IV
 *
 * @param *aes AES context
 * @param *out output buffer
 * @param *in input buffer
 * @param in_size size of *in (bytes)
 * @param *iv 8 byte IV field (NULL for default)
 *
 * @return 0 success; -1 failure
 *
 * */
int aes_wrap_decipher(aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint32_t in_size, const uint8_t *iv);

/** @} */

#endif
/** @} */
