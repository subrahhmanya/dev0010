# Modular AES

An AES implementation for resource constrained applications.

Components:

- AES block cipher
    - byte oriented (512B of tables)
    - support for 128, 196 and 256 bit keys
- AES_ECB
    - multiple blocks in one call with zero padding
- AES_GCM
    - table-less
    - vector operations optimised for target word size
    - single pass (no starting and stopping)
- AES key wrap (NIST)

## Porting

This implementation is intended to be portable. Modules are included and
modified according to the following global defines:

    /* target endianness {0 or 1}; default 1*/
    #define __LITTLE_ENDIAN     1

    /* target word size {1, 2, 4 or 8}; default 1 */
    #define __WORD_SIZE         4

    /* use <string.h> instead of local equivalents */
    #define __USE_STRING

    /* include AES cipher */
    #define AES

        /* include decrypt function */
        #define AES_DECR

        /* memory segment attribute for constant tables (appropriate for GCC) */
        #define AES_CONST

        /* macro for accessing table data in AES_CONST */
        #define SBOX(C)
        #define RSBOX(C)
        #define RCON(C)

    /* include these modes */
    #define AES_GCM
    #define AES_ECB
    #define AES_WRAP


## License

MIT License.


Cameron Harper 2013
cam@cjh.id.au



