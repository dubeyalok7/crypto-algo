#ifndef _SHA_H_
#define _SHA_H
#include <stdint.h>
#include <string.h>
#ifndef __enum__
#define __enum__
enum {
    SHA_SUCCESS = 0,
    SHA_NULL,
    SHA_WRN,
    SHA_ERR,
    SHA_BAD_PARAM
};
#endif

#define SHA256_SHR(bits, word)    ((word)>>(bits))
#define SHA256_ROTR(bits, word)   (((word)>>(bits))| ((word)<<(32-(bits))))
#define SHA256_RTOL(bits, word)   (((word)<<(bits))| ((word)>>(32-(bits))))

// Following x, y and z are word
#define SHA256_CH(x, y, z)        (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA256_MAJ(x, y, z)       (((x) & (y)) ^ ((y) & (z)) ^ ((z) & (x)))

#define BSIG0(x)                  (SHA256_ROTR(2, x) ^ SHA256_ROTR(13, x) ^ SHA256_ROTR(22, x))
#define BSIG1(x)                  (SHA256_ROTR(6, x) ^ SHA256_ROTR(11, x) ^ SHA256_ROTR(25, x))
#define SSIG0(x)                  (SHA256_ROTR(7, x) ^ SHA256_ROTR(18, x) ^ SHA256_ROTR(3, x))
#define SSIG1(x)                  (SHA256_ROTR(17, x) ^ SHA256_ROTR(19, x) ^ SHA256_ROTR(10, x))


enum {
    SHA256_Message_Block_Size       = 64,
    SHA256_Hash_Size                = 32,
    SHA256_Hash_Size_Bits           = 256,
};

typedef struct SHA256Context
{
    uint32_t h[SHA256_Hash_Size/4]; // intermediate hash value

    uint32_t hl;
    uint32_t ll;

    int_least16_t msg_block_idx;

    uint8_t msg_block[SHA256_Message_Block_Size];

    int Computed;
    int Corrupted;

}SHA256Context;

extern int sha256Init(SHA256Context *);
extern int sha256Input(SHA256Context *, const uint8_t *bytes, unsigned int byte_count);
extern int sha256FinalizeBits(SHA256Context *, uint8_t bits, unsigned int bit_count);
extern int sha256Result(SHA256Context *, uint8_t msgDigest[SHA256_Hash_Size]);
#endif
