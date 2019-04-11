#ifndef __SHA512_H_
#define __SHA512_H_

#include <stdint.h>

enum {
    SHA512_Message_Block_Size       = 128,
    SHA512_Hash_Size                = 64,
    SHA512_Hash_Size_Bits           = 512,

};
typedef struct SHA512Context {
#ifdef 32BIT_SYSTEM
    uint32_t h[SHA512_Hash_Size/4]; // Intermediate hash value
    uint32_t len[4];
#else  /* 64BIT_SYSTEM */
    uint64_t h[SHA512_Hash_Size/8];
    uint64_t ll, hl;
#endif
    int_least16_t msg_block_size; // msg block array idx
    // 1024-bit msg block
    uint8_t msg_block[SHA512_Message_Block_Size];
    int Computed;
    int Corrupted;
}SHA512Context;

extern int sha512Init(SHA512Context *);
extern int sha512Input(SHA512Context *, const uint8_t *bytes, unsigned int bytecount);
extern int SHA512FinalBits(SHA512Context *, uint8_t bits, unsigned int bit_count);
extern int SHA512Result(SHA512Context *, uint8_t Message_Digest[SHA512_Hash_Size]);

#endif