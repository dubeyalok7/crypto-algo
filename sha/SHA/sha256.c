#include <stdint.h>
#include <string.h>
#include "sha256.h"

static uint8_t add_tmp;
#define SHA256_add_len(ctx, lenn)                \
        (add_tmp = (ctx)->ll, (ctx)->Corrupted = \
        (((ctx)->ll += (len) < add_tmp) &&       \
        (++(ctx)->hl == 0) ? SHA_WRN :\
        (ctx)->Corrupted))



// Local functiona prototype 
static void sha256PadMsg(SHA256Context *ctx, uint8_t pad_byte);
static void sha256Process(SHA256Context *ctx);
static void sha256Finalize(SHA256Context *ctx, uint8_t pad_byte);

// Defination of local functions

static void sha256PadMsg(SHA256Context *ctx, uint8_t pad_byte)
{
    /*
     * Check to see if the current message block is too small to hold
     * the initial padding bits and length.  If so, we will pad the
     * block, process it, and then continue padding into a second
     * block.
     */

    if(ctx->msg_block_idx >= (sha256_Message_Block_Size - 8)){
        ctx->msg_block[ctx->msg_block_idx++] = pad_byte;
        while(ctx->msg_block_idx < sha256_Message_Block_Size)
            ctx->msg_block[ctx->msg_block_idx++] = 0;
        sha256Process(ctx);
    } else
        ctx->msg_block[ctx->msg_block_idx++] = 0;

    /* Store the msg len as the last 8 octets */
    ctx->msg_block[56] = (uint32_t)(ctx->hl >> 24);
    ctx->msg_block[57] = (uint32_t)(ctx->hl >> 16);
    ctx->msg_block[58] = (uint32_t)(ctx->hl >> 8);
    ctx->msg_block[59] = (uint32_t)(ctx->hl);
    ctx->msg_block[60] = (uint32_t)(ctx->ll >> 24);
    ctx->msg_block[61] = (uint32_t)(ctx->ll >> 16);
    ctx->msg_block[62] = (uint32_t)(ctx->ll >> 8);
    ctx->msg_block[63] = (uint32_t)(ctx->ll);

    sha256Process(ctx);
}

static void sha256Process(SHA256Context *ctx)
{
    /* Constants defined in FIPS 180-3, section 4.2.2 */
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
        0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
        0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
        0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
        0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    int t, t4;
    uint32_t tmp1, tmp2;
    uint32_t w[64];
    uint32_t a,b,c,d,e,f,g,h;

    /* Initialize the first 16 words in the array */
    for(t = t4 = 0; t< 16; t++, t4+=4)
    {
        w[t] = (((uint32_t)ctx->msg_block[t4]) << 24) |
            (((uint32_t)ctx->msg_block[t4 + 1]) << 16) |
            (((uint32_t)ctx->msg_block[t4 + 2]) << 8) |
            (((uint32_t)ctx->msg_block[t4 + 3]));
    }

    for(t = 16; t<64; ++t)
        w[t] = SSIG1(w[t-2]) + w[t-7] + SSIG0(w[t-15]) + w[t-16];

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];

    for(int t = 0; t< 64; ++t) {
        tmp1 = h + SSIG1(e) + sha256_CH(e, f, g) + k[t] + w[t];
        tmp2 = SSIG0(a) + sha256_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

static void sha256Finalize(SHA256Context *ctx, uint8_t pad_byte)
{
    sha256PadMsg(ctx, pad_byte);
    for(int i=0; i< sha256_Message_Block_Size; ++i){
        ctx->msg_block[i] = 0;
    }
    ctx->ll = ctx->hl = 0;
    ctx->Computed = 1;
}

/* 
Defination for extern API's
*/
int sha256Init(SHA256Context *ctx)
{
    /*
     * For SHA-256, the initial hash value, H(0), consists of the following
     * eight 32-bit words, in hex. These words were obtained by taking the
     * first thirty-two bits of the fractional parts of the square roots of
     * the first eight prime numbers.
     */
    memset(ctx, 0, sizeof(*ctx));
    ctx->hl = ctx->ll = 0;
    ctx->msg_block_idx = 0;

    ctx->h[0] = 0x6a09e667;
    ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372;
    ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f;
    ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab;
    ctx->h[7] = 0x5be0cd19;
    ctx->Computed = 0;
    ctx->Corrupted = SHA_SUCCESS;
    
    return SHA_SUCCESS;
}

int sha256Input(SHA256Context *ctx, const uint8_t *msg, unsigned int len)
{
    if(!ctx)
        return SHA_NULL;
    if(!len)
        return SHA_SUCCESS;
    if(!msg)
        return SHA_NULL;

    if(ctx->Computed) return ctx->Corrupted = SHA_ERR;
    if(ctx->Corrupted) return ctx->Corrupted;

    while(len--){
        ctx->msg_block[ctx->msg_block_idx++] = *msg;
        if((SHA256_add_len(ctx, 8) == SHA_SUCCESS) &&
             (ctx->msg_block_idx == sha256_Message_Block_Size))
            sha256Process(ctx);
        ++msg;
    }
    return SHA_SUCCESS;
}

int sha256FinalizeBits(SHA256Context *ctx, uint8_t msg_bits, unsigned int len)
{
    static uint8_t mask[8] = {
        /* 0 0b00000000 */ 0x00, /* 1 0b10000000 */ 0x80,
        /* 2 0b11000000 */ 0xC0, /* 3 0b11100000 */ 0xE0,
        /* 4 0b11110000 */ 0xF0, /* 5 0b11111000 */ 0xF8,
        /* 6 0b11111100 */ 0xFC, /* 7 0b11111110 */ 0xFE
    };
    static uint8_t markbit[8] = {
        /* 0 0b10000000 */ 0x80, /* 1 0b01000000 */ 0x40,
        /* 2 0b00100000 */ 0x20, /* 3 0b00010000 */ 0x10,
        /* 4 0b00001000 */ 0x08, /* 5 0b00000100 */ 0x04,
        /* 6 0b00000010 */ 0x02, /* 7 0b00000001 */ 0x01
    };

    if(!ctx) return SHA_NULL;
    if(!len) return SHA_SUCCESS;
    if(ctx->Corrupted) return ctx->Corrupted;
    if(ctx->Computed) return SHA_ERR;
    if(len >= 8) return ctx->Corrupted = SHA_BAD_PARAM;

    SHA256_add_len(ctx, len);
    sha256Finalize(ctx, (uint8_t)((msg_bits & mask[len])| markbit[len]));

    return ctx->Corrupted;
}

extern int sha256Result(SHA256Context *ctx, uint8_t msgDigest[sha256_Hash_Size])
{
    if(!ctx) return SHA_NULL;
    if(!msgDigest) return SHA_NULL;
    if(ctx->Corrupted) return ctx->Corrupted;
    if(ctx->Computed) return SHA_ERR;


    for(int i = 0; i < sha256_Hash_Size; ++i)
    {
        msgDigest[i] = (uint8_t) (ctx->h[i>>2]>> 8*(3-(i&0x03)));
    }
    return SHA_SUCCESS;
}
