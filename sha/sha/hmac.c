#include "sha.h"

int hmac(SHAVersion whichSha, const unsigned char *message_array,
        int length, const unsigned char *key, int key_len,
        uint8_t digest[USHAMaxHashSize])
{
    HMACContext context;
    return hmacReset(&context, whichSha, key, key_len) ||
        hmacInput(&context, message_array, length) ||
        hmacResult(&context, digest);
}

int hmacReset(HMACContext *context, enum SHAVersion whichSha,
        const unsigned char * key, int key_len)
{
    int i, blockSize, hashSize, ret;

    /* inner padding - key XORd with ipad */
    unsigned char k_ipad[USHA_Max_Message_Block_Size];

    /* temporary buffer when keylen > blockSize */
    unsigned char tmpKey[USHAMaxHashSize];

    if(!context) return shaNull;
    context->Computed = 0;
    context->Corrupted = shaSuccess;

    blockSize = context->blockSize = USHABlockSize(whichSha);
    hashSize = context->hashSize = USHAHashSize(whichSha);
    context->whichSha = whichSha;

    /*
     * If key is longer than the hash blockSize,
     * reset it to key = HASH(key).
     */

    if(key_len > blockSize) {
        USHAContext tcontext;
        int err = USHAReset(&tcontext, whichSha) ||
            USHAInput(&tcontext, key, key_len) ||
            USHAResult(&tcontext, tmpKey);

        if(err != shaSuccess) return err;
        key = tmpKey;
        key_len = hashSize;
    }

    /*
     * The HAMX transform looks like:
     *
     * SHA(K XOR opad, SHA(K XOR ipad, text))
     *
     * where K is an n byte key, 0-padded to a total of blockSize bytes,
     * ipad is the byte 0x36 repeated blockSize times,
     * opad is the byte 0x5c repeated blockSize times,
     * and text is the the data being protected.
     */

    /*store pad bytes are '\0' XOR'd with ipad and opad values */
    for(i = 0; i < key_len; ++i) {
        k_ipad[i] = key[i] ^ 0x36;
        context->k_opad[i] = key[i] ^ 0x5c;
    }

    /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
    for( ; i < blockSize; ++i) {
        k_ipad[i] = 0x36;
        context->k_opad[i] = 0x5c;
    }

    /* perform inner hash */
    /* init context for 1st pass */
    ret = USHAReset(&context->shaContext, whichSha) ||
        /* and start with inner pad */
        USHAInput(&context->shaContext, k_ipad, blockSize);

    return context->Corrupted = ret;
}

int hmacInput(HMACContext *context, const unsigned char *text, int text_len)
{
    if(!context) return shaNull;
    if(context->Corrupted) return context->Corrupted;
    if(context->Computed) return context->Corrupted  = shaStateError;
    /* then text of datagram */
    return context->Corrupted = USHAInput(&context->shaContext, text, text_len);
}

int hmacFinalBits(HMACContext *context, uint8_t bits, unsigned int bit_count)
{
    if(!context) return shaNull;
    if(context->Corrupted) return context->Corrupted;
    if(context->Computed) return context->Corrupted = shaStateError;
    /* then final bits of datagram */
    return context->Corrupted = USHAFinalBits(&context->shaContext, bits, bit_count);
}

int hmacResult(HMACContext *context, uint8_t *digest)
{
    int ret;
    if(!context) return shaNull;
    if(context->Corrupted) return context->Corrupted;
    if(context->Computed) return context->Corrupted = shaStateError;

    /* finish up 1st pass */
    /* (Use digest here as a temporary buffer. */

    ret = USHAResult(&context->shaContext, digest) ||
        /* perform outer SHA */
        /* init context for 2nd pass. */
        USHAReset(&context->shaContext, context->whichSha) ||
        /* start with outer pad */
        USHAInput(&context->shaContext, context->k_opad, context->blockSize) ||
        /*finish up 2nd pass */
        USHAResult(&context->shaContext, digest);

    context->Computed = 1;
    return context->Corrupted = ret;
}
