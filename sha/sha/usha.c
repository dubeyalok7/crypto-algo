#include "sha.h"

int USHAReset(USHAContext *context, enum SHAVersion whichSha)
{
    if(!context) return shaNull;
    context->whichSha = whichSha;
    switch(whichSha) {
        case SHA1:  return SHA1Reset((SHA1Context*)&context->ctx);
        case SHA224: return SHA224Reset((SHA224Context*)&context->ctx);
        case SHA256: return SHA256Reset((SHA256Context*)&context->ctx);
        case SHA384: return SHA384Reset((SHA384Context*)&context->ctx);
        case SHA512: return SHA512Reset((SHA512Context*)&context->ctx);
        default: return shaBadParam;
    }
}

int USHAInput(USHAContext *context, const uint8_t *bytes, unsigned int bytecount)
{
    if(!context) return shaNull;
    switch(context->whichSha) {
        case SHA1:
            return SHA1Input((SHA1Context*)&context->ctx, bytes, bytecount);
        case SHA224:
            return SHA224Input((SHA224Context*)&context->ctx, bytes, bytecount);
        case SHA256:
            return SHA256Input((SHA256Context*)&context->ctx, bytes, bytecount);
        case SHA384:
            return SHA384Input((SHA384Context*)&context->ctx, bytes, bytecount);
        case SHA512:
            return SHA512Input((SHA512Context*)&context->ctx, bytes, bytecount);
        default:
            return shaBadParam;
    }
}

int USHAFinalBits(USHAContext *context, uint8_t bits, unsigned int bit_count)
{
    if(!context) return shaNull;
    switch(context->whichSha) {
        case SHA1:
            return SHA1FinalBits((SHA1Context*)&context->ctx, bits, bit_count);
        case SHA224:
            return SHA224FinalBits((SHA224Context*)&context->ctx, bits, bit_count);
        case SHA256:
            return SHA256FinalBits((SHA256Context*)&context->ctx, bits, bit_count);
        case SHA384:
            return SHA384FinalBits((SHA384Context*)&context->ctx, bits, bit_count);
        case SHA512:
            return SHA512FinalBits((SHA512Context*)&context->ctx, bits, bit_count);
        default:
            return shaBadParam;
    }
}

int USHAResult(USHAContext *context, uint8_t Message_Digest[USHAMaxHashSize])
{
    if(!context) return shaNull;
    switch(context->whichSha) {
        case SHA1:
            return SHA1Result((SHA1Context*)&context->ctx, Message_Digest);
        case SHA224:
            return SHA224Result((SHA224Context*)&context->ctx, Message_Digest);
        case SHA256:
            return SHA256Result((SHA256Context*)&context->ctx, Message_Digest);
        case SHA384:
            return SHA384Result((SHA384Context*)&context->ctx, Message_Digest);
        case SHA512:
            return SHA512Result((SHA512Context*)&context->ctx, Message_Digest);
        default: return shaBadParam;
    }
}

int USHABlockSize(enum SHAVersion whichSha)
{
    switch (whichSha) {
        case SHA1:   return SHA1_Message_Block_Size;
        case SHA224: return SHA224_Message_Block_Size;
        case SHA256: return SHA256_Message_Block_Size;
        case SHA384: return SHA384_Message_Block_Size;
        default:
        case SHA512: return SHA512_Message_Block_Size;
    }
}

int USHAHashSize(enum SHAVersion whichSha)
{
    switch (whichSha) {
        case SHA1:   return SHA1HashSize;
        case SHA224: return SHA224HashSize;
        case SHA256: return SHA256HashSize;
        case SHA384: return SHA384HashSize;
        default:
        case SHA512: return SHA512HashSize;
    }
}

int USHAHashSizeBits(enum SHAVersion whichSha)
{
    switch (whichSha) {
        case SHA1:   return SHA1HashSizeBits;
        case SHA224: return SHA224HashSizeBits;
        case SHA256: return SHA256HashSizeBits;
        case SHA384: return SHA384HashSizeBits;
        default:
        case SHA512: return SHA512HashSizeBits;
    }
}

const char *USHAHashName(enum SHAVersion whichSha)
{
    switch (whichSha) {
        case SHA1:   return "SHA1";
        case SHA224: return "SHA224";
        case SHA256: return "SHA256";
        case SHA384: return "SHA384";
        default:
        case SHA512: return "SHA512";
    }
}
