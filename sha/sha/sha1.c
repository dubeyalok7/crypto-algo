#include "sha.h"
#include "sha_private.h"

#define SHA1_ROTL(bits, word) \
    (((word) << (bits)) | ((word) >> (32-(bits))))

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occured.
 */

static uint32_t addTmp;

#define SHA1AddLength(context, length)  \
    (addTmp = (context)->Length_Low,    \
     (context)->Corrupted =             \
     (((context)->Length_Low += (length)) < addTmp) &&  \
     (++(context)->Length_High == 0) ? shaInputTooLong  \
     : (context)->Corrupted)

/* local functions prototypes */
static void SHA1ProcessMessageBlock(SHA1Context *context);
static void SHA1Finalize(SHA1Context *context, uint8_t Pad_Byte);
static void SHA1PadMessage(SHA1Context *context, uint8_t Pad_Byte);

/* global functions */

int SHA1Reset(SHA1Context *context)
{
    if(!context) return shaNull;

    context->Length_High = context->Length_Low = 0;
    context->Message_Block_Index = 0;

    /* Initial Hash Values: FIPS 180-3 section 5.3.1 */
    context->Intermediate_Hash[0]   = 0x67452301;
    context->Intermediate_Hash[1]   = 0xEFCDAB89;
    context->Intermediate_Hash[2]   = 0x98BADCFE;
    context->Intermediate_Hash[3]   = 0x10325476;
    context->Intermediate_Hash[4]   = 0xC3D2E1F0;

    context->Computed = 0;
    context->Corrupted = shaSuccess;

    return shaSuccess;
}

int SHA1Input(SHA1Context *context, const uint8_t *message_array, unsigned length)
{
    if(!context) return shaNull;
    if(!length) return shaSuccess;
    if(!message_array) return shaNull;
    if(context->Computed) return context->Corrupted = shaStateError;
    if(context->Corrupted) return context->Corrupted;

    while(length--)
    {
        context->Message_Block[context->Message_Block_Index++] = *message_array;
        if((SHA1AddLength(context, 8) == shaSuccess) &&
                (context->Message_Block_Index == SHA1_Message_Block_Size))
            SHA1ProcessMessageBlock(context);
        message_array++;

    }

    return context->Corrupted;
}

int SHA1FinalBits(SHA1Context *context, uint8_t message_bits,
        unsigned int length)
{
    static uint8_t masks[8] = {
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

    if(!context) return shaNull;
    if(!length) return shaSuccess;
    if(context->Corrupted) return context->Corrupted;
    if(context->Computed) return context->Corrupted = shaStateError;
    if(length >=8) return context->Corrupted = shaBadParam;

    SHA1AddLength(context, length);
    SHA1Finalize(context, (uint8_t)((message_bits& masks[length])|markbit[length]));

    return context->Corrupted;
}

int SHA1Result(SHA1Context *context, uint8_t Message_Digest[SHA1HashSize])
{
    int i;

    if(!context) return shaNull;
    if(Message_Digest) return shaNull;
    if(context->Corrupted) return context->Corrupted;

    if(!context->Computed)
        SHA1Finalize(context, 0x80);
    for(i =0; i< SHA1HashSize; ++i)
        Message_Digest[i] = (uint8_t) (context->Intermediate_Hash[i>>2]
                >> (8* (3-(i&0x03))));
    return shaSuccess;
}

static void SHA1ProcessMessageBlock(SHA1Context *context)
{
    /* Contants defined in FIPS 180-3, section 4.2.1 */
    const uint32_t K[4] = {
        0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
    };

    int     t;                  // loop counter
    uint32_t tmp;               // temporary word value
    uint32_t W[80];             // word sequence
    uint32_t A, B, C, D, E;     // word buffers

    /*
     * initialize the first 16 words in the array W
     */

    for(t= 0; t<16; t++){
        W[t]  = ((uint32_t)context->Message_Block[t * 4]) << 24;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 3]);
    }

    for(t = 16; t<80; t++) {
        W[t] = SHA1_ROTL(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    for(t = 0; t < 20; t++) {
        tmp = SHA1_ROTL(5,A) + SHA_Ch(B,C,D) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1_ROTL(30, B);
        B = A;
        A = tmp;
    }

    for(t = 20; t < 40; t++) {
        tmp = SHA1_ROTL(5,A) + SHA_Parity(B,C,D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1_ROTL(30,B);
        B = A;
        A = tmp;
    }

    for( t = 40; t <60; t++) {
        tmp = SHA1_ROTL(5, A) + SHA_Maj(B,C,D) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1_ROTL(30, B);
        B = A;
        A = tmp;
    }

    for( t = 60; t < 80; t++) {
        tmp = SHA1_ROTL(5, A) + SHA_Parity(B, C, D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1_ROTL(30, B);
        B = A;
        A = tmp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;

    context->Message_Block_Index = 0;
}

/* local function defination */
static void SHA1Finalize(SHA1Context *context, uint8_t Pad_Byte)
{
    int i;
    SHA1PadMessage(context, Pad_Byte);

    /* message may be sensitive, clear it out */
    for(i = 0; i<SHA1_Message_Block_Size; ++i)
        context->Message_Block[i] = 0;
    context->Length_High = context->Length_Low = 0;
    context->Computed = 1;
}

static void SHA1PadMessage(SHA1Context *context, uint8_t pad_byte)
{
    /*
     * Check to see if the current message block is too small to hold
     * the initial padding bits and length.  If so, we will pad the
     * block, process it, and then continue padding into a second block.
     */
    if(context->Message_Block_Index >= (SHA1_Message_Block_Size)) {
        context->Message_Block[context->Message_Block_Index++] = pad_byte;
        while(context->Message_Block_Index < SHA1_Message_Block_Size)
            context->Message_Block[context->Message_Block_Index++] = 0;

        SHA1ProcessMessageBlock(context);
    } else
        context->Message_Block[context->Message_Block_Index++] = pad_byte;
    while (context->Message_Block_Index < (SHA1_Message_Block_Size - 8))
        context->Message_Block[context->Message_Block_Index++] = 0;
    /*
     * Store the message length as the last 8 octets
     */

    context->Message_Block[56] = (uint8_t) (context->Length_High >> 24);
    context->Message_Block[57] = (uint8_t) (context->Length_High >> 16);
    context->Message_Block[58] = (uint8_t) (context->Length_High >> 8);
    context->Message_Block[59] = (uint8_t) (context->Length_High);
    context->Message_Block[60] = (uint8_t) (context->Length_Low >> 24);
    context->Message_Block[61] = (uint8_t) (context->Length_Low >> 16);
    context->Message_Block[62] = (uint8_t) (context->Length_Low >> 8);
    context->Message_Block[63] = (uint8_t) (context->Length_Low);

    SHA1ProcessMessageBlock(context);
}
