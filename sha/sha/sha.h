#ifndef _SHA_H_
#define _SHA_H_

#include <stdint.h>

#ifndef _SHA_enum_
#define _SHA_enum_

enum {
    shaSuccess = 0,
    shaNull,
    shaInputTooLong,
    shaStateError,
    shaBadParam
};
#endif

enum {
    SHA1_Message_Block_Size = 64,
    SHA224_Message_Block_Size = 64,
    SHA256_Message_Block_Size = 64,
    SHA384_Message_Block_Size = 128,
    SHA512_Message_Block_Size = 128,
    USHA_Max_Message_Block_Size = SHA512_Message_Block_Size,

    SHA1HashSize = 20,
    SHA224HashSize = 28,
    SHA256HashSize = 32,
    SHA384HashSize = 48,
    SHA512HashSize = 64,
    USHAMaxHashSize = SHA512HashSize,

    SHA1HashSizeBits = 160,
    SHA224HashSizeBits = 224,
    SHA256HashSizeBits = 256,
    SHA384HashSizeBits = 384,
    SHA512HashSizeBits = 512,
    USHAMaxHashSizeBits = SHA512HashSizeBits
};

typedef enum SHAVersion {
    SHA1, SHA224, SHA256, SHA384, SHA512
} SHAVersion;

typedef struct SHA1Context {
    uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest*/

    uint32_t Length_High;       /* Message length in bits */
    uint32_t Length_Low;        /* Message length in bits */

    int_least16_t Message_Block_Index;  /* Message_Block array index */
    /* 512 bit message blocks */
    uint8_t Message_Block[SHA1_Message_Block_Size];

    int Computed;
    int Corrupted;
}SHA1Context;

typedef struct SHA256Context {
    uint32_t Intermediate_Hash[SHA256HashSize/4];

    uint32_t Length_High;
    uint32_t Length_Low;

    int_least16_t Message_Block_Index;

    uint8_t Message_Block[SHA256_Message_Block_Size];

    int Computed;
    int Corrupted;
}SHA256Context;

typedef struct SHA512Context {
#ifdef USE_32BIT_ONLY
    uint32_t Intermediate_Hash[SHA512HashSize/4]; /*Message digest */
    uint32_t Lenght[4];
#else  /* !USE_32BIT_ONLY */
    uint64_t Intermediate_Hash[SHA512HashSize/8];
    uint64_t Length_High, Length_Low;
#endif

    int_least16_t Message_Block_Index;  /* Message_Block array index */
    /* 1024-bit message block */

    uint8_t Message_Block[SHA512_Message_Block_Size];

    int Computed;
    int Corrupted;
}SHA512Context;

typedef struct SHA256Context SHA224Context;
typedef struct SHA512Context SHA384Context;

typedef struct USHAContext {
    int whichSha;
    union {
        SHA1Context sha1Context;
        SHA224Context sha224Context;
        SHA256Context sha256Context;
        SHA384Context sha384Context;
        SHA512Context sha512Context;
    }ctx;
}USHAContext;

typedef struct HMACContext {
    int whichSha;               /* which SHA us being used */
    int hashSize;               /* hash size of SHA being used */
    int blockSize;              /* block size of SHA being used */
    USHAContext shaContext;     /* SHA Context  */

    unsigned char k_opad[USHA_Max_Message_Block_Size]; /* outer padding - key XORD with opad */

    int Computed;               /* is the max computed */
    int Corrupted;              /* cumulative corruption code */
}HMACContext;

typedef struct HKDFContext {
    int whichSha;
    HMACContext hmacContext;
    int hashSize;

    unsigned char prk[USHAMaxHashSize];

    int Computed;
    int Corrupted;
}HKDFContext;

/* SHA -1 */
extern int SHA1Reset(SHA1Context *);
extern int SHA1Input(SHA1Context *, const uint8_t *bytes, unsigned int bytecount);
extern int SHA1FinalBits(SHA1Context *, uint8_t bits, unsigned int bit_count);
extern int SHA1Result(SHA1Context *, uint8_t Message_Digest[SHA1HashSize]);

/* SHA-224 */
extern int SHA224Reset(SHA224Context *);
extern int SHA224Input(SHA224Context *, const uint8_t *bytes, unsigned int bytecount);
extern int SHA224FinalBits(SHA224Context *, uint8_t bits, unsigned int bit_count);
extern int SHA224Result(SHA224Context *, uint8_t Message_Digest[SHA224HashSize]);

/* SHA-256 */
extern int SHA256Reset(SHA256Context *);
extern int SHA256Input(SHA256Context *, const uint8_t *bytes, unsigned int bytecount);
extern int SHA256FinalBits(SHA256Context *, uint8_t bits, unsigned int bit_count);
extern int SHA256Result(SHA256Context *, uint8_t Message_Digest[SHA256HashSize]);

/* SHA-384 */
extern int SHA384Reset(SHA384Context *);
extern int SHA384Input(SHA384Context *, const uint8_t *bytes, unsigned int bytecount);
extern int SHA384FinalBits(SHA384Context *, uint8_t bits, unsigned int bit_count);
extern int SHA384Result(SHA384Context *, uint8_t Message_Digest[SHA384HashSize]);

/* SHA-512 */
extern int SHA512Reset(SHA512Context *);
extern int SHA512Input(SHA512Context *, const uint8_t *bytes, unsigned int bytecount);
extern int SHA512FinalBits(SHA512Context *, uint8_t bits, unsigned int bit_count);
extern int SHA512Result(SHA512Context *, uint8_t Message_Digest[SHA512HashSize]);

/* Unified SHA functions, chosen by which SHA */
extern int USHAReset(USHAContext *context, SHAVersion whichSha);
extern int USHAInput(USHAContext *context, const uint8_t *bytes, unsigned int bytecount);
extern int USHAFinalBits(USHAContext *context, uint8_t bits, unsigned int bit_count);
extern int USHAResult(USHAContext *context, uint8_t Message_Digest[USHAMaxHashSize]);
extern int USHABlockSize(enum SHAVersion whichSha);
extern int USHAHashSize(enum SHAVersion whichSha);
extern int USHAHashSizeBits(enum SHAVersion whichSha);
extern const char *USHAHashName(enum SHAVersion whichSha);

/*
 * HMAC Keyed-Hashing for Message Authenticaton, RFC 2104,
 * for all SHAs.
 * This interface allows a fixed-length text input to be used.
 */
extern int hmac(SHAVersion whichSha,    /* which SHA algorithm to use */
        const unsigned char *text,      /* pointer to data stream   */
        int text_len,                   /* length of data stream    */
        const unsigned char *key,       /* pointer to authentication key */
        int key_len,                    /* length of authentication key */
        uint8_t digest[USHAMaxHashSize]); /* caller digest to fill in */

/*
 * HMAC Keyed-Hashing for Message Authenticaton, RFC 2104,
 * for all SHAs.
 * This interface allows any length of text input to be used.
 */

extern int hmacReset(HMACContext *context, enum SHAVersion whichSha,
        const unsigned char *key, int key_len);
extern int hmacInput(HMACContext *context, const unsigned char *text,
        int text_len);
extern int hmacFinalBits(HMACContext *context, uint8_t bits,
        unsigned int bit_count);
extern int hmacResult(HMACContext *context, uint8_t digest[USHAMaxHashSize]);

/*
 * HKDF HMAC-based Extract-and-Expand Key Derivation Function,
 * RFC 5869,  for all SHAs.
 */
extern int hkdf(SHAVersion whichSha, const unsigned char *salt,
        int salt_len, const unsigned char *ikm, int ikm_len,
        const unsigned char *info, int info_len,
        uint8_t okm[ ], int okm_len);
extern int hkdfExtract(SHAVersion whichSha, const unsigned char *salt,
        int salt_len, const unsigned char *ikm,
        int ikm_len, uint8_t prk[USHAMaxHashSize]);
extern int hkdfExpand(SHAVersion whichSha, const uint8_t prk[ ],
        int prk_len, const unsigned char *info,
        int info_len, uint8_t okm[ ], int okm_len);
/*
 * HKDF HMAC-based Extract-and-Expand Key Derivation Function,
 * RFC 5869, for all SHAs.
 * This interface allows any length of text input to be used.
 */

extern int hkdfReset(HKDFContext *context, enum SHAVersion whichSha,
        const unsigned char *salt, int salt_len);
extern int hkdfInput(HKDFContext *context, const unsigned char *ikm,
        int ikm_len);
extern int hkdfFinalBits(HKDFContext *context, uint8_t ikm_bits,
        unsigned int ikm_bit_count);
extern int hkdfResult(HKDFContext *context,
        uint8_t prk[USHAMaxHashSize],
        const unsigned char *info, int info_len,
        uint8_t okm[USHAMaxHashSize], int okm_len);

#endif /* _SHA_H_*/

