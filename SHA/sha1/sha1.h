#ifndef _SHA_H
#define _SHA_H

#include <stdint.h>
#include <stdio.h>

#ifndef _SHA_enum_
#define _SHA_enum_
enum
{
    shaSuccess = 0,
    shaNull,
    shaInputTooLong,
    shaStateError
};
#endif
#define SHA1HashSize 20

typedef struct SHA1Context
{
    uint32_t Intermediate_Hash[SHA1HashSize/4];

    uint32_t Length_Low;            /* Message length in bits */
    uint32_t Length_High;           /* Message length in bits */

    int_least16_t Message_Block_Index; /* Index into message block array */
    uint8_t Message_Block[64];      /* 512-bit message blocks   */

    int Computed;                   /*Is the digest computed?   */
    int Corrupted;
} SHA1Context;

/*
 *Function Protypes
 */

int SHA1Reset   (SHA1Context *);
int SHA1Input   (SHA1Context *, const uint8_t *, unsigned int);
int SHA1Result  (SHA1Context *, uint8_t *Message_Digest);
uint8_t * generateSHA1(FILE *ifile);
int compareSHA1 (FILE *ifile, const char *hashVal);
#endif
