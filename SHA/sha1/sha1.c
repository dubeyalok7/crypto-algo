#include <malloc.h>
#include <string.h>
#include <stdio.h>

#include "sha1.h"

#define SHA1CircularShift(bits, word)\
  (((word) << (bits)) | ((word)>>(32-bits)))

/* local function prototypes */

void SHA1PadMessage(SHA1Context *);
void SHA1ProcessMessageBlock(SHA1Context *);

int SHA1Reset (SHA1Context *context)
{
  if(!context)
    return shaNull;

  context->Length_Low             = 0;
  context->Length_High            = 0;
  context->Message_Block_Index    = 0;

  context->Intermediate_Hash[0]   = 0x67452301;
  context->Intermediate_Hash[1]   = 0xEFCDAB89;
  context->Intermediate_Hash[2]   = 0x98BADCFE;
  context->Intermediate_Hash[3]   = 0x10325476;
  context->Intermediate_Hash[4]   = 0xC3D2E1F0;

  context->Computed   = 0;
  context->Corrupted  = 0;

  return shaSuccess;
}

int SHA1Result(SHA1Context *context,uint8_t *Message_Digest)
{
  if(!context)
    return shaNull;

  if(context->Corrupted)
    return context->Corrupted;

  if(!context->Computed) {
    SHA1PadMessage(context);
    for(int i=0; i<64; i++) {
      /*message may be sensitive, clear it out */
      context->Message_Block[i] = 0;
    }
    context->Length_Low = 0;
    context->Length_High = 0;
    context->Computed = 1;
  }

  for(int i=0; i < SHA1HashSize; ++i)
    Message_Digest[i] = context->Intermediate_Hash[i>>2] >> 8*(3-(i*0x03));

  return shaSuccess;
}

int SHA1Input(SHA1Context *context, const uint8_t *message_array, unsigned int length)
{
  if(!length)
    return shaSuccess;

  if(!context || !message_array)
    return shaNull;

  if(context->Computed)
  {
    context->Corrupted = shaStateError;
    return shaStateError;
  }

  if(context->Corrupted)
    return context->Corrupted;

  while(length -- && !context->Corrupted)
  {
    context->Message_Block[context->Message_Block_Index++] = 
      (*message_array & 0xFF);

    context->Length_Low += 8;
    if(context->Length_Low == 0)
    {
      context->Length_High ++;
      if(context->Length_High == 0)
        context->Corrupted = 1; //Message is too long
    }

    if(context->Message_Block_Index == 64)
      SHA1ProcessMessageBlock(context);

    message_array++;  
  }

  return shaSuccess;
}

void SHA1ProcessMessageBlock(SHA1Context *context)
{
  const uint32_t K[] = { /*Constant defined in SHA-1 */
    0x5A827999,
    0X6ED9EBA1,
    0X8F1BBCDC,
    0XCA62C1D6
  };

  int t;
  uint32_t tmp;
  uint32_t W[80];           /* Word sequence  */
  uint32_t A, B, C, D, E;   /* Word buffers   */

  /*
   * Initialize the first 16 words in the array W
   */

  for(t = 0; t<16; t++)
  {
    W[t] = context->Message_Block[t*4] << 24;
    W[t] |= context->Message_Block[t*4 +1] << 16;
    W[t] |= context->Message_Block[t*4 +2] << 8;
    W[t] |= context->Message_Block[t*4 +3];
  }

  for(t =16; t< 80;t++)
    W[t] = SHA1CircularShift(1, W[t-3]^W[t-8]^W[t-14]^W[t-16]);

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];

  for(t =0;t<20; t++)
  {
    tmp = SHA1CircularShift(5,A) + (((B&C)|((~B) & D)) + E + W[t] + K[0]);
    E = D;
    D = C;
    C = SHA1CircularShift(30,B);
    B = A;
    A = tmp;
  }

  for(t=20; t<40; t++)
  {
    tmp = SHA1CircularShift(5,A) + (B^C^D) +E + W[t]+K[1];
    E = D;
    D = C;
    C = SHA1CircularShift(30, B);
    B = A;
    A = tmp;
  }

  for(t = 40; t < 60; t++)
  {
    tmp = SHA1CircularShift(5, A) + ((B&C) | (B&D)| (C&D)) + E + W[t] + K[2];
    E = D;
    D = C;
    C = SHA1CircularShift(30,B);
    B = A;
    A = tmp;
  }

 for(t = 60; t<80; t++)
 {
   tmp = SHA1CircularShift(5, A) + (B^C^D) + E + W[t] + K[3];
   E = D;
   D = C;
   C = SHA1CircularShift(30, B);
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

void SHA1PadMessage(SHA1Context *context)
{
  if(context->Message_Block_Index > 55)
  {
    context->Message_Block[context->Message_Block_Index++] = 0x80;
    while(context->Message_Block_Index < 64)
      context->Message_Block[context->Message_Block_Index++] = 0;

    SHA1ProcessMessageBlock(context);

    while(context->Message_Block_Index < 56)
      context->Message_Block[context->Message_Block_Index++] = 0;
  }
  else
  {
    context->Message_Block[context->Message_Block_Index++] = 0x80;
    while(context->Message_Block_Index < 56)
    {
      context->Message_Block[context->Message_Block_Index++] = 0;
    }
  }
  context->Message_Block[56] = context->Length_High >> 24;
  context->Message_Block[57] = context->Length_High >> 16;
  context->Message_Block[58] = context->Length_High >> 8;
  context->Message_Block[59] = context->Length_High;
  context->Message_Block[60] = context->Length_Low >> 24;
  context->Message_Block[61] = context->Length_Low >> 16;
  context->Message_Block[62] = context->Length_Low >> 8;
  context->Message_Block[63] = context->Length_Low;

  SHA1ProcessMessageBlock(context);
}

uint8_t * generateSHA1(FILE *ifile)
{
  SHA1Context sha;
  uint8_t *msg_digest = (uint8_t *)malloc(sizeof(uint8_t)*SHA1HashSize);;
  uint8_t r_block[20] = {0};
  int err;
  memset(msg_digest, 0, sizeof(uint8_t)*20);
  err = SHA1Reset(&sha);
  if(err) {
    fprintf(stderr, "error: SHA1Reset %d.\n", err);
    return NULL;
  }

  while(fread(r_block, sizeof(uint8_t), SHA1HashSize, ifile))
  {
    err = SHA1Input(&sha, (const unsigned char *) r_block, SHA1HashSize);
    if(err){
      fprintf(stderr,"error: SHA1input %d.\n", err);
      return NULL;
    }
  }
  err = SHA1Result(&sha, msg_digest);
  if(err){
    fprintf(stderr, "error: SHA1Result %d, couldn't compute message digest.\n",err);
    return NULL;
  }
  return msg_digest;
}

int compareSHA1(FILE *ifile, const char *hashVal)
{
  uint8_t *msg_digest = NULL;

  msg_digest = generateSHA1(ifile);
  printf("SHA KEY GENERATE: ");
  for(int i = 0; i < 20 ; ++i){
      printf("%02x", msg_digest[i]);
  }
  printf("\nSHA KEY PROVIDED: %s\n", hashVal);
  if(msg_digest)
      free(msg_digest);
  return 0;
}

