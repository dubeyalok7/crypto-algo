#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "feistal.h"
static uint64_t encrypt(uint32_t left, uint32_t right, uint32_t keys[]);
void encrypt_ecb(FILE *infile, FILE *outfile, uint32_t keys[])
{
  uint32_t left, right;
  size_t ret;
  uint64_t sblock;
  memset(&sblock,0,sizeof(sblock));
  while(fread(&sblock, sizeof(sblock), 1, infile)){    
    left = (sblock>>32);
    right = ((sblock<<32)>>32);
    sblock = encrypt(left, right, keys);
    fwrite(&sblock,1,sizeof(sblock), outfile);
    memset(&sblock,0,sizeof(sblock));
  }
}

static uint64_t encrypt(uint32_t left, uint32_t right, uint32_t keys[])
{
  uint32_t i, l1, r1;
  for(i=0; i<ROUNDS; i++) {
    r1 = left ^ xor_fun(right, keys[i]);
    l1 = right;
    if(i == (ROUNDS -1)) {
      left = r1;
      right = l1;
    } else {
      left = l1;
      right = r1;
    }
  }
  return (uint64_t)left<<32 | right;
}
