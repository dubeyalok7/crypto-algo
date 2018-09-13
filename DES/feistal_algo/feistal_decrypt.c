#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "feistal.h"

static uint64_t decrypt(uint32_t left, uint32_t right, uint32_t keys[]);

void decrypt_ecb(FILE *infile, FILE *outfile, uint32_t keys[])
{
  uint32_t left, right;
  size_t ret;
  uint64_t sblock;
  while(!feof(infile)) {
    memset(&sblock, 0, sizeof(sblock));
    ret = fread(&sblock, 1, sizeof(sblock), infile);
    if(!ret) break;
    left = (sblock>>32);
    right = (sblock<<32)>>32;
    sblock = decrypt(left, right, keys);
    fwrite(&sblock, 1, sizeof(sblock), outfile);
  }
}

static uint64_t decrypt(uint32_t left, uint32_t right, uint32_t keys[])
{
  uint32_t i, l1, r1;
  for(i=ROUNDS -1; i>=0; i--){
    r1 = left ^ f(right, keys[i]);
    l1 = right;
    if(i == 0){
      left = r1;
      right = l1;
    } else {
      left = l1;
      right = r1;
    }
  }
  return (uint64_t)left<<32 | right;
}
