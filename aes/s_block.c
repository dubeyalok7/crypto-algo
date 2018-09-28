#include <stdint.h>
#include <stdio.h>

#include "aes.h"
#include "math.h"
#include "matrix.h"


#define ROTL8(x, shift) ((uint8_t) ((x)<<(shift)) | ((x) >> (8-(shift))))

void _init_sbox(uint8_t sbox[256]) {
    uint8_t p = 1, q =1;

    /* loop invariant: p*q == 1 in the Galios Field */

    do {
        /*multiply p by 3*/
        p = p ^ (p << 1)^(p & 0x80 ? 0x1B: 0);

        /* divide q by 3 (equals multiplication by 0xf6 */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        /* compute the affine transformation */

        uint8_t xformed = q^ROTL8(q,1)^ROTL8(q,2)^ROTL8(q,3)^ROTL8(q,4);

        sbox[p] = xformed ^ 0x63;
    } while(p !=1);

    /* 0 is a special case since it has no inverse */
    sbox[0] = 0x63;
}

void initialize_aes_sbox(int sbox[][SBOX_SIZE],float isbox[][SBOX_SIZE]) {
  uint8_t s_box[256]={0};
  int i, j, k = 0;
  /*
  if(!is_prime(p)){
    printf("ERROR: enter valid prime number\n");
    return;
  }
  _init_sbox(s_box, p);
  */
  _init_sbox(s_box);

  for(i=0;i<SBOX_SIZE; i++){
    for(j=0;j<SBOX_SIZE;j++){
      sbox[i][j]=s_box[k++];
    }
  }

  inverse(sbox, isbox);
  printf("S_BOX initialization success ...\n");
  return;
}
