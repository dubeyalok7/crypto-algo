#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "des.h"
#include "key.h"

void addbit(uint64_t *block, uint64_t from, int pos_from, int pos_to)
{
  if(((from << (pos_from)) & FIRSTBIT) != 0)
    *block += (FIRSTBIT >> pos_to);
}


void permutation(uint64_t *data, bool initial)
{
  uint64_t dtmp = 0;
  for(int i=0; i<64; i++)
  {
    if(initial)
      addbit(&dtmp, *data, IP[i] -1, i);
    else
      addbit(&dtmp, *data, IP_1[i] -1, i);
  }
  *data = dtmp;
}

void key_schedule(uint64_t *key, uint64_t *nxt_key, int round)
{
  uint64_t key_left = 0;
  uint64_t key_right = 0;

  uint64_t key_left_tmp = 0;
  uint64_t key_right_tmp = 0;

  nxt_key = 0;

  if(0 == round){ // 1. first round permuted choice 1
    for(int i=0; i<56; i++) {
      if(i<28)
        addbit(&key_left, *key, PC1[i] -1, i);
      else
        addbit(&key_right, *key, PC1[i] -1, i%28);
    }
  }
  else // other rounds -> seperate key into two key halves.
  {
    for(int i=0; i<56; i++)
    {
      if(i<28)
        addbit(&key_left, *key, i, i);
      else
        addbit(&key_right, *key, i, i%28);
    }
  }

  // rotations
  key_left_tmp = rotations[round] == 1 ? FIRSTBIT : 0xc000000000000000;
  key_right_tmp = rotations[round] == 1 ? FIRSTBIT : 0xc000000000000000;
  key_left_tmp = (key_left & key_left_tmp) >> (28 - rotations[round]);
  key_right_tmp = (key_right & key_right_tmp) >> (28 - rotations[round]);

  key_left_tmp += (key_left << rotations[round]);
  key_right_tmp += (key_right << rotations[round]);

  //combine the 2 keys into 1 (nxt_key)
  //nxt_key will be used for following rounds

  for(int i=0; i<56; i++)
  {
    if(i<28)
      addbit(nxt_key, key_left_tmp, i, i);
    else
      addbit(nxt_key, key_right_tmp, i%28, i);
  }

  *key = 0;

  for(int i=0; i<48; i++)
    addbit(key, *nxt_key, PC2[i]-1, i);
}

void rounds(uint64_t *data, uint64_t key)
{
  uint64_t right_block = 0;
  uint64_t right_block_tmp = 0;

  // block expansion
  for(int i=0; i<48; i++)
    addbit(&right_block, *data, (EP[i] + 31), i);

  // xor with key
  right_block = right_block^key;

  // substitution
  int coordx, coordy;
  uint64_t substitued;

  for(int i=0; i<8; i++)
  {
    coordx = ((right_block << 6 * i) & FIRSTBIT) == FIRSTBIT ? 2:0;

    coordy = 0;
    for(int j=1; j<5; j++) {
      if(((right_block<<(6*i + 5)) & FIRSTBIT) == FIRSTBIT)
        coordy += 2^(4-j);
    }

    substitued = sbox[i][coordx][coordy];
    substitued  = substitued << (60 - (4*i));
    right_block_tmp += substitued;
  }

  //Right Block completed
  right_block = right_block_tmp;

  //Permuation
  right_block_tmp = 0;

  for(int i=0; i<32; i++)
    addbit(&right_block_tmp, right_block, PF[i]-1, i);

  right_block = right_block_tmp;

  // xor with left block
  right_block = right_block ^ *data;

  //combine the new block and the right block
  *data = (*data<< 32) + (right_block>>32);
}

static bool key_parity_verify(uint64_t key)
{
  int parity_bit = 0; // parity helper

  for(int i=0; i<64; i++)
  {
    // test parity bit (8th bit)
    if(i%8 == 7)
    {
      if(parity_bit == 0) {
        // test if 8th bit != 0
        if( ((key<<i) & FIRSTBIT) != (uint64_t)0) {
          if( ((key<<i) & FIRSTBIT) != (uint64_t)0){         
            printf("parity error at bit #%i\n", i+1);
            return false;
          }
        } 
      } else {
        if( ((key<<i)&FIRSTBIT) != FIRSTBIT) {
          if( ((key<<i)&FIRSTBIT) != FIRSTBIT) {
            printf("parity error at bit #%i\n", i+1);
            return false;
          }
        }
      }
      parity_bit = 0;
    }
    else {
      if( ((key<<i) & FIRSTBIT) == FIRSTBIT) {
        parity_bit = parity_bit == 0 ? 1:0;
      }
    }
  }
}

uint64_t key_convert(const char *key)
{ 
  if(strlen(key)>9)
    return 0; 
  uint64_t keyval = 0;
  for(int i=0;i < 8;i++){
    keyval = (keyval<<8)|key[i];
  }
  if(key_parity_verify(keyval))
    return keyval;
  return 0;
}

static void get_subkey(uint64_t key, uint64_t sub_key[])
{
  sub_key[0] = key;
  uint64_t nxt_key;

  for(int i =0; i<ROUNDS; i++)
  {
    key_schedule(&sub_key[i], &nxt_key, i);
    if(i != 15)
      sub_key[i+1] = nxt_key;
  }
}

void encrypt(FILE *ifile, FILE *ofile, uint64_t key)
{
  size_t size;
  uint64_t data;
  uint64_t sub_key[ROUNDS]={0};
  get_subkey(key, sub_key);

  while((size = fread(&data,1,8, ifile)) > 0)
  {
    if(size != 8)
      data = data << (8*(8-size));

    permutation(&data, true);
    for(int i=0;i< ROUNDS;i++)
      rounds(&data, sub_key[i]);

    permutation(&data, false);

    if(size != 8)
      data = data<< (8*(8-size));

    fwrite(&data, 1, size, ofile);
    data = 0;
  }
}

void decrypt(FILE *ifile, FILE *ofile, uint64_t key)
{
  size_t size;
  uint64_t data;
  uint64_t sub_key[ROUNDS]={0};
  get_subkey(key, sub_key);

  while((size = fread(&data,1,8, ifile)) > 0)
  {
    data = (data<<32) + (data>>32);
    for(int i=ROUNDS-1; i >=0; i--)
      rounds(&data, sub_key[i]);

    permutation(&data, false);

    if(size != 8)
      data = data<< (8*(8-size));

    fwrite(&data, 1, size, ofile);
    data = 0;
  }
}
