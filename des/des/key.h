#ifndef KEY_H
#define KEY_H

#include <stdint.h>

enum OPERATION{
  ENCRYPT,
  DECRYPT
};

void addbit(uint64_t *block, uint64_t from, int pos_from, int pos_to);
void permutation(uint64_t *data, bool initial);
void key_schedule(uint64_t *key, uint64_t *nxt_key, int round);
void rounds(uint64_t *data, uint64_t key);
static bool key_parity_verify(uint64_t key);
uint64_t key_convert(const char *key);
void encrypt(FILE *ifile, FILE *ofile, uint64_t key);
void decrypt(FILE *ifile, FILE *ofile, uint64_t key);
#endif

