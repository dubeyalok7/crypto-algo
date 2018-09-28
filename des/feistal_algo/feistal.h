#ifndef FEISTAL_ALGO_H
#define FEISTAL_ALGO_H
#include <stdint.h>
#include <stdio.h>
#define ROUNDS 16

enum OPERATION{
  ENCRYPT,
  DECRYPT
};

void help();
uint32_t xor_fun(uint32_t block, uint32_t key);
void encrypt_ecb(FILE *infile, FILE *outfile, uint32_t keys[]);
void decrypt_ecb(FILE *infile, FILE *outfile, uint32_t keys[]);
void fesital(FILE *ofile, FILE *ifile, int op);
int generateSubKeys(char *key, uint32_t keys[]);
void generateKey(void);
#endif
