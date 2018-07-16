#ifndef _AES_H
#define _AES_H
#include <stdint.h>

#define SBOX_SIZE 16

void initialize_aes_sbox (int sbox[][SBOX_SIZE], float isbox[][SBOX_SIZE]);
#endif
