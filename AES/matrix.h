#ifndef MATRIX_H
#define MATRIX_H

#include <stdint.h>
#include "aes.h"

void get_cofactor(int A[][SBOX_SIZE], int tmp[][SBOX_SIZE], int p, int q, int n);
int determinant(int A[][SBOX_SIZE], int n);
void adjoint(int A[][SBOX_SIZE], int adj[][SBOX_SIZE]);
int inverse(int sbox[][SBOX_SIZE], float iSbox[][SBOX_SIZE]);

#endif
