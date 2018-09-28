#include <stdint.h>
#include <stdio.h>

#include "aes.h"
#include "matrix.h"

void get_cofactor(int A[][SBOX_SIZE], int tmp[][SBOX_SIZE], int p, int q, int n)
{
  int i=0, j=0, row, col;
  for(row = 0; row < n; row++) {
    for(col =0; col < n; col++) {
      if((row!=p)&&(col!=q))
      {
        tmp[i][j++] = A[row][col];
        if(j==n-1){
          j=0;
          i++;
        }
      }
    }
  }
}

int determinant(int A[][SBOX_SIZE], int n)
{
  int D = 0, i;
  if(n==1)
    return A[0][0];

  int tmp[SBOX_SIZE][SBOX_SIZE]={0};
  int sign = 1;

  for(i=0;i<n;i++) {
    get_cofactor(A, tmp, 0, i, n);
    D += sign*A[0][i]*determinant(tmp, n-1);

    sign = -sign;
  }
  return D;
}


void adjoint(int A[][SBOX_SIZE], int adj[][SBOX_SIZE])
{
  int i, j;
  if(SBOX_SIZE==1) {
    adj[0][0] = 1;
    return;
  }

  int sign = 1, tmp[SBOX_SIZE][SBOX_SIZE];

  for(i = 0; i < SBOX_SIZE; i++) {
    for(j = 0; j < SBOX_SIZE; j++) {
      get_cofactor(A, tmp, i, j, SBOX_SIZE);
      sign = (i+j)%2==0 ? 1 : -1;
      adj[i][j] = sign*(determinant(tmp, SBOX_SIZE -1));
    }
  }
}

int inverse(int A[][SBOX_SIZE], float iA[][SBOX_SIZE])
{
  int i, j;
  int det = determinant(A, SBOX_SIZE);
  if(det == 0){
    printf("Singular matrix, can't find it's inverse\n");
    return 0;
  }

  int adj[SBOX_SIZE][SBOX_SIZE];
  adjoint(A, adj);

  for (i =0; i<SBOX_SIZE; i++)
    for(j=0; j<SBOX_SIZE; j++)
      iA[i][j] = adj[i][j]/(float)(det);
  return 1;
}
