#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include "keygen.h"
#include "math.h"

int encrypt(long long *en, const char * msg,struct key_t pub, size_t len)
{
  if(NULL == msg){
    printf("Error: empty message pass\n");
    return -1;
  }
  int i;
  for(i=0; i<len; i++){
    en[i] = mod_cal(msg[i], pub.val, pub.n);
  }
  return 0;
}

int decrypt(char *msg, const long long * cipher,struct key_t pri, size_t len)
{
  if(NULL == cipher){
    printf("Error: empty message pass\n");
    return -1;
  }

  int i;
  for(i=0; i<len; i++){
    msg[i]=0;
    msg[i] = mod_cal(cipher[i], pri.val, pri.n);
  }

  return 0;
}
