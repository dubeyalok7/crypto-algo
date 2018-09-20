#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "feistal.h"

void help(){
  printf("Usage:\n");
  printf("./feistal -i <infile_name> -o <outfile_name> -k key -e\n\
      -i      input file name\n\
      -o      output file name\n\
      -<task> \"-e\" for encrypt and \"-d\" for decrypt\n\n");
  printf("Note: Use ./feistal -g to generate 64 bits keys\n");
  return;
}

static char *getKey(){
  char *p = (char *)malloc(sizeof(char)*10);
  size_t size = sizeof(char)*10;
  memset(p,'\0',sizeof(char)*10);
  printf("Enter key: ");
  getline(&p, &size, stdin);
  if(strlen(p)<=8){
    help();
    return NULL;
  }
  return p;
}

uint32_t f(uint32_t block, uint32_t key)
{
  return block^key;
}

void fesital(FILE *ifile, FILE *ofile, int op)
{
  uint32_t keys[ROUNDS] = { 0xDEAD, 0xBEEF, 0xBAAD, 0xF00D, 0xFEED, 0xFACE, 0xCAFE, 0xBABE, 0xDEAD, 0xBABE, 0xD15, 0xEA5E, 0xDECE, 0xA5ED, 0xBAAD, 0xAC1D };
  char *key = getKey();
  if(!generateSubKeys(key, keys)){
    printf("Error: key generation getting failed\n");
    return;
  }
  for(int i=0;i<ROUNDS;i++)
    printf("%x ", keys[i]);
  printf("\n");
  switch(op){
    case 0:
      encrypt_ecb(ifile, ofile, keys);
      break;
    case 1:
      decrypt_ecb(ifile, ofile, keys);
      break;
    default:
      printf("Invalid option\n");
      break;
  }
  free(key);
  return;
}
