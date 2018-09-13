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
  return p;
}

uint32_t f(uint32_t block, uint32_t key)
{
  return block^key;
}

void fesital(FILE *ofile, FILE *ifile, int op)
{
  uint32_t keys[ROUNDS];
  char *key = getKey();
  if(!generateSubKeys(key, keys)){
    printf("Error: key generation getting failed\n");
    return;
  }
  switch(op){
    case 0:
      encrypt_ecb(ifile, ofile, keys);
      break;
    case 1:
      decrypt_ecb(ifile, ofile, keys);
    default:
      printf("Invalid option\n");
      break;
  }
  free(key);
  return;
}
