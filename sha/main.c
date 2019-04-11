#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sha256.h"

void help()
{
  printf("\t\t\t...HELP...\t\t\t\n");
  printf("usage: ./sha -i <filename> -h <hashing_val>\n");
  printf("\t-i  input file\n");
  printf("\t-h  256/512 hashing value\n");
}

void init_sha_256(char *infile)
{
  SHA256Context ctx;
  char msg[1000];
  uint8_t msgDigest[SHA256_Hash_Size];
  FILE *fp = fopen(infile, "r+");
  if(NULL == fp){
    printf("error: file doesn't exist.\n");
    return;
  }
  sha256Init(&ctx);
  while(!feof(fp)){
    fscanf(fp, "%s", msg);
    sha256Input(&ctx, (uint8_t *)msg, strlen(msg));
  }
  sha256FinalizeBits(&ctx, 0x80, 3);
  sha256Result(&ctx, msgDigest);
    
  for(int i = 0; i < SHA256_Hash_Size; ++i){
    printf("%.2x ", msgDigest[i]);
  }
  fclose(fp);  
}


void init_sha_512(char *infile)
{

}


int main(int argc, char *argv[])
{
  int opt, hash_val = 0;
  extern char *optarg;
  char *infile;
  if(argc<5){
    help();
    return 0;
  }
  while((opt = getopt(argc, argv, "i:h:")) != -1){
    switch (opt)
    {
      case 'i':
        infile = optarg;
        break;
      case 'h':
        hash_val = atoi(optarg);      
        break;
    }
  }
  if(256 == hash_val){
    init_sha_256(infile);
  } else if(512 == hash_val){
    init_sha_512(infile);
  }  
  return 0;
}
