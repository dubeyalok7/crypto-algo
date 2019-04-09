#include <stdio.h>
#include <malloc.h>

#include "sha256.h"


int main()
{
  SHA256Context ctx;
  char msg[1000];
  uint8_t msgDigest[SHA256_Hash_Size];
  char *filename = "/home/napster/VisualStudio/crypto-algo/sha/sha/sample.txt";
  FILE *fp = fopen(filename, "r+");
  if(NULL == fp){
    printf("error: file doesn't exist.\n");
    return -1;
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

  printf("\nCompilation Success\n");
  fclose(fp);
  return 0;
}
