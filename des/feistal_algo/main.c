#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "feistal.h"

int main(int argc, char *argv[])
{
  FILE *infile, *outfile;
  char *key;
  int op;
  if((argc==2)&&(!strcmp(argv[1],"-g"))){
    generateKey();
    return 0;
  }

  if((argc < 5)){
    help();
    return 0;
  }

  for(int i=1; i< argc ; i+=2){
    if(!strcmp(argv[i],"-i")){
      printf("Input file: %s\n", argv[i+1]);
      infile = fopen(argv[i+1],"r");
      if(!infile){
        printf("Error: in-valid file name\n");
        help();
        return 0;
      }
    }
    else if(!strcmp(argv[i],"-o")){
      printf("Output File: %s\n",argv[i+1]);
      outfile = fopen(argv[i+1],"w+");
    }
    else if(!strcmp(argv[i],"-e")|| !strcmp(argv[i],"-d")){
      if(argv[i][1] =='e'){
        printf("Encrypting the file...\n");
        op = ENCRYPT;
      }else if(argv[i][1] =='d'){
        op = DECRYPT;
        printf("Decrypting the file...\n");
      }else{
        help();
        return 0;
      }
    }
  }
  fesital(infile, outfile, op);
  fclose(infile);
  fclose(outfile);
  return 0;
}
