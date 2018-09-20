#include <stdlib.h>
#include <time.h>
#include "feistal.h"

static int inRange(char ch){
  if(ch>='!' && ch<='~')
    return 1;
  return 0;
}

int generateSubKeys(char *key, uint32_t keys[]){
  if(key==NULL)
    return 0;
  int k=0;

  for(int i=0;(i<ROUNDS) && (key[k] != '\0');i+=2, k++){
    keys[i] = (uint32_t)key[k]^keys[i];
    keys[i+1] = (uint32_t)key[k]^keys[i+1];
  } 

  /*
  for(int i=0;i<ROUNDS;i++)
    printf("%x ", keys[i]);
  printf("\n"); */
  return 1;
}

void generateKey(){
  int i=0;
  srand(time(0));
  char key[10]={'\0'};
  while(i!=8){
    key[i] =(char)rand()%256;
    if(inRange(key[i]))
      i++;
  }
  printf("Generated Key: %s\n", key);
}
