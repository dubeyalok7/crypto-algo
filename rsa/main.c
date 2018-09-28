#include <stdio.h>
#include <string.h>
#include "keygen.h"


int main(int argc, char *argv[])
{
  long long emsg[MSG_LIMIT]={0};
  unsigned char dmsg[MSG_LIMIT] = {0};
  char msg[MSG_LIMIT]={'\0'};
  int i;
  size_t len;
  if((argc<=1)||(argc>2)){
    printf("rsa help:\n\
        ./rsa <message>\n");
    return 0;
  }
  len = strlen(argv[1]);
  if(len>=MSG_LIMIT){
    printf("Error: enter msg within limits of 1-1022");
    return 0;
  }
  memcpy(msg, argv[1], len);

  printf("Input msg: ");
  for(i=0; i<len;i++)
      printf("%x ",msg[i]);
  printf("\n");

  struct keygen_t key = keygen();
  encrypt(emsg, msg, key.pub ,len);
  printf("Cipher :\n");
  for(i=0; i<len;i++)
      printf("%llx ",emsg[i]);
  printf("\n");

  decrypt(dmsg, emsg, key.pri, len);
  printf("Decipher :\n");
  for(i=0; i<len;i++)
      printf("%x ",dmsg[i]);
  printf("\n");;

  printf("original msg: %s\n", msg);
  printf("decrypt  msg: %s\n", dmsg);
  return 0;
}
