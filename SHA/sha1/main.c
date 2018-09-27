#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include "sha1.h"

static void usage(int status)
{
  if(EXIT_SUCCESS == status){
    fprintf(stdout,"Usage:\
        \nTo generate sha key: ./sha1 -i <filename>\
        \nTo validate sha key: ./sha1 -i <filename> -k <key>\n\n");
    fprintf(stdout, "-i, --input = FILE     input file\n");
    fprintf(stdout, "-k, --key = KEY        SHA key given to validate integrity\n");
  }
  else{
    fprintf(stderr, "try './sha1 --help' for more information.\n");
  }
}

int main(int argc, char *argv[])
{
  FILE *ifile = NULL;
  const char *hash_val = NULL;
  uint8_t *msg_digest = NULL;

  int optc = 0;
  const char *short_opts = "h:i:k:";
  const struct option long_opts[]=
  {
    {"input",   required_argument, NULL, 'i'},
    {"key",      required_argument, NULL, 'k'},
    {"help",           no_argument, NULL, 'h'},
    {NULL,                       0, NULL,   0}
  };

  if(argc == 1){
    usage(EXIT_FAILURE);
    return 0;
  }


  while((optc = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1)
  {
    switch(optc)
    {
      case 'i':
        ifile = fopen(optarg, "r");
        if(!ifile){
          fprintf(stdout, "error: issue in opening file\n");
          goto exit;
        }
        break;
      case 'k':
        hash_val = optarg;
        break;
      case 'h':
        usage(EXIT_SUCCESS);
        goto exit;
      default:
        usage(EXIT_FAILURE);
    }
  }

  if(!hash_val){
    msg_digest= generateSHA1(ifile);
    if(!msg_digest){
      fprintf(stderr, "error: SHA generation failure\n");
    }
    else {
      for(int i=0; i<20; ++i)
        printf("%02x ", msg_digest[i]);
      printf("\n");
    }
  }else {
    compareSHA1(ifile, hash_val);
  }
exit:
  if(msg_digest)
    free(msg_digest);
  if(ifile)
    fclose(ifile);
  return 0;
}

