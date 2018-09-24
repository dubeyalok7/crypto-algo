#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>

#include "key.h"

static void help(int status)
{
  if(status == EXIT_SUCCESS)
  {
    fprintf(stdout,"Usage: des -i <filename> -o <filename> -k <key> -t <task>\n"
        "encrypt or decrypt with DES...\n"
        "-k, --key=KEY      64 bits key\n"
        "-t, --task         'e' for encryption or 'd' for decryption\n"
        "-o, --output=FILE  write result to FILE\n"
        "-i, --input=FILE   read from the FILE\n"
        "--help         display this help\n");
  }
  else
  {
    fprintf(stderr, "Try './des --help' for more information.\n");
  }
  exit(status);
}

int main(int argc, char *argv[])
{
  uint64_t key = 0;
  const char *keystr = NULL;
  FILE *ifile = NULL, *ofile=NULL;
  int op;

  int optc = 0;

  const char *short_opts = "t:o:k:i:h:";
  const struct option long_opts[]=
  {
    {"help",           no_argument, NULL, 'h'},
    {"task",      required_argument, NULL, 't'},
    {"output",   required_argument, NULL, 'o'},
    {"input",   required_argument, NULL, 'i'},
    {"key",      required_argument, NULL, 'k'},
    {NULL,                       0, NULL,   0}
  };
  if(argc == 1)
    help(EXIT_FAILURE);

  while((optc = getopt_long(argc, argv, short_opts, long_opts, NULL))!= -1)
  {
    switch(optc)
    {
      case 't':
        if(optarg[0]=='e')
          op = ENCRYPT;
        else if(optarg[0] == 'd')
          op = DECRYPT;
        else{
          fprintf(stdout, "error: in-valid type operations\n");
          goto exit;
        }
        break;
      case 'h':
        help(EXIT_SUCCESS);
        break;
      case 'o':
        ofile = fopen(optarg, "w+");
        if(!ofile) {
          fprintf(stdout, "error: not have permission to create/open file or invalid file name\n"); 
          goto exit;
        }
        break;
      case 'i':
        ifile = fopen(optarg, "r");
        if(!ifile) {
          fprintf(stdout, "error: file doesn't exist\n");
          goto exit;
        }
        break;
      case 'k':
        keystr = optarg;
        if(!keystr) {
          fprintf(stdout, "error: key is not provided\n");
          goto exit;
        }
        break;
      default:
        help(EXIT_FAILURE);
    }
  }
  if(!keystr)
    help(EXIT_FAILURE);

  key = key_convert(keystr);
  if(!key){
    fprintf(stdout, "error: check key length\n");
    goto exit;
  }
    
  if(op)
    decrypt(ifile, ofile, key);
  else
    encrypt(ifile, ofile, key);

exit:
  if(ifile)
    fclose(ifile);
  if(ofile)
    fclose(ofile);
  return 0;
}
