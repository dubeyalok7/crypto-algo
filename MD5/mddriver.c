
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "global.h"
#include "md5.h"

/* Length of test block, number of test blocks. */
#define TEST_BLOCK_LEN 1000
#define TEST_BLOCK_COUNT 1000

static void MDString PROTO_LIST((char *));
static void MDTimeTrial PROTO_LIST ((void));
static void MDTestSuite PROTO_LIST((void));
static void MDFile PROTO_LIST((char *));
static void MDFilter PROTO_LIST ((void));
static void MDPrint PROTO_LIST((unsigned char [16]));

#define MD_CTX MD5_CTX
#define MDInit MD5Init
#define MDUpdate MD5Update
#define MDFinal MD5Final
#define MD 5

void help()
{
  printf("\
       *    Main driver\n\
       *   -sstring  - digests string\n\
       *   -t        - runs time trial\n\
       *   -x        - runs test script\n\
       *   filename  - digest file\n\
       *   (none)    - digests standard input\n\
       *   \n");
}

int main(argc, argv)
  int argc;
  char *argv[];
{
  int i;
  if(argc > 1){
   for(i = 1 ; i< argc; i++){
     if (argv[i][0]=='-' && argv[i][1] == 's')
       MDString(argv[i]+2);
     else if (strcmp(argv[i], "-t") == 0)
       MDTimeTrial();
     else if (strcmp(argv[i], "-x") == 0)
       MDTestSuite();
     else
       MDFile(argv[i]);
   }
  }else{
    help();
     MDFilter();
  }
  return 0;
}

/* Digests a string and prints the result. */
static void MDString (string)
  char *string;
{
  MD_CTX context;
  unsigned char digest[16];
  unsigned int len = strlen(string);

  MDInit(&context);
  MDUpdate(&context, string, len);
  MDFinal(digest, &context);

  printf("MD%d (\"%s\") = ",MD,string);
  MDPrint(digest);
  printf("\n");
}

/* Measures the time to digest TEST_BLOCK_COUNT TEST_BLOCK_LEN - byte blocks. */
static void MDTimeTrial()
{
  MD_CTX context;
  time_t endTime, startTime;
  unsigned char blocks[TEST_BLOCK_LEN], digest[16];
  unsigned int i;

  printf("MD%d time trial. Digesting %d %d-byte blocks ...", MD, TEST_BLOCK_LEN,
      TEST_BLOCK_COUNT);

  /* Initialize block */
  for( i = 0; i<TEST_BLOCK_LEN; i++)
    blocks[i] = (unsigned char)(i & 0xff);

  /*start timer */
  time(&startTime);

  /* Digest blocks */
  MDInit(&context);

  for(i=0;i<TEST_BLOCK_COUNT; i++)
    MDUpdate(&context, blocks, TEST_BLOCK_LEN);
  MDFinal(digest, &context);

  /* Stop timer */
  time(&endTime);

  printf(" done\n");
  printf("Digest = ");
  MDPrint(digest);
  printf("\nTime = %ld seconds\n", (long)(endTime - startTime));
  printf("Speed = %ld bytes/second\n",
      (long)TEST_BLOCK_LEN*(long)TEST_BLOCK_COUNT/(endTime - startTime));
}

/* Digest a reference suite of strings and prints the results. */
static void MDTestSuite()
{
  printf ("MD%d test suite:\n", MD);
  
  MDString ("");
  MDString ("a");
  MDString ("abc");
  MDString ("message digest");
  MDString ("abcdefghijklmnopqrstuvwxyz");
  MDString
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
  MDString ("1234567890123456789012345678901234567890\
      1234567890123456789012345678901234567890");
}

/* Digests a file and prints the result */
static void MDFile (filename)
  char *filename;
{
  FILE *file;
  MD_CTX context;
  int len;
  unsigned char buffer[1024], digest[16];

  if((file = fopen(filename, "rb"))==NULL)
    printf("%s can't be opened\n", filename);
  else {
    MDInit (&context);
    while(len = fread(buffer, 1, 1024, file))
      MDUpdate(&context, buffer, len);
    MDFinal (digest, &context);
    fclose(file);

    printf("MD%d (%s) = ",MD, filename);
    printf("\n");
  }
}

/* Digests the standard input and prints the result */
static void MDFilter ()
{
  MD_CTX context;
  int len;
  unsigned char buffer[16], digest[16];
  
  MDInit (&context);
  while (len = fread (buffer, 1, 16, stdin))
    MDUpdate (&context, buffer, len);
  MDFinal (digest, &context);

  MDPrint (digest);
  printf ("\n");
}

/* Prints a message digest in hexadecimal. */
static void MDPrint (digest)
unsigned char digest[16];
{
  unsigned int i;
  
  for (i = 0; i < 16; i++)
    printf ("%02x", digest[i]);
}
