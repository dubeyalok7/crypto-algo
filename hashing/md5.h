#include <stdint.h>

#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif

typedef struct {
  uint8_t state[4];
  uint8_t count[2];
  unsigned char buffer[64];
}MD5_CTX;

void MD5Init PROTO_LIST((MD5_CTX *));
void MD5Update PROTO_LIST ((MD5_CTX *, unsigned char *, unsigned int));
void MD5Final PROTO_LIST ((unsigned char [16], MD5_CTX *));
