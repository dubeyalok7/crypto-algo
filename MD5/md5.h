typedef struct {
  UINT4 state[4];
  UINT4 count[2];
  unsigned char buffer[64];
}MD5_CTX;

void MD5Init PROTO_LIST((MAD5_CTX *));
void MD5Update PROTO_LIST ((MD5_CTX *, unsigned char *, unsigned int));
void MD5Final PROTO_LIST ((unsigned char [16], MD5_CTX *));


