#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include "md5.h"

void hexdump(void *data, size_t size)
{ unsigned char *byteData = (unsigned char *)data; for (size_t i = 0; i < size; i++) { printf("%02x ", byteData[i]); if ((i + 1) % 16 == 0) printf("\n"); } printf("\n"); }

/// @brief the implementation of HMAC-MD5 as well as some corresponding test vectors
/// @param text  pointer to data stream
/// @param text_len length of data stream
/// @param key pointer to authentication key
/// @param key_len length of authentication key
/// @param digest aller digest to be filled in

void hmac_md5(unsigned char *text, int text_len, unsigned char *key, int key_len, void *digest)
{
    MD5_CTX context;
    unsigned char k_ipad[65]; /* inner padding - key XORd with ipad*/
    unsigned char k_opad[65]; /* outer padding - key XORd with opad*/

    unsigned char tk[16];
    int i;
    /* if key is longer than 64 bytes reset it to key=MD5(key) */
    if (key_len > 64)
    {
        MD5_CTX tctx;
        MD5Init(&tctx);
        MD5Update(&tctx, key, key_len);
        MD5Final(tk, &tctx);

        key = tk;
        key_len = 16;
    }
    /* the HMAC_MD5 tansform look like
     * MD5 (K XOR opad, MD5(K XOR ipad, text))
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected.
     */

    /* start out by storing key in pads*/
    bzero(k_ipad, sizeof k_ipad);
    bzero(k_opad, sizeof k_opad);
    bcopy(key, k_ipad, key_len);
    bcopy(key, k_opad, key_len);

    /* XOR key with ipad and opad values*/
    for (i = 0; i < 64; i++)
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /* perform inner MD5 */
    MD5Init(&context);                   /* init context for 1st
                                          * pass */
    MD5Update(&context, k_ipad, 64);     /* start with inner pad */
    MD5Update(&context, text, text_len); /* then text of datagram */
    MD5Final(digest, &context);          /* finish up 1st pass */
    /*
     * perform outer MD5
     */
    MD5Init(&context);               /* init context for 2nd pass */
    MD5Update(&context, k_opad, 64); /* start with outer pad */
    MD5Update(&context, digest, 16); /* then results of 1st hash */
    MD5Final(digest, &context);      /* finish up 2nd pass */
}

int main_hmac(int argc, char *argv[])
{
    unsigned char key[255];
    unsigned char data[255];
    unsigned char digest[255];
    
    memset(key, 0 , sizeof(key));
    memset(data, 0, sizeof(data));
    memset(digest, 0, sizeof(digest));

    printf("Enter data: ");
    scanf("%s", key);
    printf("\nEnter key: ");
    scanf("%s", data);

    hmac_md5(data, strlen(data), key, strlen(key), digest);
    hexdump(digest, sizeof(digest));
    return 0;
}