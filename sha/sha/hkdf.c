#include "sha.h"
#include <string.h>
#include <stdlib.h>

int hkdf(SHAVersion whichSha,
        const unsigned char *salt, int salt_len,
        const unsigned char *ikm, int ikm_len,
        const unsigned char *info, int info_len,
        uint8_t okm[], int okm_len)
