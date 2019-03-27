#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "matrix.h"
#include "aes.h"

int main(int argc, char *argv[])
{
    //uint8_t s_box[256];
    char msg[1024];
    int sbox[SBOX_SIZE][SBOX_SIZE]={0,};
    int isbox[SBOX_SIZE][SBOX_SIZE]={0,};
    size_t len;
    /*
    if(argc == 1){
        printf("aes help:\n\
                ./aes <message>\n");
        return 0;
    }
    */
    initialize_aes_sbox(sbox, isbox);
    sleep(5);
    for(int i=0;i<16;i++) {
        for(int j=0;j<16;j++)
            printf("%x ", sbox[i][j]);
        printf("\n");
    }

    printf("\n");
    for(int i=0;i<16;i++) {
        for(int j=0;j<16;j++)
            printf("%x ", isbox[i][j]);
        printf("\n");
    }
    printf("\n");
    for(int i=0;i<16;i++) {
        for(int j=0;j<16;j++)
            printf("%x ", sbox[i][j]^isbox[i][j]);
        printf("\n");
    }
    return 0;
}
