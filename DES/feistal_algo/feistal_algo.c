#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void help()
{
    printf("\nUsage: ./feistal -k key -m msg\n");
    printf("Option:\n   -t      ECB or CBC (Defualt: CBC)\n");
    printf("\nNote: key size should be equal to or greater than 64 bits i.e. 8 chars\n");
    return;
}

int is_valid_type(char *type)
{
    if(!strcmp(type,"CBC"))
        return 1;
    if(!strcmp(type,"ECB"))
        return 1;
    return 0;
}

void feistal(char *msg, char *key, char *type){
    printf("msg: %s\nkey: %s\ntype: %s\n",msg, key, type);
}

int main(int argc, char *argv[])
{
    if((argc < 5)){
        help();
        return 0;
    }
    else if(argc >5 && argc != 7){
        help();
        return 0;
    }
    else if(argc == 7 && strncmp(argv[5], "-t", strlen("-t"))){
        help();
        return 0;
    }

    if(strncmp(argv[1],"-k", strlen("-k"))|| (strncmp(argv[3],"-m", strlen("-m")))){
        help(0);
        return 0;
    }

    char *msg, *key, *cypher, type[4]="CBC";
    msg = argv[4], key = argv[2];

    if(strlen(key)<8){
        help();
        return 0;
    }
    if(argc ==7)
        strncpy(type, argv[6], sizeof(char)*3);

    if(!is_valid_type(type)){
        help();
        return 0;
    }

    feistal(msg, key, type);

    return 0;
}
