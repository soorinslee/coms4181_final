#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <time.h> 
#include "sha256.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

BYTE password[SHA256_BLOCK_SIZE];
char password_string[999];

void print_hex(BYTE str[], int len)
{
	int idx;
	char password_string[len];

	for(idx = 0; idx < len; idx++)
		printf("%02x", str[idx]);
		password_string[idx] = str[idx];
	//printf("Password String is %s", password_string);
}

int hex_to_string(BYTE str[]) {

    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
        sprintf(password_string + i * 2, "%02x", str[i]);
 
    //printf("%s\n",password_string);
 
    return 0;
}

int hashpassword(char *  input){
	//printf("hashing");
	SHA256_CTX ctx;
	sha256_init(&ctx);
	for (int idx = 0; idx < 100000; ++idx)
		sha256_update(&ctx, input, strlen(input));
	sha256_final(&ctx, password);
}

int main(int argc, char *argv[])
{
    hashpassword(argv[1]);
    hex_to_string(password);
       
    //printf("Password String is %s\n", password_string);
    fputs(password_string, stdout);
    //putchar(password_string);
    return(0);
}