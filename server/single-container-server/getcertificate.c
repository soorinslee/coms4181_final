/*******************************************************/
//COMS W4181
//Final Project
//
//getcertificate.c
//By four words all lowercase ONEWORDALLUPPERCASE
/*******************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

int main(int argc, char** argv) {

    if(argc != 2) {
        fprintf(stderr, "Incorrect number of arguments.\n");
        return 1;
    }

    char* user = malloc((strlen(argv[1])+1) * sizeof(char));
    strcpy(user, argv[1]);

    DIR* dir = opendir("./certs");

    if(dir == NULL) {
        fprintf(stderr, "Issue opening certs directory.\n");
        free(user);
        closedir(dir);
        return 2;
    }

    struct dirent* file;
    int user_exists = 0;
    FILE* cert_file;

    while((file = readdir(dir)) != NULL) {

	if(strcmp(user, file->d_name) == 0) {

	    user_exists = 1;

	    char fp[strlen(user) + 13];
	    strcpy(fp, "./certs/");
	    strcat(fp, user);
	    strcat(fp, "/");
	    strcat(fp, user);
	    strcat(fp, ".pem");
	    cert_file = fopen(fp, "r");
	    break;

	}

    }

    closedir(dir);

    if(user_exists == 0) {
        fprintf(stderr, "User: %s does not exist.\n", user);
        free(user);
        return 3;
    }

    if(cert_file == NULL) {
        fprintf(stderr, "User: %s does not have a certificate.\n", user);
        free(user);
        return 3;
    }


    fseek(cert_file, 0, SEEK_END);
    long size = ftell(cert_file);
    fseek(cert_file, 0, SEEK_SET);

    char* buffer = malloc(size * sizeof(char));

    if(buffer == NULL) {
	fprintf(stderr, "Error allocating memory for buffer.\n");
	free(user);
	fclose(cert_file);
	return 4;
    }

    if(fread(buffer, 1, size, cert_file) != size) {
        fprintf(stderr, "Error reading cert_file.\n");
        free(user);
        free(buffer);
        fclose(cert_file);
        return 5;
    }

    if(fwrite(buffer, 1, size, stdout) != size) {
        fprintf(stderr, "Error writing to stdout.\n");
        free(user);
        free(buffer);
        fclose(cert_file);
        return 6;
    }


    free(user);
    free(buffer);
    fclose(cert_file);
    return 0;

}
