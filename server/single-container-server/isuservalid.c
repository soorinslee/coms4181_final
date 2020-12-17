/*******************************************************/
//COMS W4181
//Final Project
//
//isuservalid.c
//
//-rwxr-sr-s 1 root root size date isuservalid
//
//By four words all lowercase ONEWORDALLUPPERCASE
/*******************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

int main(int argc, char** argv) {

    if(argc != 3) {
	fprintf(stderr, "Incorrect number of arguments.\n");
	return 1;
    }

    char* user = malloc((strlen(argv[1])+5) * sizeof(char));

    if(user == NULL) {
        fprintf(stderr, "Error allocating memory for user.\n");
        return 2;
    }

    strcpy(user, argv[1]);

    char* pass = malloc((strlen(argv[2])+1) * sizeof(char));

    if(pass == NULL) {
        fprintf(stderr, "Error allocating memory for pass.\n");
	free(user);
        return 2;
    }

    strcpy(pass, argv[2]);

    DIR* dir = opendir("./passwords");

    if(dir == NULL) {
	fprintf(stderr, "Issue opening passwords directory.\n");
	free(user);
	free(pass);
	closedir(dir);
	return 3;
    }

    struct dirent* file;

    int user_exists = 0;

    FILE* pwd_file;

    strcat(user, ".pwd");

    while((file = readdir(dir)) != NULL) {

	if(strcmp(user, file->d_name) == 0) {

	    user_exists = 1;

	    char fp[strlen(user) + 13];

	    strcpy(fp, "./passwords/");
	    strcat(fp, user);

	    pwd_file = fopen(fp, "r");

	    if(pwd_file == NULL) {
        	fprintf(stderr, "Error opening pwd_file.\n");
		free(user);
		free(pass);
                return 4;
            }

	    break;

	}
    }

    closedir(dir);


    if(user_exists == 0) {
	fprintf(stderr, "User: %s does not exist.\n", user);
	free(user);
	free(pass);
	return 5;
    }

    char* hashed_pwd = malloc(33 * sizeof(char));

    if(hashed_pwd == NULL) {
        fprintf(stderr, "Error allocating memory for hashed_pwd.\n");
        free(user);
        free(pass);
        fclose(pwd_file);
        return 2;
    }

    fseek(pwd_file, 0, SEEK_SET);

    if(fread(hashed_pwd, 1, 32, pwd_file) != 32) {
	fprintf(stderr, "User's stored password corrupted.\n");
	free(user);
	free(pass);
	free(hashed_pwd);
	fclose(pwd_file);
	return 6;
    }

    *(hashed_pwd + 32) = '\0';

    if(strcmp(pass, hashed_pwd) != 0) {
	fprintf(stderr, "Password provided does not match stored password.\n");
	free(user);
	free(pass);
	free(hashed_pwd);
	fclose(pwd_file);
	return 7;
    }

    printf("User is valid.\n");

    free(user);
    free(pass);
    free(hashed_pwd);
    fclose(pwd_file);
    return 0;

}
