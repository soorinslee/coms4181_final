/*******************************************************/
//COMS W4181
//Final Project
//
//hasmsg.c
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
        return 4;
    }

    char* user = malloc((strlen(argv[1])+1) * sizeof(char));
    strcpy(user, argv[1]);

    DIR* dir = opendir("./messages");

    if(dir == NULL) {
        fprintf(stderr, "Issue opening messages directory.\n");
        free(user);
        closedir(dir);
        return 2;
    }

    struct dirent* file;
    int user_exists = 0;
    DIR* user_dir;

    while((file = readdir(dir)) != NULL) {

        if(strcmp(user, file->d_name) == 0) {

            user_exists = 1;

            char fp[strlen(user) + 13];
            strcpy(fp, "./messages/");
            strcat(fp, user);
	    user_dir = opendir(fp);
            break;

        }

    }

    closedir(dir);

    if(user_exists == 0) {
        fprintf(stderr, "User: %s does not exist.\n", user);
        free(user);
        return 3;
    }

    struct dirent* user_file;

    while((user_file = readdir(user_dir)) != NULL) {

	if(strcmp(".", user_file->d_name) != 0) {
	    if(strcmp("..", user_file->d_name) != 0) {
		printf("User exists and has messages.\n");
		free(user);
		closedir(user_dir);
		return 0;
	    }
	}
    }

    printf("User exists but has no messages.\n");
    free(user);
    closedir(user_dir);
    return 1;

}
