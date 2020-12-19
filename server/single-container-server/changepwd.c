/*******************************************************/
//COMS W4181
//Final Project
//
//changepwd.c
//
//-rwxr-sr-s 1 root root size date changepwd
//
//By four words all lowercase ONEWORDALLUPPERCASE
/*******************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/wait.h>
#include "changepwd.h"
#include "isuservalid.h"

int changepwd(char* in_user, char* pass, char* new_pass) {

    // if(argc != 4) {
    //     fprintf(stderr, "Incorrect number of arguments.\n");
    //     return 1;
    // }

    char* user = malloc((strlen(in_user)+5) * sizeof(char));

    if(user == NULL) {
        fprintf(stderr, "Error allocating memory for user.\n");
        return 2;
    }

    strcpy(user, in_user);

    //   char* pass = malloc((strlen(in_pass)+1) * sizeof(char));
    //
    //   if(pass == NULL) {
    //       fprintf(stderr, "Error allocating memory for pass.\n");
    //       free(user);
    // return 2;
    //   }
    //
    //   strcpy(pass, argv[2]);
    //
    //   char* new_pass = malloc((strlen(argv[3])+1) * sizeof(char));
    //
    //   if(new_pass == NULL) {
    //       fprintf(stderr, "Error allocating memory for new_pass.\n");
    //       return 2;
    //   }
    //
    //   strcpy(new_pass, argv[3]);

    if(strlen(new_pass) != 32) {
        fprintf(stderr, "New password corrupted.\n");
        free(user);
        // free(pass);
        // free(new_pass);
        return 2;
    }

    if(isuservalid(user, pass) != 0) {
        fprintf(stderr, "User not valid.\n");
        free(user);
        return 4;
    }

    // pid_t pid = fork();
    // int status;
    //
    // if(pid < 0) {
    //     fprintf(stderr, "Error creating second process with fork()\n");
    //     free(user);
    //     free(pass);
    //     free(new_pass);
    //     return 3;
    // } else if(pid == 0) {
    //     execl("./isuservalid", "isuservalid", user, pass, NULL);
    //
    // } else {
    //     pid = wait(&status);
    //     if(WEXITSTATUS(status) != 0) {
    //         fprintf(stderr, "User not valid.\n");
    //         free(user);
    //         // free(pass);
    //         // free(new_pass);
    //         return 4;
    //     }
    // }

    strcat(user, ".pwd");

    char fp[strlen(user) + 13];

    strcpy(fp, "./passwords/");
    strcat(fp, user);

    FILE* pwd_file = fopen(fp, "w");

    if(pwd_file == NULL) {
        fprintf(stderr, "Error opening pwd_file.\n");
        free(user);
        free(pass);
        free(new_pass);
        return 5;
    }

    fseek(pwd_file, 0, SEEK_SET);
    if(fwrite(new_pass, 1, 32, pwd_file) != 32) {
        fprintf(stderr, "Error writing to %s.\n", user);
        free(user);
        // free(pass);
        // free(new_pass);
        fclose(pwd_file);
        return 6;
    }

    printf("Password successfully changed.\n");

    free(user);
    // free(pass);
    // free(new_pass);
    fclose(pwd_file);
    return 0;

}
