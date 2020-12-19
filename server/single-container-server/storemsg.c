/*******************************************************/
//COMS W4181
//Final Project
//
//storemsg.c
//By four words all lowercase ONEWORDALLUPPERCASE
/*******************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/time.h>
#include "storemsg.h"

int storemsg(char* sender, char* rcpt, char* message) {

    char* user = malloc((strlen(rcpt)+1) * sizeof(char));
    strcpy(user, rcpt);

    DIR* dir = opendir("./messages");

    if(dir == NULL) {
        fprintf(stderr, "Issue opening messages directory.\n");
        free(user);
        closedir(dir);
        return 2;
    }

    struct dirent* file;
    int user_exists = 0;
    //DIR* user_dir;

    while((file = readdir(dir)) != NULL) {

        if(strcmp(user, file->d_name) == 0) {

            user_exists = 1;

            //char fp[strlen(user) + 13];
            //strcpy(fp, "./messages/");
            //strcat(fp, user);
            //user_dir = opendir(fp);
            break;

        }

    }

    closedir(dir);

    if(user_exists == 0) {
        fprintf(stderr, "User: %s does not exist.\n", user);
        free(user);
        return 3;
    }

    char msg[1000];

    struct timeval timer_usec;
    long long int timestamp_usec;
    if (!gettimeofday(&timer_usec, NULL)) {
        timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll + (long long int) timer_usec.tv_usec;
    } else {
        timestamp_usec = -1;
    }

    sprintf(msg, "./messages/%s/%s-%lld", user, rcpt, timestamp_usec);

    FILE* msg_file = fopen(msg, "w");
    char* buffer = malloc(100 * sizeof(char));

    if(fwrite(message, 1, strlen(message), msg_file) != strlen(message)) {
        fprintf(stderr, "Error writing to msg_file.\n");
        free(user);
        fclose(msg_file);
        return 4;
    }

    // while(1) {
    //
    //     ssize_t read_size = read(STDIN_FILENO, buffer, sizeof(buffer));
    //
    //     if(read_size == -1) {
    //         fprintf(stderr, "Error reading stdin.\n");
    //         free(user);
    //         free(buffer);
    //         fclose(msg_file);
    //         return 5;
    //     } else if(read_size < sizeof(buffer)) {
    //
    //         if(fwrite(buffer, 1, read_size, msg_file) != read_size) {
    //             fprintf(stderr, "Error writing to msg_file.\n");
    //             free(user);
    //             free(buffer);
    //             fclose(msg_file);
    //             return 4;
    //         }
    //
    //         break;
    //
    //     }
    //
    //     if(fwrite(buffer, 1, sizeof(buffer), msg_file) != sizeof(buffer)) {
    //         fprintf(stderr, "Error writing to msg_file.\n");
    //         free(user);
    //         free(buffer);
    //         fclose(msg_file);
    //         return 4;
    //     }
    //
    // }

    free(user);
    // free(buffer);
    fclose(msg_file);

    return 0;

}
