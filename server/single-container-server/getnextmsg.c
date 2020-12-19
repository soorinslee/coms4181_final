/*******************************************************/
//COMS W4181
//Final Project
//
//getnextmsg.c
//By four words all lowercase ONEWORDALLUPPERCASE
/*******************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/time.h>
#include "getnextmsg.h"

#define MAX_MSG_LEN 100000;

struct MSG {
    int code;
    char* sender;
    char* message;
};

int getnextmsg(char* username) {

    struct MSG* msg_ret = malloc(sizeof(struct MSG));
    if (msg_ret == NULL) {
        return NULL;
    }

    char* user = malloc((strlen(username)+1) * sizeof(char));
    strcpy(user, username);
    char fp[strlen(user) + 12];
    strcpy(fp, "./messages/");
    strcat(fp, user);


    DIR* dir = opendir(fp);

    if(dir == NULL) {
        fprintf(stderr, "Issue opening user's message directory.\n");
        free(user);
        closedir(dir);
        msg_ret->code = 2;
        return msg_ret;
    }

    struct dirent* file;

    struct timeval timer_usec;
    long long int min;
    if (!gettimeofday(&timer_usec, NULL)) {
        min = ((long long int) timer_usec.tv_sec) * 1000000ll + (long long int) timer_usec.tv_usec;
    } else {
        min = -1;
        fprintf(stderr, "Issue getting current time.\n");
        free(user);
        closedir(dir);
        msg_ret->code = 2;
        return msg_ret;
    }

    char* sender = calloc(1024, sizeof(char));

    while((file = readdir(dir)) != NULL) {

        long long int fn;
        if(strcmp(file->d_name, ".") == 0 || strcmp(file->d_name, "..") == 0) {
            continue;
        }
        sscanf(file->d_name, "%s-%lld", sender, &fn);
        if(fn < min) {
            min = fn;
        }

    }

    closedir(dir);

    char min_msg[1024];
    sprintf(min_msg, "./messages/%s/%s-%lld", user, sender, min);

    FILE* msg_file = fopen(min_msg, "r");

    char* msg_str = malloc(MAX_MSG_LEN * sizeof(char));

    if(msg_str == NULL) {
        fprintf(stderr, "Error allocating memory for msg_str.\n");
        free(user);
        fclose(msg_file);
        msg_ret->code = 4;
        return msg_ret;
    }

    if(fread(msg_str, 1, sizeof(msg_str), msg_file) == 0) {
        msg_ret->code = 5;
        return msg_ret;
    }

    // while(1) {
    //
    //     int leave = 0;
    //
    //     size_t size = fread(buffer, 1, sizeof(buffer), msg_file);
    //     if(size < sizeof(buffer)) {
    //         leave = 1;
    //     }
    //
    //     if(fwrite(buffer, 1, size, stdout) != size) {
    //         fprintf(stderr, "Error writing to stdout.\n");
    //         free(user);
    //         free(buffer);
    //         fclose(msg_file);
    //         msg_ret->code = 5;
    //         return msg_ret;
    //     }
    //
    //     if(leave) {
    //         break;
    //     }
    //
    // }

    remove(min_msg);
    free(user);
    fclose(msg_file);

    msg_ret->code = 0;
    msg_ret->sender = sender;
    msg_ret->message = msg_str;

    return msg_ret;

}
