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

int main(int argc, char** argv) {

    if(argc != 2) {
        fprintf(stderr, "Incorrect number of arguments.\n");
        return 4;
    }

    char* user = malloc((strlen(argv[1])+1) * sizeof(char));
    strcpy(user, argv[1]);
    char fp[strlen(user) + 12];
    strcpy(fp, "./messages/");
    strcat(fp, user);


    DIR* dir = opendir(fp);

    if(dir == NULL) {
        fprintf(stderr, "Issue opening user's message directory.\n");
        free(user);
        closedir(dir);
        return 2;
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
	return 2;
    }


    while((file = readdir(dir)) != NULL) {

	long long int fn;
	if(strcmp(file->d_name, ".") == 0 || strcmp(file->d_name, "..") == 0) {
	    continue;
	}
	sscanf(file->d_name, "%lld", &fn);
        if(fn < min) {
            min = fn;
        }

    }

    closedir(dir);

    char min_msg[100];
    sprintf(min_msg, "./messages/%s/%lld", user, min);

    FILE* msg_file = fopen(min_msg, "r");

    char* buffer = malloc(100 * sizeof(char));

    if(buffer == NULL) {
        fprintf(stderr, "Error allocating memory for buffer.\n");
        free(user);
        fclose(msg_file);
        return 4;
    }

    while(1) {

	int leave = 0;

	size_t size = fread(buffer, 1, sizeof(buffer), msg_file);
	if(size < sizeof(buffer)) {
            leave = 1;    
        }

        if(fwrite(buffer, 1, size, stdout) != size) {
            fprintf(stderr, "Error writing to stdout.\n");
            free(user);
            free(buffer);
            fclose(msg_file);
            return 6;
        }

	if(leave) {
            break;
	}

    }

    remove(min_msg);
    free(user);
    free(buffer);
    fclose(msg_file);
	
    return 0;

}

