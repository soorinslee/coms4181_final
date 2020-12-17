#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/time.h>

int storemsg(int argc, char** argv) {

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

    char msg[100];

    struct timeval timer_usec;
    long long int timestamp_usec;
    if (!gettimeofday(&timer_usec, NULL)) {
        timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll + (long long int) timer_usec.tv_usec;
    } else {
        timestamp_usec = -1;
    }

    sprintf(msg, "./messages/%s/%lld", user, timestamp_usec);

    FILE* msg_file = fopen(msg, "w");
    char* buffer = malloc(100 * sizeof(char));

    while(1) {

	ssize_t read_size = read(STDIN_FILENO, buffer, sizeof(buffer));

	if(read_size == -1) {
            fprintf(stderr, "Error reading stdin.\n");
            free(user);
            free(buffer);
            fclose(msg_file);
            return 5;
        } else if(read_size < sizeof(buffer)) {

            if(fwrite(buffer, 1, read_size, msg_file) != read_size) {
                fprintf(stderr, "Error writing to msg_file.\n");
                free(user);
                free(buffer);
                fclose(msg_file);
                return 4;
            }

            break;

        }

        if(fwrite(buffer, 1, sizeof(buffer), msg_file) != sizeof(buffer)) {
            fprintf(stderr, "Error writing to msg_file.\n");
            free(user);
            free(buffer);
            fclose(msg_file);
            return 4;
        }

    }

    free(user);
    free(buffer);
    fclose(msg_file);

    printf("Success.\n");

    return 0;

}
