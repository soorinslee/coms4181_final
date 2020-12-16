//
// Created by freddylukai on 12/14/20.
//

#include <stdio.h>
#include "server_handler.h"

cJSON* get_response_obj(cJSON* request) {
    const char* fname = "mock.json";
    char fcontent[100000] = {0};
    FILE* fp;

    fp = fopen(fname, "r");
    fread(fcontent, sizeof(char), 100000, fp);
    //cJSON_Parse turns a string into a cJSON object w/allocation
    return cJSON_Parse(fcontent);
}