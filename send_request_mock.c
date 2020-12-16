//
// Created by freddylukai on 12/6/20.
//

#include "send_request.h"
#include <stdio.h>

cJSON* send_request(cJSON *request) {
    const char* fname = "mock.json";
    char fcontent[100000] = {0};
    FILE* fp;

    fp = fopen(fname, "r");
    fread(fcontent, sizeof(char), 100000, fp);
    //cJSON_Parse turns a string into a cJSON object w/allocation
    return cJSON_Parse(fcontent);
}