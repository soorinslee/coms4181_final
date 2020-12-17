//
// Created by freddylukai on 12/14/20.
//

#include <stdio.h>
#include "server_handler.h"
#include "isuservalid.h"
#include "changepwd.h"
#include "getcertificate.h"
#include "setcertificate.h"
#include "hasmsg.h"
#include "getnextmsg.h"
#include "storemsg.h"

cJSON* get_response_obj(cJSON* request) {
    const char* fname = "mock.json";
    char fcontent[100000] = {0};
    FILE* fp;

    fp = fopen(fname, "r");
    fread(fcontent, sizeof(char), 100000, fp);
    //cJSON_Parse turns a string into a cJSON object w/allocation
    return cJSON_Parse(fcontent);

}

//changepwd request
int changepwd_request(char* user, char* pass, char* new_pass) {
    return changepwd(user, pass, new_pass);
}

//getcert request
int getcert_request(char* user, char* pass) {

    if(isuservalid(user, password) != 0) {
        return 5;
    }

    //generate cert
    system("bash signCert.sh client");

    //replace stdin with cert file
    int in = open("./ca/intermediate/certs/final.cert.pem")
    dup2(in, 0);
    close(in);

    if(setcertificate(user) != 0) {
        fprintf(stderr, "Issue saving generated certificate.\n");
        return 5;
    }

    if(getcertificate(user) != 0) {
        fprintf(stderr, "Issue getting saved certificate.\n");
        return 5;
    }

    //getcertificate writes the certificate to stdout but I'm not
    //totally sure how to go about using that output to send back to the user 


}
