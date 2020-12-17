//
// Created by freddylukai on 12/14/20.
//

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "server_handler.h"
#include "isuservalid.h"
#include "changepwd.h"
#include "getcertificate.h"
#include "setcertificate.h"
#include "hasmsg.h"
#include "getnextmsg.h"
#include "storemsg.h"
#include "cJSON.h"

#define MAX_MSG_LEN 100000;

struct CALL_RET {
    int code;
    char* content;
};

cJSON* handle_request_1(cJSON* request);

cJSON* handle_request_2(cJSON* request);

cJSON* handle_request_3(cJSON* request);

cJSON* handle_request_4(cJSON* request);

cJSON* handle_request_5(cJSON* request);

struct CALL_RET* isuservalid_call(char* username, char* password);

struct CALL_RET* getcert_call(char* csr_str);

cJSON* get_response_obj(cJSON* request) {
    int request_type;

    if (request == NULL) {
        return NULL;
    }

    if (cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(request, "request_type")) == false) {
        fprintf(stderr, "Invalid request.\n");
        return NULL;
    }

    request_type = cJSON_GetObjectItemCaseSensitive(request, "request_type")->valueint;
    switch (request_type) {
        case 1:
            return handle_request_1(request);
        case 2:
            return handle_request_2(request);
        case 3:
            return handle_request_3(request);
        case 4:
            return handle_request_4(request);
        case 5:
            return handle_request_5(request);
        default:
            fprintf(stderr, "Invalid request.\n");
            return NULL;
    }

}

// handles getcert requests
cJSON* handle_request_1(cJSON* request) {
    // todo: tighten up these bounds as reasonable
    char username[256] = {0}, hpass[1024] = {0}, csr_str[16384] = {0};
    cJSON* response_obj, *content_obj;
    struct CALL_RET* call_return;

    // first check that the request has all the required components
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "username")) == false) {
        fprintf(stderr, "Failed getcert: Invalid username.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "password")) == false) {
        fprintf(stderr, "Failed getcert: Invalid password.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "public_key")) == false) {
        fprintf(stderr, "Failed getcert: Invalid csr.\n");
        return NULL;
    }
    // create all the components required
    strncpy(username, cJSON_GetObjectItemCaseSensitive(request, "username")->valuestring, 256);
    strncpy(hpass, cJSON_GetObjectItemCaseSensitive(request, "password")->valuestring, 1024);
    strncpy(csr_str, cJSON_GetObjectItemCaseSensitive(request, "public_key")->valuestring, 16384);

    // setup JSON return
    response_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_obj, "response_type", 1);
    content_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(response_obj, "content", content_obj);
    cJSON_AddNumberToObject(content_obj, "response_type", 1);

    // make calls
    call_return = isuservalid_call(username, password);
    if (call_return->code != 0) {
        cJSON_AddNumberToObject(response_obj, "status_code", 401);
        cJSON_AddStringToObject(content_obj, "error_msg", "Invalid username or password.\n");
        free(call_return);
        return response_obj;
    }
    free(call_return);
    call_return = getcert_call(csr_str);
    if (call_return->code != 0) {
        cJSON_AddNumberToObject(response_obj, "status_code", 401);
        cJSON_AddStringToObject(content_obj, "error_msg", "Invalid key provided.\n");
        free(call_return);
        return response_obj;
    }
    cJSON_AddNumberToObject(response_obj, "status_code", 200);
    cJSON_AddItemToObject(response_obj, "certificate", cJSON_CreateString(call_return->content));
    free(call_return->content);
    free(call_return);
    return response_obj;
}

// calls isuservalid and gets a response
struct CALL_RET* isuservalid_call(char* username, char* password) {
    //todo Jason: fill this in
    // return 0 if valid, else anything else
    // do not allocate call_ret->content
    // you should allocate for call_ret though; the caller will free
}

// calls getcert and gets a response
struct CALL_RET* getcert_call(char* csr_str) {
    //todo Jason: fill this in; assume csr_str is the full string of the public key/csr
    // you probably want to save the csr to a .csr, get the intermediate cert, and sign the .csr
    // call_ret is a structure designed to make it simple if we eventually go to TCP
    // the first field is code: for this, 0 if successful, otherwise anything else
    // if 0 is returned, I expect content in the call_ret, otherwise it should be free
    // the content should be the full text of the certificate
    // so you can write the csr, sign it, write the output cert, and then read it to a string and stick it in content
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
