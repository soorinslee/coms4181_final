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
} call_ret;

cJSON* handle_request_1(cJSON* request);

cJSON* handle_request_2(cJSON* request);

cJSON* handle_request_3(cJSON* request);

cJSON* handle_request_4(cJSON* request);

cJSON* handle_request_5(cJSON* request);

call_ret* getcert_call(char* username, char* password, char* csr_str);

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
    cJSON* response_obj, content_obj;
    call_ret* call_return;

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

    // make the call
    call_return = getcert_call(username, hpass, csr_str);

    // create a JSON response based on the call
    response_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_obj, "response_type", 1);
    content_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(response_obj, "content", content_obj);
    cJSON_AddNumberToObject(content_obj, "response_type", 1);
    switch (call_return->code) {
        case 0:
            cJSON_AddNumberToObject(response_obj, "status_code", 200);
            cJSON_AddStringToObject(content_obj, "certificate", cJSON_CreateString(call_return->content));
            break;
        case 1:
            cJSON_AddNumberToObject(response_obj, "status_code", 401);
            cJSON_AddStringToObject(content_obj, "error_msg", "Invalid username or password.\n");
            break;
        case 2:
            cJSON_AddNumberToObject(response_obj, "status_code", 401);
            cJSON_AddStringToObject(content_obj, "error_msg", "Invalid key presented for signature.\n");
            break;
        default:
            fprintf(stderr, "Invalid return.\n");
            cJSON_Delete(response_obj);
            free(call_return->content);
            return NULL;
    }
    free(call_return->content);
    return response_obj;
}

// calls getcert and gets a response
call_ret* getcert_call(char* username, char* password, char* csr_str) {
    //todo Jason: fill this in; assume csr_str is the full string of the public key/csr
    // you probably want to save the csr to a .csr, get the intermediate cert, and sign the .csr
    // after checking if username is valid
    // call_ret is a structure designed to make it simple if we eventually go to TCP
    // the first field is code: for this, 0 if successful, 1 if username/password was not authorized, 2 if csr is bad
    // the other field is content: whatever string content we might need to return
    // so check if user is valid
    // write csr to a file if needed, get intermediate and sign
    // if it succeeds, malloc call_ret->content, read certificate to that
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
