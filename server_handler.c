//
// Created by freddylukai on 12/14/20.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include "server_handler.h"
#include "server/single-container-server/isuservalid.h"
#include "server/single-container-server/changepwd.h"
#include "server/single-container-server/getcertificate.h"
#include "server/single-container-server/setcertificate.h"
#include "server/single-container-server/hasmsg.h"
#include "server/single-container-server/getnextmsg.h"
#include "server/single-container-server/storemsg.h"
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

struct CALL_RET* getcert_call(char* username, char* csr_str);

struct CALL_RET* changepw_call(char* username, char* password, char* new_password);

struct CALL_RET* hasmsg_call(char* username);

struct CALL_RET* iscertvalid_call(char* cert_str, char* sig_str);

struct CALL_RET* getrcptcert_call(char* recipient);

struct CALL_RET* savemsg_call(char* sender, char* recipient, char* message);

struct CALL_RET* getmsg_call(char* recipient);

cJSON* get_response_obj(cJSON* request) {
    int request_type;

    fprintf(stdout, cJSON_Print(request));

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
    char *username, *hpass, *csr_str;
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
    username = cJSON_GetObjectItemCaseSensitive(request, "username")->valuestring;
    hpass = cJSON_GetObjectItemCaseSensitive(request, "password")->valuestring;
    csr_str = cJSON_GetObjectItemCaseSensitive(request, "public_key")->valuestring;

    // setup JSON return
    response_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_obj, "response_type", 1);
    content_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(response_obj, "content", content_obj);
    cJSON_AddNumberToObject(content_obj, "response_type", 1);

    // make calls
    call_return = isuservalid_call(username, hpass);
    if (call_return->code != 0) {
        cJSON_AddNumberToObject(response_obj, "status_code", 401);
        cJSON_AddStringToObject(content_obj, "error_msg", "Invalid username or password.\n");
        free(call_return);
        return response_obj;
    }
    free(call_return);
    call_return = getcert_call(username, csr_str);
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

cJSON* handle_request_2(cJSON* request) {
    char *username, *hpass, *hpass2, *csr_str;
    cJSON* response_obj, *content_obj;
    struct CALL_RET* call_return;

    // first check that the request has all the required components
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "username")) == false) {
        fprintf(stderr, "Failed changepw: Invalid username.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "password")) == false) {
        fprintf(stderr, "Failed changepw: Invalid password.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "new_password")) == false) {
        fprintf(stderr, "Failed changepw: Invalid new password.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "public_key")) == false) {
        fprintf(stderr, "Failed changepw: Invalid csr.\n");
        return NULL;
    }
    // create all the components required
    username = cJSON_GetObjectItemCaseSensitive(request, "username")->valuestring;
    hpass = cJSON_GetObjectItemCaseSensitive(request, "password")->valuestring;
    hpass2 = cJSON_GetObjectItemCaseSensitive(request, "new_password")->valuestring;
    csr_str = cJSON_GetObjectItemCaseSensitive(request, "public_key")->valuestring;

    // setup JSON return
    response_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_obj, "response_type", 2);
    content_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(response_obj, "content", content_obj);
    cJSON_AddNumberToObject(content_obj, "response_type", 2);

    // make calls
    call_return = hasmsg_call(username);
    if (call_return->code != 1) {
        cJSON_AddNumberToObject(response_obj, "status_code", 403);
        cJSON_AddStringToObject(content_obj, "error_msg", "Unread messages remain; cannot change password.\n");
        free(call_return);
        return response_obj;
    }
    free(call_return);
    call_return = changepw_call(username, hpass, hpass2);
    if (call_return->code != 0) {
        cJSON_AddNumberToObject(response_obj, "status_code", 401);
        cJSON_AddStringToObject(content_obj, "error_msg", "Invalid username or password.\n");
        free(call_return);
        return response_obj;
    }
    call_return = getcert_call(username, csr_str);
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

cJSON* handle_request_3(cJSON* request) {
    char *sender, *cur_rcpt, *cert_str, *sig_str;
    cJSON* response_obj, *content_obj, *loop_obj, *loop_internal_obj, *elem;
    struct CALL_RET* call_return;

    // first check that the request has all the required components
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "username")) == false) {
        fprintf(stderr, "Failed sendmsg: No username specified.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "certificate")) == false) {
        fprintf(stderr, "Failed sendmsg: No user login cert.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "signature")) == false) {
        fprintf(stderr, "Failed sendmsg: No signature.\n");
        return NULL;
    }
    if (cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(request, "recipients")) == false) {
        fprintf(stderr, "Failed sendmsg: No recipients.\n");
        return NULL;
    }
    // create all the components required
    sender = cJSON_GetObjectItemCaseSensitive(request, "username")->valuestring;
    cert_str = cJSON_GetObjectItemCaseSensitive(request, "certificate")->valuestring;
    sig_str = cJSON_GetObjectItemCaseSensitive(request, "signature")->valuestring;

    // setup JSON return
    response_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_obj, "response_type", 3);
    content_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(response_obj, "content", content_obj);
    cJSON_AddNumberToObject(content_obj, "response_type", 3);

    // check that the user is valid
    call_return = iscertvalid_call(cert_str, sig_str);
    if (call_return->code != 0) {
        cJSON_AddNumberToObject(response_obj, "status_code", 401);
        cJSON_AddStringToObject(content_obj, "error_msg", "User authorization failed.\n");
        free(call_return);
        return response_obj;
    }
    free(call_return);

    // start sending out requests
    loop_obj = cJSON_CreateArray();
    cJSON_AddItemToObject(content_obj, "certificates", loop_obj);
    cJSON_AddNumberToObject(response_obj, "status_code", 200);
    cJSON_ArrayForEach(elem, cJSON_GetObjectItemCaseSensitive(request, "recipients")) {
        if (cJSON_IsString(elem) == true) {
            cur_rcpt = elem->valuestring;
            call_return = getrcptcert_call(cur_rcpt);
            if (call_return->code == 0) {
                loop_internal_obj = cJSON_CreateObject();
                cJSON_AddStringToObject(loop_internal_obj, "username", cur_rcpt);
                cJSON_AddStringToObject(loop_internal_obj, "certificate", call_return->content);
                free(call_return->content);
                cJSON_AddItemToArray(loop_obj, loop_internal_obj);
            }
            free(call_return);
        }
    }
    return response_obj;
}

cJSON* handle_request_4(cJSON* request) {
    char *sender, *recipient, *cert_str, *sig_str, *msg;
    cJSON* response_obj, *content_obj;
    struct CALL_RET* call_return;

    // first check that the request has all the required components
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "username")) == false) {
        fprintf(stderr, "Failed sendmsg: No username specified.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "certificate")) == false) {
        fprintf(stderr, "Failed sendmsg: No user login cert.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "signature")) == false) {
        fprintf(stderr, "Failed sendmsg: No signature.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "recipient")) == false) {
        fprintf(stderr, "Failed sendmsg: No recipient.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "message")) == false) {
        fprintf(stderr, "Failed sendmsg: No message.\n");
        return NULL;
    }
    // create all the components required
    sender = cJSON_GetObjectItemCaseSensitive(request, "username")->valuestring;
    cert_str = cJSON_GetObjectItemCaseSensitive(request, "certificate")->valuestring;
    sig_str = cJSON_GetObjectItemCaseSensitive(request, "signature")->valuestring;
    recipient = cJSON_GetObjectItemCaseSensitive(request, "recipient")->valuestring;
    msg = cJSON_GetObjectItemCaseSensitive(request, "message")->valuestring;

    // setup JSON return
    response_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_obj, "response_type", 4);
    content_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(response_obj, "content", content_obj);
    cJSON_AddNumberToObject(content_obj, "response_type", 4);

    // check that the user is valid
    call_return = iscertvalid_call(cert_str, sig_str);
    if (call_return->code != 0) {
        cJSON_AddNumberToObject(response_obj, "status_code", 401);
        cJSON_AddStringToObject(content_obj, "error_msg", "User authorization failed.\n");
        free(call_return);
        return response_obj;
    }
    free(call_return);

    // send the message
    call_return = savemsg_call(sender, recipient, msg);
    if (call_return-> code != 0) {
        cJSON_AddNumberToObject(response_obj, "status_code", 403);
        cJSON_AddStringToObject(content_obj, "error_msg", "Failed to save msg.\n");
    }
    else {
        cJSON_AddNumberToObject(response_obj, "status_code", 200);
        cJSON_AddStringToObject(content_obj, "message", "OK\n");
    }
    free(call_return);
    return response_obj;
}

cJSON* handle_request_5(cJSON* request) {
    char *recipient, *cert_str, *sig_str;
    cJSON* response_obj, *content_obj, *tmp_obj;
    struct CALL_RET* call_return;

    // first check that the request has all the required components
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "username")) == false) {
        fprintf(stderr, "Failed recvmsg: No username specified.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "certificate")) == false) {
        fprintf(stderr, "Failed recvmsg: No user login cert.\n");
        return NULL;
    }
    if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(request, "signature")) == false) {
        fprintf(stderr, "Failed recvmsg: No signature.\n");
        return NULL;
    }

    // create all the components required
    recipient = cJSON_GetObjectItemCaseSensitive(request, "username")->valuestring;
    cert_str = cJSON_GetObjectItemCaseSensitive(request, "certificate")->valuestring;
    sig_str = cJSON_GetObjectItemCaseSensitive(request, "signature")->valuestring;

    // setup JSON return
    response_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_obj, "response_type", 5);
    content_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(response_obj, "content", content_obj);
    cJSON_AddNumberToObject(content_obj, "response_type", 5);

    // check that the user is valid
    call_return = iscertvalid_call(cert_str, sig_str);
    if (call_return->code != 0) {
        cJSON_AddNumberToObject(response_obj, "status_code", 401);
        cJSON_AddStringToObject(content_obj, "error_msg", "User authorization failed.\n");
        free(call_return);
        return response_obj;
    }
    free(call_return);

    // check that the user has messages;
    call_return = hasmsg_call(recipient);
    if (call_return->code != 0) {
        cJSON_AddNumberToObject(response_obj, "status_code", 403);
        cJSON_AddStringToObject(content_obj, "error_msg", "User has no messages.\n");
        free(call_return);
        return response_obj;
    }
    free(call_return);

    // attempt to retrieve a message
    call_return = getmsg_call(recipient);
    if (call_return->code != 0) {
        cJSON_AddNumberToObject(response_obj, "status_code", 403);
        cJSON_AddStringToObject(content_obj, "error_msg", "Unable to retrieve next message.\n");
        free(call_return);
        return response_obj;
    }
    // retrieve the contents of the message if possible
    tmp_obj = cJSON_Parse(call_return->content);
    free(call_return->content);
    free(call_return);
    if (tmp_obj == NULL || cJSON_IsString(cJSON_GetObjectItemCaseSensitive(tmp_obj, "sender_certificate")) == false || cJSON_IsString(cJSON_GetObjectItemCaseSensitive(tmp_obj, "message")) == false) {
        cJSON_AddNumberToObject(response_obj, "status_code", 403);
        cJSON_AddStringToObject(content_obj, "error_msg", "Unable to parse next message.\n");
        cJSON_Delete(tmp_obj);
        return response_obj;
    }
    cJSON_AddNumberToObject(response_obj, "status_code", 200);
    cJSON_AddStringToObject(content_obj, "sender_certificate", cJSON_GetObjectItemCaseSensitive(tmp_obj, "certificate")->valuestring);
    cJSON_AddStringToObject(content_obj, "message", cJSON_GetObjectItemCaseSensitive(tmp_obj, "message")->valuestring);
    cJSON_Delete(tmp_obj);
    return response_obj;
}

// calls isuservalid and gets a response
struct CALL_RET* isuservalid_call(char* username, char* password) {
    struct CALL_RET* call_ret = malloc(sizeof(struct CALL_RET));
    if (call_ret == NULL) {
        return NULL;
    }
    call_ret->code = isuservalid(username, password);
    return call_ret;
}

// calls getcert and gets a response
struct CALL_RET* getcert_call(char* username, char* csr_str) {
    struct CALL_RET* call_ret = malloc(sizeof(struct CALL_RET));
    if (call_ret == NULL) {
        return NULL;
    }

    // write csr
    char* csr_fn = calloc(sizeof(char), 1024);
    strcat(csr_fn, "ca/intermediate/csr/");
    strcat(csr_fn, username);
    strcat(csr_fn, ".csr.pem");
    FILE* csr_file = fopen(csr_fn, "w");

    if (csr_file == NULL) {
        fprintf(stderr, "Failed to open %s\n", csr_fn);
        free(csr_fn);
        call_ret->code=1;
        return call_ret;
    }

    if(fwrite(csr_str, 1, strlen(csr_str), csr_file) != strlen(csr_str)) {
        fprintf(stderr, "Error writing to csr_file.\n");
        free(csr_fn);
        fclose(csr_file);
        call_ret->code = 1;
        return call_ret;
    }
    fclose(csr_file);

    // sign csr and generate cert
    char* gen_cert = calloc(sizeof(char), 1024);
    strcat(gen_cert, "bash signCert.sh ");
    strcat(gen_cert, username);
    system(gen_cert);

    // call setcertificate to move cert to user folder
    char* cert_fn = calloc(sizeof(char), 1024);
    sprintf(cert_fn, "./ca/intermediate/certs/%s.cert.pem", username);
    int in = open(cert_fn, O_RDONLY);
    dup2(in, 0);
    close(in);

    if(setcertificate(username) != 0) {
        fprintf(stderr, "Issue saving generated certificate.\n");
        call_ret->code = 2;
        return call_ret;
    }

    // call getcertificate to read cert from user folder
    call_ret->code = 0;
    call_ret->content = getcertificate(username);
    return call_ret;

}

struct CALL_RET* changepw_call(char* username, char* password, char* new_password) {
    struct CALL_RET* call_ret = malloc(sizeof(struct CALL_RET));
    if (call_ret == NULL) {
        return NULL;
    }
    call_ret->code = changepwd(username, password, new_password);
    return call_ret;
}

struct CALL_RET* hasmsg_call(char* username) {
    struct CALL_RET* call_ret = malloc(sizeof(struct CALL_RET));
    if (call_ret == NULL) {
        return NULL;
    }
    call_ret->code = hasmsg(username);
    //from the design doc I had it returning 0 if user has messages
    //and i if not obv can be changed easiliy just want to make sure
    //it doesn't cause inconsistency
    return call_ret;
}

struct CALL_RET* iscertvalid_call(char* cert_str, char* sig_str) {
    //todo Jason: checks if this certificate is valid
    // 0 if yes, otherwise anything else
    // struct CALL_RET* call_ret = malloc(sizeof(struct CALL_RET));
    // if (call_ret == NULL) {
    //     return NULL;
    // }
    //
    // char* verify_cert = malloc(100 * sizeof(char));
    // strcat(verify_cert, "bash signCert.sh ");
    // strcat(verify_cert, username)
    // //generate cert
    // system(verify_cert);
    return NULL;
}

struct CALL_RET* getrcptcert_call(char* recipient) {
    //todo Jason: gets a certificate for a given user
    // 0 if the user is valid, otherwise anythign else
    // if 0 is returned, the certificate should be written as a string to content
    // otherwise content should be empty
    return NULL;
}

struct CALL_RET* savemsg_call(char* sender, char* recipient, char* message) {
    struct CALL_RET* call_ret = malloc(sizeof(struct CALL_RET));
    if (call_ret == NULL) {
        return NULL;
    }
    call_ret->code = storemsg(sender, recipient, message);
    return call_ret;
}

struct CALL_RET* getmsg_call(char* recipient) {
    // TODO: call_ret->content
    // cJSON_PrintUnformatted on
    // {
    //   message: contents of mesage file
    //   certificate: contents of sender's certificate
    // }

    struct CALL_RET* call_ret = malloc(sizeof(struct CALL_RET));
    if (call_ret == NULL) {
        return NULL;
    }

    struct MSG* msg_ret = malloc(sizeof(struct MSG));
    if (msg_ret == NULL) {
        return NULL;
    }

    if(hasmsg(recipient) != 0) {
        call_ret->code = 1;
        return call_ret;
    }

    msg_ret = getmsg(recipient);

    char* certificate = getcertificate(msg_ret->sender);

    cJSON* msg_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(response_obj, "message", msg_ret->message);
    cJSON_AddStringToObject(response_obj, "certificate", certificate);

    call_ret->code = 0;
    call_ret->content = msg_obj;

    return call_ret;


}
