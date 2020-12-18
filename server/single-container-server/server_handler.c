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

struct CALL_RET* changepw_call(char* username, char* password, char* new_password);

struct CALL_RET* hasmsg_call(char* username);

struct CALL_RET* iscertvalid_call(char* cert_str, char* sig_str);

struct CALL_RET* getrcptcert_call(char* recipient);

struct CALL_RET* savemsg_call(char* sender, char* recipient, char* message);

struct CALL_RET* getmsg_call(char* recipient);

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
    if (call_return->code != 0) {
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

cJSON* handle_request_3(cJSON* request) {
    char *sender, *cur_rcpt, *cert_str, *sig_str;
    cJSON* response_obj, *content_obj, *loop_obj, *loop_internal_obj;
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
    call_return = savemsg_call(username, recipient, msg);
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
    cJSON_AddStringToObject(content_obj, "sender_certificate", cJSON_GetObjectItemCaseSensitive(tmp_obj, "sender_certificate")->valuestring);
    cJSON_AddStringToObject(content_obj, "message", cJSON_GetObjectItemCaseSensitive(tmp_obj, "message")->valuestring);
    cJSON_Delete(tmp_obj);
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

struct CALL_RET* changepw_call(char* username, char* password, char* new_password) {
    //todo Jason: this is similar to the isuservalid_call
}

struct CALL_RET* hasmsg_call(char* username) {
    //todo Jason: checks if the user has messages; don't worry about authenticating
    // 0 if no messages, otherwise anything else
}

struct CALL_RET* iscertvalid_call(char* cert_str, char* sig_str) {
    //todo Jason: checks if this certificate is valid
    // 0 if yes, otherwise anything else
}

struct CALL_RET* getrcptcert_call(char* recipient) {
    //todo Jason: gets a certificate for a given user
    // 0 if the user is valid, otherwise anythign else
    // if 0 is returned, the certificate should be written as a string to content
    // otherwise content should be empty
}

struct CALL_RET* savemsg_call(char* sender, char* recipient, char* message) {
    //todo Jason: save a message for a recipient
    // 0 if it works, otherwise anything else
    // content should always be empty
}

struct CALL_RET* getmsg_call(char* recipient) {
    //todo Jason: pls lmk when you get to this one, this one is a bit complicated
}

////changepwd request
//int changepwd_request(char* user, char* pass, char* new_pass) {
//    return changepwd(user, pass, new_pass);
//}
//
////getcert request
//int getcert_request(char* user, char* pass) {
//
//    if(isuservalid(user, password) != 0) {
//        return 5;
//    }
//
//    //generate cert
//    system("bash signCert.sh client");
//
//    //replace stdin with cert file
//    int in = open("./ca/intermediate/certs/final.cert.pem")
//    dup2(in, 0);
//    close(in);
//
//    if(setcertificate(user) != 0) {
//        fprintf(stderr, "Issue saving generated certificate.\n");
//        return 5;
//    }
//
//    if(getcertificate(user) != 0) {
//        fprintf(stderr, "Issue getting saved certificate.\n");
//        return 5;
//    }
//
//    //getcertificate writes the certificate to stdout but I'm not
//    //totally sure how to go about using that output to send back to the user
//
//
//}
