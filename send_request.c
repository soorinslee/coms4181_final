//
// Created by freddylukai on 12/12/20.
//

#include "send_request.h"
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <stdbool.h>

#define MAX_MSG_LEN 1000000

cJSON* send_request_handler(cJSON* request, SSL_CTX *ctx, int request_type);

char* get_url(const char* url);

int connect_and_get_socket_descriptor(const char* url, int port);

char* format_request_bytes(cJSON* request);

cJSON* format_response(char* bytes, int request_type);

cJSON* send_request(cJSON* request) {
    //variables
    SSL_METHOD *method;
    SSL_CTX *ctx;
    int type = 0;
    cJSON* response;

    //check request type
    if (cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(request, "request_type")) == false){
        fprintf(stderr, "Invalid request: type not recognized.\n");
        return NULL;
    }
    type = cJSON_GetObjectItemCaseSensitive(request, "request_type")->valueint;
    if (type < 1 || type > 5) {
        fprintf(stderr, "Invalid request: type not recognized.\n");
        response = NULL;
    }

    //SSL initialization
    SSL_library_init();
    SSL_load_error_strings();

    //get SSL context
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to get SSL context.\n");
        return NULL;
    }

    response = send_request_handler(request, ctx, type);

    SSL_CTX_free(ctx);
    return response;
}

cJSON* send_request_handler(cJSON* request, SSL_CTX* ctx, int request_type) {
    char* url;
    int port, socket_descriptor, msg_len;
    int err;
    SSL *ssl;
    cJSON *url_obj, *response_obj = NULL;
    char* message;
    char response[MAX_MSG_LEN] = {0};
    char errs[1024] = {0};

    //as we have no certificate, we do not initially load a certificate or private key as a client
    //setup SSL ca-chain file
    err = SSL_CTX_load_verify_locations(ctx, "certs/ca-chain.pem", NULL);
    if (err == 0) {
        fprintf(stderr, "Could not load ca-chain file.\n");
        return NULL;
    }
    //set verification rules (default depth is fine)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    //get portno and url
    url_obj = cJSON_GetObjectItemCaseSensitive(request, "url");
    if (cJSON_IsString(url_obj) == true && url_obj->valuestring != NULL) {
        url = get_url(url_obj->valuestring);
        if (url == NULL) {
            fprintf(stderr, "URL not valid.\n");
            return NULL;
        }
    } else {
        fprintf(stderr, "Invalid request: request does not contain url.\n");
        return NULL;
    }
    if (cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(request, "port_no")) == false) {
        fprintf(stderr, "Port number not valid.\n");
        free(url);
        return NULL;
    }
    port = cJSON_GetObjectItemCaseSensitive(request, "port_no")->valueint;

    // connect to server
    socket_descriptor = connect_and_get_socket_descriptor(url, port);
    free(url);
    if (socket_descriptor == -1) {
        return NULL;
    }

    //get message content
    message = format_request_bytes(request);
    if (message == NULL) {
        return NULL;
    }
    msg_len = strlen(message);

    //create ssl session
    ssl = SSL_new(ctx);

    //attach SSL
    SSL_set_fd(ssl, socket_descriptor);
    if ( (err = SSL_connect(ssl)) == 1) {
        //send message
        err = SSL_write(ssl, message, msg_len);
        if (err != msg_len) {
            fprintf(stderr, "Did not successfully write entire message.\n");
            ERR_error_string(SSL_get_error(ssl, err), errs);
            fprintf(stderr, "%s\n", errs);
            SSL_free(ssl);
            free(message);
            return NULL;
        }
        // we can safely deallocate the message here
        free(message);
        // read the response
        err = SSL_read(ssl, response, MAX_MSG_LEN-1);
        if (err <= 0) {
            fprintf(stderr, "Failed to receive information from server.\n");
            SSL_free(ssl);
            return NULL;
        }
        response_obj = format_response(response, request_type);
    } else {
        fprintf(stderr, "Failed SSL connection.\n");
        ERR_error_string(SSL_get_error(ssl, err), errs);
        fprintf(stderr, "%s\n", errs);
    }
    SSL_free(ssl);
    close(socket_descriptor);
    return response_obj;
}

// realistically, this only does some basic checks on the validity of the URL
char* get_url(const char* url) {
    char* url_part;
    if (strnlen(url, 1024) == 1024) {
        return NULL;
    }
    if (strncmp("https://", url, 8) == 0) {
        url_part = (char*)malloc(strlen(url)-8);
        if (url_part == NULL) {
            return url_part;
        }
        strcpy(url_part, url+8);
        return url_part;
    }
    else if (strncmp("http://", url, 7) == 0) {
        url_part = (char*)malloc(strlen(url)-7);
        if (url_part == NULL) {
            return url_part;
        }
        strcpy(url_part, url+7);
        return url_part;
    }
    else {
        url_part = (char*)malloc(strlen(url));
        if (url_part == NULL) {
            return url_part;
        }
        strcpy(url_part, url);
        return url_part;
    }
}

int connect_and_get_socket_descriptor(const char* url, int port) {
    int socket_descriptor;
    struct hostent *host;
    struct sockaddr_in addr;

    //create TCP connection
    if ( (host = gethostbyname(url)) == NULL) {
        fprintf(stderr, "Could not resolve hostname.\n");
        return -1;
    }
    socket_descriptor = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( (connect(socket_descriptor, (struct sockaddr*)&addr, sizeof(addr))) != 0) {
        close(socket_descriptor);
        fprintf(stderr, "Could not connect to server.\n");
        return -1;
    }
    return socket_descriptor;
}

char* format_request_bytes(cJSON* request) {
    char* msg_json_portion, *msg_tot;
    const char* http_part = "POST mail HTTP/1.0\nContent-Length:0\n\n";
    const int http_len = strlen(http_part);
    int msg_len;

    if (cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(request, "content")) == false) {
        fprintf(stderr, "Could not get message content.\n");
        return NULL;
    }
    msg_json_portion = cJSON_PrintUnformatted(cJSON_GetObjectItemCaseSensitive(request, "content"));
    msg_len = strnlen(msg_json_portion, MAX_MSG_LEN);
    if (msg_len <= 0 || msg_len == MAX_MSG_LEN) {
        fprintf(stderr, "Message length not permitted.\n");
        if (msg_len > 0) {
            free(msg_json_portion);
        }
        return NULL;
    }
    msg_tot = (char*)calloc(sizeof(char), http_len + msg_len + 1);
    strcpy(msg_tot, http_part);
    strcat(msg_tot, msg_json_portion);
    free(msg_json_portion);
    return msg_tot;
}

// will do some checks that the response object contains the parts its supposed to contain
cJSON* format_response(char* bytes, int request_type) {
    const char* http_response = "HTTP/1.0 200 OK\nContent-Length:0\nConnection:close\n\n";
    const int http_resp_len = strlen(http_response);
    cJSON* response_obj;

    if (strnlen(bytes, http_resp_len+2) == http_resp_len) {
        fprintf(stderr, "Server returned null.\n");
        return NULL;
    }
    response_obj = cJSON_Parse(bytes+http_resp_len);
    if (response_obj == NULL) {
        fprintf(stderr, "Could not parse response.\n");
        return NULL;
    }

    if (cJSON_GetObjectItemCaseSensitive(response_obj, "status_code") == NULL || cJSON_GetObjectItemCaseSensitive(response_obj, "response_type") == NULL || cJSON_GetObjectItemCaseSensitive(response_obj, "content") == NULL) {
        fprintf(stderr, "Response is invalid.\n");
        cJSON_Delete(response_obj);
        return NULL;
    }
    if (cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(response_obj, "response_type")) == false || cJSON_GetObjectItemCaseSensitive(response_obj, "response_type")->valueint != request_type) {
        fprintf(stderr, "Unexpected response.\n");
        cJSON_Delete(response_obj);
        return NULL;
    }
    return response_obj;
}