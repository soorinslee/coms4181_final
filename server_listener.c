//
// Created by freddylukai on 12/14/20.
//
// based on https://github.com/IamLupo/openssl-examples/blob/master/tlsv1.2/https/src/server.c

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include "cJSON.h"
#include "get_server_certs.h"
#include "server_handler.h"

#define MAX_MSG_LEN 1000000

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
int open_port(int port);

SSL_CTX* init_ctx();

void get_certificates(SSL_CTX* ctx);

void server(SSL* ssl);

cJSON* get_response(char* request_msg);

char* create_response_msg(cJSON* response);

int main(int argc, char** argv) {
    int portno;
    int socket;
    SSL_CTX *ctx;

    if (argc != 2) {
        fprintf(stdout, "Usage: ./server [portno]\n");
        return 1;
    }

    portno = strtol(argv[1], (char**)NULL, 10);
    if (portno <= 0 || portno > 65536) {
        fprintf(stderr, "Illegal port number.\n");
        return 1;
    }

    // load socket and SSL context
    socket = open_port(portno);
    ctx = init_ctx();
    get_certificates(ctx);

    while(1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(socket, (struct sockaddr*)&addr, &len);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        server(ssl);
    }
    close(socket);
    SSL_CTX_free(ctx);
}

int open_port(int port) {
    int socket_descriptor;
    struct sockaddr_in addr;

    socket_descriptor = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(socket_descriptor, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "Failed to bind to port.\n");
        abort();
    }
    if (listen(socket_descriptor, 10) != 0) {
        fprintf(stderr, "Can't configure listening port.\n");
        abort();
    }
    return socket_descriptor;
}

SSL_CTX* init_ctx() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    //SSL initialization
    SSL_library_init();
    SSL_load_error_strings();

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to get server SSL context.\n");
        abort();
    }

    return ctx;
}

void get_certificates(SSL_CTX* ctx) {
    load_server_certs(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
}

void server(SSL* ssl) {
    char request[MAX_MSG_LEN] = {0}, *response;
    char errs[1024] = {0};
    int read, sd, err;
    cJSON *response_obj;

    if ((err = SSL_accept(ssl)) == -1) {
        fprintf(stderr, "SSL error.\n");
        ERR_error_string(SSL_get_error(ssl, err), errs);
        fprintf(stderr, "%s\n", errs);
        sd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(sd);
        return;
    }
    SSL_read(ssl, request, MAX_MSG_LEN);
    response_obj = get_response(request);
    response = create_response_msg(response_obj);
    read = SSL_write(ssl, response, strlen(response));
    if (read < 0) {
        fprintf(stderr, "Response failed to write.\n");
    }
    sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
}

cJSON* get_response(char* request_msg) {
    const char* http_req = "POST mail HTTP/1.0\nContent-Length:0\n\n";
    const int http_req_len = strlen(http_req);
    cJSON* request_obj;

    request_obj = cJSON_Parse(request_msg+http_req_len);
    // this method cannot do any pre-handling of requests
    // if the request is bad, the handler should identify this
    // and submit a reasonably created JSON error response
    return get_response_obj(request_obj);
}

char* create_response_msg(cJSON* response) {
    char* response_msg, responsetypechar;
    char* response_bytes;
    const char* http_part = "HTTP/1.0 200 OK\nContent-Length:0\nConnection:close\n\n";
    const int http_len = strlen(http_part);
    int msglen;
    char* error_msg_len = "{\"status_code\":413, \"response_type\":0, \"content\":{\"response_type\":0, \"message\":\"Return content exceeded maximum permitted length\"}}";

    // as we MUST return something, we return the error message if the content is too large
    response_msg = cJSON_PrintUnformatted(response);
    msglen = strnlen(response_msg, MAX_MSG_LEN);
    if (msglen == MAX_MSG_LEN) {
        free(response_msg);
        fprintf(stderr, "Message is too long.\n");
        response_msg = calloc(sizeof(char), strlen(error_msg_len)+1+http_len);
        strcpy(response_msg, http_part);
        strcat(response_msg, error_msg_len);
        responsetypechar = (char)cJSON_GetObjectItemCaseSensitive(response, "response_type")->valueint;
        memset(response_msg+36, responsetypechar, 1);
        memset(response_msg+66, responsetypechar, 1);
    }
    response_bytes = calloc(sizeof(char), msglen+http_len+1);
    strcpy(response_bytes, http_part);
    strcat(response_bytes, response_msg);
    free(response_msg);
    return response_bytes;
}

#pragma clang diagnostic pop