//
// Created by freddylukai on 12/14/20.
//

#include "get_server_certs.h"

void load_server_certs(SSL_CTX* ctx) {
    //for now, just fetch some certs from local storage
    SSL_CTX_load_verify_locations(ctx, "certs/ca-chain.pem", NULL);
    SSL_CTX_use_certificate_file(ctx, "certs/server.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM);
}