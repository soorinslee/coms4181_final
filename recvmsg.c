#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include "cJSON.h"
#include "send_request.h"

int main(int argc, char *argv[]) {
    // Check for server URL
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Error: Incorrect number of arguments\n");
        return -1;
    }

    // Open client certificate
    FILE *certFile;
    certFile = fopen("./certs/cert.pem", "r");

    // Certificate not found; return error
    if (!certFile){
        fprintf(stderr, "Error: Client certificate not found\n");
        return -1;
    }

    // Read pem file and store
    fseek(certFile, 0, SEEK_END);
    long fsize = ftell(certFile);
    fseek(certFile, 0, SEEK_SET);
    char certContent[fsize + 1];
    memset(certContent, '\0', sizeof(certContent));
    fread(certContent, 1, fsize, certFile);
    //fprintf(stdout, "Cert: %s\n", cert);
    fclose(certFile);

    // Get username
    struct passwd *pwd;
    pwd = getpwuid(getuid()); 
    char *username = pwd->pw_name;
    //fprintf(stdout, "Username: %s\n", username);

    // Get URL
    char *url = argv[1];
    //fprintf(stdout, "URL: %s\n", url);

    // Get port number
    int portNumber = 443;
    if (argc == 3){
        portNumber = atoi(argv[2]);
    }
    //fprintf(stdout, "Port Number: %d\n", portNumber);

    // Create request
    int requestType = 5;
    cJSON *request1 = cJSON_CreateObject();
    cJSON *content = cJSON_CreateObject();
    cJSON_AddStringToObject(request1, "url", url);
    cJSON_AddNumberToObject(request1, "port-no", portNumber);
    cJSON_AddNumberToObject(request1, "request-type", requestType);
    cJSON_AddStringToObject(content, "certificate", certContent);
    cJSON_AddItemToObject(request1, "content", content);
    cJSON_AddNumberToObject(content, "request-type", requestType);
    cJSON_AddStringToObject(content, "username", username);

    // TODO: STORE SIGNATURE IN sign.txt
    
    // Get signature
    {
        FILE *req1Sign;
        req1Sign = fopen("sign.txt", "r");
        fseek(req1Sign, 0, SEEK_END);
        long fsizeR1 = ftell(req1Sign);
        fseek(req1Sign, 0, SEEK_SET);
        signature = (char*) calloc(1, fsizeR1 + 1);
        fread(signature, 1, fsizeR1, req1Sign);
        fclose(req1Sign);   
        remove("sign.txt"); 
    }

    // Add signature to content
    cJSON_AddStringToObject(content, "signature", signature);

    char *request1String = cJSON_Print(request1);
    printf("%s\n", request1String);
    free(request1String);

    // Invoke send_request and get response
    cJSON* response1JSON = NULL;
    response1JSON = send_request(request1);
    cJSON_Delete(request1);

    // Get content
    cJSON *contentRes1 = cJSON_DetachItemFromObjectCaseSensitive(response1JSON, "content"); 

    // Check for response status code
    char* response1Code = cJSON_Print(cJSON_GetObjectItemCaseSensitive(response1JSON, "status-code"));

    if (strcmp(response1Code, "200") != 0){
        char *errorMsg = cJSON_Print(cJSON_GetObjectItemCaseSensitive(contentRes1, "error_msg"));
        fprintf(stderr, "ERROR: %s\n", errorMsg);
        cJSON_Delete(response1JSON);
        free(errorMsg);
        free(response1Code);
        return -1;
    }

    // Get sender certificate
    cJSON *certRes1 = cJSON_GetObjectItemCaseSensitive(contentRes1, "sender-certificate");
    char *senderCert = cJSON_Print(certRes1);

    // Create temporary certificate file
    FILE *certOutput = fopen("cert.pem", "w");
    fprintf(certOutput, "%s\n", senderCert);

    // Get encrypted message
    cJSON *msgRes1 = cJSON_GetObjectItemCaseSensitive(contentRes1, "message");
    char *msg = cJSON_Print(msgRes1);

    // Create temporary message file
    FILE *msgOutput = fopen("msg.txt", "w");
    fprintf(msgOutput, "%s\n", msg);

    // TODO: VERIFY MESSSAGE

    // Free/Delete everything
    free(signature);
    free(response1Code);
    cJSON_Delete(response1JSON);
    cJSON_Delete(contentRes1);

    return 1;
}
