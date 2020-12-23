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
    fclose(certFile);

    // Sign certificate using client's private key
    system("openssl smime -sign -in ./certs/cert.pem -signer ./certs/cert.pem -inkey ./keys/key.pem -out sign.txt -text");
     
    char *signature;

    // Get signature
    {
        FILE *req1Sign;
        req1Sign = fopen("sign.txt", "r");

        if (req1Sign == NULL){
            printf("ERROR: Unable to get signature\n");            
            return -1;
        }

        fseek(req1Sign, 0, SEEK_END);
        long fsizeR1 = ftell(req1Sign);
        fseek(req1Sign, 0, SEEK_SET);
        signature = (char*) calloc(1, fsizeR1 + 1);
        fread(signature, 1, fsizeR1, req1Sign);
        fclose(req1Sign);   
	
	    // Check for signature
        if (strlen(signature) == 0){
            printf("ERROR: Unable to get signature\n");
            free(signature);
            return -1;
        }        
        remove("sign.txt"); 
    }

    // Get username
    struct passwd *pwd;
    pwd = getpwuid(getuid()); 
    char *username = pwd->pw_name;

    // Get URL
    char *url = argv[1];

    // Get port number
    int portNumber = 443;
    if (argc == 3){
        portNumber = atoi(argv[2]);
    }

    // Create request
    int requestType = 5;
    cJSON *request1 = cJSON_CreateObject();
    cJSON *content = cJSON_CreateObject();
    cJSON_AddStringToObject(request1, "url", url);
    cJSON_AddNumberToObject(request1, "port_no", portNumber);
    cJSON_AddNumberToObject(request1, "request_type", requestType);
    cJSON_AddStringToObject(content, "certificate", certContent);
    cJSON_AddItemToObject(request1, "content", content);
    cJSON_AddNumberToObject(content, "request_type", requestType);
    cJSON_AddStringToObject(content, "username", username);

    // Add signature to content
    cJSON_AddStringToObject(content, "signature", signature);

    char *request1String = cJSON_Print(request1);
    free(request1String);

    // Invoke send_request and get response
    cJSON* response1JSON = NULL;
    response1JSON = send_request(request1);
    cJSON_Delete(request1);

    // Get content
    cJSON *contentRes1 = cJSON_DetachItemFromObjectCaseSensitive(response1JSON, "content"); 

    // Check for response status code
    char* response1Code = cJSON_Print(cJSON_GetObjectItemCaseSensitive(response1JSON, "status_code"));

    if (strcmp(response1Code, "200") != 0){
        char *errorMsg = cJSON_Print(cJSON_GetObjectItemCaseSensitive(contentRes1, "error_msg"));
        fprintf(stderr, "ERROR: %s\n", errorMsg);
        cJSON_Delete(response1JSON);
        cJSON_Delete(contentRes1);
        free(errorMsg);
        free(signature);
        free(response1Code);
        return -1;
    }

    // Get sender certificate
    cJSON *certRes1 = cJSON_GetObjectItemCaseSensitive(contentRes1, "sender_certificate");
    char *senderCert = certRes1->valuestring;

    // Create temporary certificate file
    FILE *certOutput = fopen("sendCert.pem", "w");
    fprintf(certOutput, "%s", senderCert);
    fclose(certOutput);

    // Get encrypted message
    cJSON *msgRes1 = cJSON_GetObjectItemCaseSensitive(contentRes1, "message");
    char *msg = msgRes1->valuestring;

    // Create temporary message file
    FILE *msgOutput = fopen("encrypted.txt", "w");
    fprintf(msgOutput, "%s", msg);
    fclose(msgOutput);

    // Decrypt message
    system("openssl smime -decrypt -in encrypted.txt -out unencrypted.txt -recip ./certs/cert.pem -inkey keys/key.pem");

    char *decrypted;

    // Check if decryption worked
    {
        FILE *decFp;
        decFp = fopen("unencrypted.txt", "r");

        if (decFp == NULL){
            printf("ERROR: Unable to decrypt\n"); 
	    free(signature);
            free(response1Code);
            cJSON_Delete(response1JSON);
            cJSON_Delete(contentRes1); 
            return -1;
        }

        fseek(decFp, 0, SEEK_END);
        long fsizeR1 = ftell(decFp);
        fseek(decFp, 0, SEEK_SET);
        decrypted = (char*) calloc(1, fsizeR1 + 1);
        fread(decrypted, 1, fsizeR1, decFp);
        fclose(decFp);   
	
        if (strlen(decrypted) == 0){
            printf("ERROR: Unable to decrypt\n");
            free(decrypted);
	    free(signature);
            free(response1Code);
            cJSON_Delete(response1JSON);
            cJSON_Delete(contentRes1);
            return -1;
        }        
    }

    // Verify message
    fprintf(stdout, "Verifying message...\n");
    system("openssl smime -verify -noverify -in unencrypted.txt -signer sendCert.pem -out verifiedMsg.txt");
    
    char *message;

    // Get emssage 
    {
        FILE *msgFp;
        msgFp = fopen("verifiedMsg.txt", "r");

        if (msgFp == NULL){
            printf("ERROR: Unable to get message\n"); 
	        ree(signature);
            free(response1Code);
	        free(decrypted);
            cJSON_Delete(response1JSON);
            cJSON_Delete(contentRes1); 
            return -1;
        }

        fseek(msgFp, 0, SEEK_END);
        long fsizeMsg = ftell(msgFp);
        fseek(msgFp, 0, SEEK_SET);
        message = (char*) calloc(1, fsizeMsg + 1);
        fread(message, 1, fsizeMsg, msgFp);
        fclose(msgFp);   
	
        if (strlen(decrypted) == 0){
            printf("ERROR: Unable to get message\n");
            free(decrypted);
	        free(signature);
            free(message);
            free(decrypted);
            free(response1Code);
            cJSON_Delete(response1JSON);
            cJSON_Delete(contentRes1);
            return -1;
        }      
       
        remove("verifiedMsg.txt"); 
    }    

    // Print message
    fprintf(stdout, "\n%s\n", message);

    // Free/Delete everything
    free(signature);
    free(response1Code);
    free(message);
    free(decrypted);
    cJSON_Delete(response1JSON);
    cJSON_Delete(contentRes1);
    remove("encrypted.txt");
    remove("unencrypted.txt");
    remove("sendCert.pem");
    return 1;
}
