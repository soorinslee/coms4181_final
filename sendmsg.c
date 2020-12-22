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
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include "cJSON.h"
#include "send_request.h"

#define MAX_NUMBER_RECIPIENTS 1024
#define BUF_SIZE 1024

int main(int argc, char *argv[]) {
    // Check for usernames and server URL
    if (argc < 3 || argc > 4) {
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
    system("openssl dgst -sign ./keys/key.pem -passin pass:password -keyform PEM -sha256 -out sign.txt -binary ./certs/cert.pem");
     
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

    // Convert signature to hex
    char signHex[strlen(signature)*3];
    memset(signHex,0,sizeof(signHex));
 
    int i, j;
    for(i=0, j=0; i<strlen(signature); i++, j+=2)
    { 
        sprintf((char*)signHex+j,"%02X",signature[i]);
    }
    signHex[j]='\0';

    // Get username
    struct passwd *pwd;
    pwd = getpwuid(getuid()); 
    char *username = pwd->pw_name;

    // Get URL
    char *url = argv[2];

    // Get port number
    int portNumber = 443;
    if (argc == 4){
        portNumber = atoi(argv[3]);
    }

    // Create array of recipients
    char recipients[MAX_NUMBER_RECIPIENTS][strlen(argv[1])];
    char *recipientsString = argv[1];
    const char *delims = ",\n";
    size_t n = 0;
    for (recipientsString = strtok(recipientsString, delims); recipientsString && n < MAX_NUMBER_RECIPIENTS; recipientsString = strtok(NULL, delims))    {
        strcpy(recipients[n++], recipientsString);
    }  

    // Create Request 1
    int requestType = 3;
    cJSON *recipientsJSON = cJSON_CreateArray();;
    cJSON *request1 = cJSON_CreateObject();
    cJSON *content = cJSON_CreateObject();
    cJSON_AddStringToObject(request1, "url", url);
    cJSON_AddNumberToObject(request1, "port_no", portNumber);
    cJSON_AddNumberToObject(request1, "request_type", requestType);
    cJSON_AddItemToObject(request1, "content", content);
    cJSON_AddNumberToObject(content, "request_type", requestType);
    cJSON_AddStringToObject(content, "username", username);

    // Add all recipients
    for (size_t index = 0; index < n; index++){
        cJSON_AddItemToArray(recipientsJSON, cJSON_CreateString(recipients[index]));
    }
    
    cJSON_AddItemToObject(content, "recipients", recipientsJSON);
    cJSON_AddStringToObject(content, "certificate", certContent);

    // Add signature to content
    cJSON_AddStringToObject(content, "signature", signHex);

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
        free(response1Code);
        free(signature);
        return -1;
    }
   
    // Get certificates
    cJSON *certsRes1 = cJSON_GetObjectItemCaseSensitive(contentRes1, "certificates");

    // Get message from stdin
    FILE *msgFp = fopen("msgUnencrypted.txt", "w");
    int read;
    char *msgCont[BUF_SIZE];

    while ((read = fread(msgCont, 1, BUF_SIZE, stdin))) {
        fwrite(msgCont, read, 1, msgFp);
    }
 
    fclose(msgFp);

    // Sign message
    system("openssl smime -sign -in msgUnencrypted.txt -out msgSigned.txt -signer ./certs/cert.pem -inkey ./keys/key.pem -text");
    
    remove("msgUnencrypted.txt");

    cJSON *request2;
    cJSON *response2JSON;
 
    for (int i = 0 ; i < cJSON_GetArraySize(certsRes1) ; i++){
	    // Create Request 2
        request2 = cJSON_CreateObject();
        cJSON *subCert = cJSON_GetArrayItem(certsRes1, i);
	    cJSON *certRes1JSON = cJSON_DetachItemFromObjectCaseSensitive(subCert, "certificate");
        int requestTypeR2 = 4;
        cJSON *contentR2 = cJSON_CreateObject();
        cJSON_AddStringToObject(request2, "url", url);
        cJSON_AddNumberToObject(request2, "port_no", portNumber);
	    cJSON_AddNumberToObject(request2, "request_type", requestTypeR2);
        cJSON_AddItemToObject(request2, "content", contentR2);
    	cJSON_AddNumberToObject(contentR2, "request_type", requestTypeR2);
	    cJSON_AddItemToObject(contentR2, "certificate", certRes1JSON);
    	cJSON_AddStringToObject(contentR2, "username", username);
        cJSON *recpRes1JSON = cJSON_DetachItemFromObjectCaseSensitive(subCert, "username");
        cJSON_AddItemToObject(contentR2, "recipient", recpRes1JSON);

	    // Store recipient's certificate in a file
        FILE *recpCertFile = fopen("recpCert.pem", "w");
        char *recpCertString = certRes1JSON->valuestring;
	    fprintf(recpCertFile, "%s", recpCertString);
        fclose(recpCertFile);

    	// Encrypt message
 	    system("openssl smime -encrypt -out msg.txt -in msgSigned.txt recpCert.pem");

    	char *msgContent;

    	// Get signed and encrypted message
    	{
            FILE *msgFile = fopen("msg.txt", "r");
	   
	        if (msgFile == NULL){
	    	    printf("ERROR: Unable to get message\n");
                cJSON_Delete(response1JSON);
                cJSON_Delete(contentRes1);
                free(response1Code);
                free(signature);
                cJSON_Delete(request2);
                return -1;
            }

            fseek(msgFile, 0, SEEK_END);
            long fsizeMsg = ftell(msgFile);
            fseek(msgFile, 0, SEEK_SET);
            msgContent = (char*) calloc(1, fsizeMsg + 1);
            fread(msgContent, 1, fsizeMsg, msgFile);
            fclose(msgFile);

            // Check for signature
            if (strlen(msgContent) == 0){
                printf("ERROR: Unable to get message\n");
                cJSON_Delete(response1JSON);
                cJSON_Delete(contentRes1);
                free(response1Code);
                free(msgContent);
                free(signature);
                cJSON_Delete(request2);
                return -1;
            }        

    	}

	    // Convert message to hex
        char msgHex[strlen(msgContent)*3];
        memset(msgHex,0,sizeof(msgHex));
 
        int a, b;
        for(a=0, b=0; a<strlen(msgContent); a++, b+=2)
        { 
            sprintf((char*)msgHex+b,"%02X",msgContent[a]);
        }
        msgHex[j]='\0';

        // Add encrypted and signed message
        cJSON_AddStringToObject(contentR2, "message", msgHex);

        // Add signature
        cJSON_AddStringToObject(contentR2, "signature", signature);
       
        // Send Request 2
        response2JSON = send_request(request2);

        // Get content
    	cJSON *contentRes2 = cJSON_DetachItemFromObjectCaseSensitive(response2JSON, "content"); 

        // Check for response status code
        char* response2Code = cJSON_Print(cJSON_GetObjectItemCaseSensitive(response2JSON, "status_code"));

        if (strcmp(response2Code, "200") != 0){
            char *errorMsg2 = cJSON_Print(cJSON_GetObjectItemCaseSensitive(contentRes2, "error_msg"));
            fprintf(stderr, "ERROR: %s\n", errorMsg2);
            cJSON_Delete(response2JSON);
            cJSON_Delete(response1JSON);
            cJSON_Delete(request2);
            cJSON_Delete(contentRes1);
	        cJSON_Delete(contentRes2);
            free(response1Code);
            free(response2Code);
            free(signature);
            free(errorMsg2);
            free(msgContent);
            return -1;
        }
	
	    // Output delivery message
        char *recpSuccess = cJSON_Print(recpRes1JSON);
        fprintf(stdout, "Message to %s successfully delivered\n", recpSuccess);

        cJSON_Delete(request2);
        cJSON_Delete(response2JSON);
        cJSON_Delete(contentRes2);
    	free(response2Code);
        free(recpSuccess);
        free(msgContent);
        remove("recpCert.pem");
        remove("msg.txt");
    } 

    // Free/Delete everything
    free(signature);
    free(response1Code);
    cJSON_Delete(response1JSON);
    cJSON_Delete(contentRes1);
    remove("msgSigned.txt");
    return 1;
}
