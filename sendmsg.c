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

#define MAX_NUMBER_RECIPIENTS 1000

/* 
 * Program arugments:
 * Usernames: an arbitrary (within reasonable bound) number of usernames
 * Ex) "name1,name2,name3" 
 * Server URL: string
 * Port No: int, optional
 */

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
    for (recipientsString = strtok(recipientsString, delims); recipientsString && n < MAX_NUMBER_RECIPIENTS; recipientsString = strtok(NULL, delims)){
        strcpy(recipients[n++], recipientsString);
    }  

    // Create Request 1
    int requestType = 3;
    cJSON *recipientsJSON = cJSON_CreateArray();;
    cJSON *request1 = cJSON_CreateObject();
    cJSON *content = cJSON_CreateObject();
    cJSON_AddStringToObject(request1, "url", url);
    cJSON_AddNumberToObject(request1, "port-no", portNumber);
    cJSON_AddNumberToObject(request1, "request-type", requestType);
    cJSON_AddItemToObject(request1, "content", content);
    cJSON_AddNumberToObject(content, "request-type", requestType);
    cJSON_AddStringToObject(content, "username", username);

    // Add all recipients
    for (size_t index = 0; index < n; index++){
        cJSON *recipientJSON = cJSON_CreateObject();
        cJSON_AddStringToObject(recipientJSON, "username", recipients[index]);
        cJSON_AddItemToArray(recipientsJSON, recipientJSON);
    }
    
    cJSON_AddItemToObject(content, "recipients", recipientsJSON);
    cJSON_AddStringToObject(content, "certificate", certContent);

    // Create variables for CMS
    BIO *in = NULL, *out = NULL, *certBIO = NULL, *keyBIO = NULL; 
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    CMS_ContentInfo *cms = NULL;
    int flags = 0;
    
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Read in signer certficate and private key
    certBIO = BIO_new_file("./certs/cert.pem", "r");
    keyBIO = BIO_new_file("./keys/private.pem", "r"); 
    if (!certBIO){
	    goto err;
    } 
    if (!keyBIO){
        goto err;
    }
    
    cert = PEM_read_bio_X509(certBIO, NULL, 0, NULL);
    key = PEM_read_bio_PrivateKey(keyBIO, NULL, 0, NULL);

    if (!cert){
        goto err;
    }
    if (!key){
        goto err;
    }
 
    // Read from certificate
    in = BIO_new_file("./certs/cert.pem", "r");
    
    // Sign message
    cms = CMS_sign(cert, key, NULL, in, flags);
    if (!cms){
        goto err;
    }

    out = BIO_new_file("sign.txt", "w");
    if (!out){
        goto err;
    }

    if (!SMIME_write_CMS(out, cms, in, flags)){
	    goto err;
    }

    char *signature;

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
    }

    // Add signature to content
    cJSON_AddStringToObject(content, "signature", signature);

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
	    CMS_ContentInfo_free(cms);
        X509_free(cert);
        EVP_PKEY_free(key);
        BIO_free(in);
        BIO_free(out);
        BIO_free(certBIO);
        BIO_free(keyBIO);
        ERR_free_strings();
        CRYPTO_cleanup_all_ex_data();
        ERR_remove_state(0);
        EVP_cleanup();
        return -1;
    }
   
    // Get certificates
    cJSON *certsRes1 = cJSON_GetObjectItemCaseSensitive(contentRes1, "certificates");

    // Sign message
    BIO *msg = BIO_new_fp(stdin, BIO_NOCLOSE);
    CMS_ContentInfo *cmsMsg = NULL;
    cmsMsg = CMS_sign(cert, key, NULL, msg, flags);
    BIO *outMsg = BIO_new_file("msg.txt", "w");
    SMIME_write_CMS(outMsg, cmsMsg, msg, flags);

    char *msgContent;

    // Get signed message
    {
        FILE *msgFile = fopen("msg.txt", "r");
        fseek(msgFile, 0, SEEK_END);
        long fsizeMsg = ftell(msgFile);
        fseek(msgFile, 0, SEEK_SET);
        msgContent = (char*) calloc(1, fsizeMsg + 1);
        fread(msgContent, 1, fsizeMsg, msgFile);
        fclose(msgFile);
    }

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
        cJSON_AddNumberToObject(request2, "port-no", portNumber);
	    cJSON_AddNumberToObject(request2, "request-type", requestTypeR2);
        cJSON_AddItemToObject(request2, "content", contentR2);
    	cJSON_AddNumberToObject(contentR2, "request-type", requestTypeR2);
	    cJSON_AddItemToObject(contentR2, "certificate", certRes1JSON);
    	cJSON_AddStringToObject(contentR2, "username", username);
        cJSON *recpRes1JSON = cJSON_DetachItemFromObjectCaseSensitive(subCert, "username");
        cJSON_AddItemToObject(contentR2, "recipient", recpRes1JSON);

        // Add encrypted and signed message
        cJSON_AddStringToObject(contentR2, "message", msgContent);

	    // Add signature
	    cJSON_AddStringToObject(contentR2, "signature", signature);
       
        // Send Request 2
        response2JSON = send_request(request2);

        // Get content
    	cJSON *contentRes2 = cJSON_DetachItemFromObjectCaseSensitive(response2JSON, "content"); 

        // Check for response status code
        char* response2Code = cJSON_Print(cJSON_GetObjectItemCaseSensitive(response2JSON, "status-code"));

        if (strcmp(response2Code, "200") != 0){
            char *errorMsg2 = cJSON_Print(cJSON_GetObjectItemCaseSensitive(contentRes2, "error_msg"));
            fprintf(stderr, "ERROR: %s\n", errorMsg2);
            cJSON_Delete(response1JSON);
            cJSON_Delete(response2JSON);
            cJSON_Delete(request2);
            cJSON_Delete(contentRes1);
	        cJSON_Delete(contentRes2);
            free(errorMsg2);
            free(response1Code);
            free(response2Code);
            free(signature);
            free(msgContent);
    	    CMS_ContentInfo_free(cms);
	        CMS_ContentInfo_free(cmsMsg);
            X509_free(cert);
            EVP_PKEY_free(key);
            BIO_free(in);
            BIO_free(out);
            BIO_free(certBIO);
            BIO_free(keyBIO);
	        BIO_free(msg);
            BIO_free(outMsg);
            ERR_free_strings();
            CRYPTO_cleanup_all_ex_data();
            ERR_remove_state(0);
            EVP_cleanup();
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
    } 

    // Free/Delete everything
    free(signature);
    free(response1Code);
    free(msgContent);
    cJSON_Delete(response1JSON);
    cJSON_Delete(contentRes1);
    CMS_ContentInfo_free(cms);
    CMS_ContentInfo_free(cmsMsg);
    X509_free(cert);
    EVP_PKEY_free(key);
    BIO_free(in);
    BIO_free(out);
    BIO_free(certBIO);
    BIO_free(keyBIO);
    BIO_free(msg);
    BIO_free(outMsg);
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
    EVP_cleanup();
    return 1;

    err:
        fprintf(stderr, "ERROR: ");
        ERR_print_errors_fp(stderr);
	    cJSON_Delete(request1);
	    CMS_ContentInfo_free(cms);
        X509_free(cert);
        EVP_PKEY_free(key);
        BIO_free(in);
        BIO_free(out);
        BIO_free(certBIO);
        BIO_free(keyBIO);
        ERR_free_strings();
        CRYPTO_cleanup_all_ex_data();
        ERR_remove_state(0);
        EVP_cleanup();
        return -1;
}
