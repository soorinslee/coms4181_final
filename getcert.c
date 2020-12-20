#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <time.h> 
#include "sha256.h"
#include "cJSON.h"
#include "send_request.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

BYTE password[SHA256_BLOCK_SIZE];
char username[999];
char url[999];
int port_no = 443;
char password_string[999];


int hex_to_string(BYTE str[]) {

    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
        sprintf(password_string + i * 2, "%02x", str[i]);
 
    printf("%s\n",password_string);
 
    return 0;
}

void print_hex(BYTE str[], int len)
{
	int idx;
	char password_string[len];

	for(idx = 0; idx < len; idx++)
		printf("%02x", str[idx]);
		password_string[idx] = str[idx];
	//printf("Password String is %s", password_string);
}


int hashpassword(char *  input){
	//printf("hashing");
	SHA256_CTX ctx;
	sha256_init(&ctx);
	for (int idx = 0; idx < 100000; ++idx)
		sha256_update(&ctx, input, strlen(input));
	sha256_final(&ctx, password);
	print_hex(password,SHA256_BLOCK_SIZE);
}
cJSON* cjson_request(char * public_key){

   char *out;
   cJSON *root, *content;
   cJSON *request_type = NULL;

   /* create root node and array */
   root = cJSON_CreateObject();
   content = cJSON_CreateObject();

   cJSON_AddItemToObject(root, "url", cJSON_CreateString(url));
   cJSON_AddItemToObject(root, "port_no", cJSON_CreateNumber(port_no));
   cJSON_AddItemToObject(root, "request_type", cJSON_CreateNumber(1));
   
   /* add cars array to root */
   cJSON_AddItemToObject(root, "content", content);

   cJSON_AddItemToObject(content, "request_type", cJSON_CreateNumber(1));
   cJSON_AddItemToObject(content, "username", cJSON_CreateString(username));
   cJSON_AddItemToObject(content, "password", cJSON_CreateString(password_string));
   cJSON_AddItemToObject(content, "public_key", cJSON_CreateString(public_key));

   /* print everything */
   //out = cJSON_Print(root);
   //printf("%s\n", out);
   //free(out);

   /* free all objects under root and root itself */
   //cJSON_Delete(root);

   return root;
}

int save_certificate(char *certificate_string){

   char ch;
   FILE *fpw;
   fpw = fopen("certs/cert.pem","w");

   if(fpw == NULL)
   {
      printf("Error");   
      exit(1);             
   }

   fprintf(fpw, "%s", certificate_string);

   //fputc(string, fpw);
   //fprintf(fpw,"%c",ch);
   fclose(fpw);

   return 0;
}

int parse_response(cJSON *root){
	int i;
	cJSON *elem;
	cJSON *status_code;
	cJSON *content;
	cJSON *response_type;
	cJSON *certificate;
	printf("%s\n", cJSON_Print(root));
	//char *json_string = "[{\"id\":\"25139\",\"date\":\"2016-10-27\",\"name\":\"Komfy Switch With Camera DKZ-201S\\/W Password Disclosure\"},{\"id\":\"25117\",\"date\":\"2016-10-24\",\"name\":\"NETDOIT weak password Vulnerability\"}]";
	//char *json_string = "[{\"status_code\":300,\"response_type\":1,\"content\":{\"response_type\":null,\"certificate\":\"null\"}}]";
	//cJSON *root = cJSON_Parse(json_string);
	int n = cJSON_GetArraySize(root);
	status_code = cJSON_GetObjectItem(root, "status_code");
	printf("%d\n", status_code->valueint);
	content = cJSON_GetObjectItemCaseSensitive(root, "content");
	response_type = cJSON_GetObjectItemCaseSensitive(root, "response_type");
	certificate = cJSON_GetObjectItemCaseSensitive(content, "certificate");
	if (status_code->valueint <= 299 && status_code->valueint >= 200){
		if(cJSON_IsNumber(response_type) && certificate->valuestring !=NULL){
			save_certificate(certificate->valuestring);
			printf("saved certificate");

		}
		else{
			fprintf(stderr, "Error code: No certificate Error");
			exit(1);

		}

	}

	else{
		fprintf(stderr, "Error code:%d\n", status_code->valueint);
		exit(1);

	}


}


int main(int argc, char *argv[])
{
	char* json;
	cJSON* request = NULL;
    cJSON* response;

	if (argc < 3){
	printf("\nError: Wrong commandline.\n");
	printf("\n");
	return -1;
	}

    char *buffer = NULL;
    char tmp[99];
    size_t bufsize = 999;
    size_t characters;

    strcpy (username,argv[1]);
    strcpy (url,argv[2]);

    if(argv[3] != NULL){
    	strcpy (tmp,argv[3]);
		sscanf(tmp, "%d", &port_no);
    }


    printf("password: ");
    characters = getline(&buffer,&bufsize,stdin);
    //printf("%zu characters were read.\n",characters);
    //printf("You typed:%s",buffer);

    hashpassword(buffer);
    hex_to_string(password);
    
    char public_key[10000] = {0};
	 FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    char * command = calloc(sizeof(char), 1024);
    strcpy(command, "./generate_key.sh ");
    strcat(command, username);

    int status = system(command);

    fp = fopen("csr/csr.pem", "r");
    if (fp == NULL){
        exit(EXIT_FAILURE);
    }

    fread(public_key, sizeof(char), 10000, fp);

    fclose(fp);

    
    //readfile();
    request = cjson_request(public_key);
    //json = cJSON_Print(request);
    //printf("%s\n", json);

    response = send_request(request);
    //json = cJSON_Print(response);
    //printf("%s\n", json);
    // make sure you deallocate objects when finished


    //save_certificate(certificate_string);
    parse_response(response);

    cJSON_Delete(response);
    free(json);



    //har *response = "{\"status_code\":200,\"response_type\":1,\"content\":{\"response_type\":1,\"certificate\":\"string\"}}"

    
    return(0);
}