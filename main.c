#include <stdio.h>
#include <stdlib.h>
#include "send_request.h"

int main() {
    char* json;
    char request_content[100000] = {0};
    FILE* f;
    f = fopen("mock_request.json", "r");
    fread(request_content, sizeof(char), 100000, f);
    cJSON* mock_request = cJSON_Parse(request_content);
    cJSON* response;
    response = send_request(mock_request);
    if (response == NULL) {
        cJSON_Delete(mock_request);
        printf("No response.\n");
        return 0;
    }
    json = cJSON_Print(response);
    printf(json);
    // make sure you deallocate objects when finished
    cJSON_Delete(response);
    cJSON_Delete(mock_request);
    free(json);
}
