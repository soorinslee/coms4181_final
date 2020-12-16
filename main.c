#include <stdio.h>
#include <stdlib.h>
#include "send_request.h"

int main() {
    char* json;
    cJSON* mock_request = cJSON_Parse("{\"request_type\":1,\"url\":\"127.0.0.1\",\"port_no\":5000,\"content\":{\"request_type\":1,\"username\":\"username\",\"password\":\"password\"}}");
    cJSON* response;
    response = send_request(mock_request);
    json = cJSON_Print(response);
    printf(json);
    // make sure you deallocate objects when finished
    cJSON_Delete(response);
    cJSON_Delete(mock_request);
    free(json);
}
