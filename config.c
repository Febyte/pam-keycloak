#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"

bool read_config(const char* path, struct config* configOut)
{
    FILE* config = fopen(path, "r");

    if (config == NULL)
    {
        return false;
    }

    configOut->shaBits = -1;

    // PATH_MAX + Length of longest property
    char line[PATH_MAX + 17] = {};
    while (!feof(config))
    {
        fscanf(config, "%s\n", line);

        const char* key = strtok(line, "=");
        const char* value = strtok(NULL, "=");

        if (!strcmp(key, "pem_path"))
        {
            strcpy(configOut->pemPath, value);
        }
        else if (!strcmp(key, "sha_bits"))
        {
            int shaBits = atoi(value);
            configOut->shaBits = shaBits;
        }
        else if (!strcmp(key, "token_cache_path"))
        {
            strcpy(configOut->tokenCachePath, value);
        }
        else if (!strcmp(key, "keycloak_base_uri"))
        {
            strcpy(configOut->kcBaseUri, value);
        }
        else if (!strcmp(key, "realm"))
        {
            strcpy(configOut->realm, value);
        }
        else if (!strcmp(key, "client_id"))
        {
            strcpy(configOut->clientId, value);
        }
    }

    return true;
}
