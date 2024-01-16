#include <stdio.h>
#include <string.h>

#include "config.h"

bool read_config(const char* path, struct config* configOut)
{
    FILE* config = fopen(path, "r");

    if (config == NULL)
    {
        return false;
    }

    // PATH_MAX + Length of longest property
    char line[PATH_MAX + 17] = {};
    while (!feof(config))
    {
        fscanf(config, "%s\n", line);

        const char* key = strtok(line, "=");
        const char* value = strtok(NULL, "=");

        if (!strcmp(key, "der_path"))
        {
            strcpy(configOut->derPath, value);
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
