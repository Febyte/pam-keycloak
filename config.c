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

    char line[1024] = {};
    while (!feof(config))
    {
        fscanf(config, "%s\n", line);

        const char* key = strtok(line, "=");
        const char* value = strtok(NULL, "=");

        if (!strcmp(key, "map_path"))
        {
            strcpy(configOut->mapPath, value);
        }
        else if (!strcmp(key, "der_path"))
        {
            strcpy(configOut->derPath, value);
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
