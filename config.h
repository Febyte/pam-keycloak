#include <stdbool.h>

struct config
{
    char mapPath[1024];
    char derPath[1024];
    char tokenCachePath[1024];
    char kcBaseUri[1024];
    char realm[512];
    char clientId[512];
};

bool read_config(const char* path, struct config* configOut);
