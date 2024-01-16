#include <stdbool.h>

#include <linux/limits.h>

struct config
{
    char derPath[PATH_MAX];
    char tokenCachePath[PATH_MAX];
    char kcBaseUri[1024];
    char realm[512];
    char clientId[512];
};

bool read_config(const char* path, struct config* configOut);
