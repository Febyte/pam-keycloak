#include <stdbool.h>

#include <linux/limits.h>

struct config
{
    char pemPath[PATH_MAX];
    int shaBits;
    char tokenCachePath[PATH_MAX];
    char kcBaseUri[256];
    char realm[256];
    char clientId[256];
};

bool read_config(const char* path, struct config* configOut);
