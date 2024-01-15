#include <stdbool.h>

#include <sys/types.h>

#include <uuid/uuid.h>

bool map_uuid_to_uid(const char* mapperPath, uuid_t uuid, uid_t* uidOut);
