#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <pwd.h>

// For fchmod
#include <sys/stat.h>

// For crc32
#include <zlib.h>

#include "uidmapper.h"

// Example of a line in the database:
// 22062a42-ec22-4cd2-98a3-d75e5ccd8278 4294967295

bool map_uuid_to_uid(const char* mapperPath, uuid_t uuid, uid_t* uidOut)
{
    FILE* mappingFile = fopen(mapperPath, "a+");
    if (mappingFile == NULL)
    {
        return false;
    }

    // Change permissions to 600.
    fchmod(fileno(mappingFile), S_IRUSR | S_IWUSR);

    // JAS: NOTE: POSIX does not specify what the initial position will be in "a+" mode. Seek to the beginning.
    fseek(mappingFile, 0, SEEK_SET);

    while (true)
    {
        char guidString[37];
        uid_t uid;

        int elementsScanned = fscanf(mappingFile, "%s %u\n", guidString, &uid);
        if (elementsScanned == 2)
        {
            uuid_t foundUuid = {};
            if (!uuid_parse(guidString, foundUuid))
            {
                if (!uuid_compare(foundUuid, uuid))
                {
                    // Found it!
                    *uidOut = uid;
                    fclose(mappingFile);

                    return true;
                }
            }
            else
            {
                // Unable to parse UUID.
                fclose(mappingFile);
                return false;
            }
        }
        else
        {
            if (feof(mappingFile))
            {
                // Create a new record.

                uint32_t newUid = crc32(0, (void*)uuid, 16);

                // Check to see if we have a collision with passwd.
                // JAS: TODO: Check to ensure this will search our own database for collisions as well, by virtue of being in NSS.
                struct passwd* pw = getpwuid(uid);
                if (pw != NULL)
                {
                    // Iterate the New UID until we find one that's free.
                    while (getpwuid(++newUid) != NULL)
                    {
                        if (newUid == UINT32_MAX)
                        {
                            return false;
                        }
                    }
                }

                uuid_unparse(uuid, guidString);
                fprintf(mappingFile, "%s %u\n", guidString, newUid);
                fclose(mappingFile);

                *uidOut = newUid;

                return true;
            }
            else
            {
                // Something went wrong with fscanf.

                fclose(mappingFile);
                return false;
            }
        }
    }

    fclose(mappingFile);

    return true;
}

bool map_uid_to_uuid(const char* mapperPath, uid_t uid, uuid_t uuidOut)
{
    FILE* mappingFile = fopen(mapperPath, "r");
    if (mappingFile == NULL)
    {
        return false;
    }

    while (true)
    {
        char guidString[37];
        uid_t foundUid;

        int elementsScanned = fscanf(mappingFile, "%s %u\n", guidString, &foundUid);
        if (elementsScanned == 2)
        {
            if (uid == foundUid)
            {
                if (!uuid_parse(guidString, uuidOut))
                {
                    fclose(mappingFile);
                    return true;
                }
            }
        }
        else
        {
            break;
        }
    }

    fclose(mappingFile);
    return false;
}
