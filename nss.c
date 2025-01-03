#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "assertion.h"
#include "config.h"
#include "oidc_client.h"

#include <nss.h>

#define CONFIG_PATH "/etc/kcoidc/kcoidc.conf"

enum nss_status _nss_kcoidc_setpwent()
{
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_kcoidc_endpwent()
{
    return NSS_STATUS_SUCCESS;
}

void populate_passwd(struct user_representation* user, struct passwd* result, char* buffer)
{
    uintptr_t bufPos = (uintptr_t)buffer;

    result->pw_name = (char*)bufPos;
    strcpy(result->pw_name, user->userName);
    bufPos += strlen(user->userName) + 1;

    result->pw_passwd = (char*)bufPos;
    result->pw_passwd[0] = '*'; result->pw_passwd[1] = '\0';
    bufPos += 2;

    result->pw_uid = user->userId;
    result->pw_gid = user->groupId;

    result->pw_gecos = (char*)bufPos;
    strcpy(result->pw_gecos, user->displayName);
    bufPos += strlen(user->displayName) + 1;

    result->pw_dir = (char*)bufPos;
    strcpy(result->pw_dir, user->homePath);
    bufPos += strlen(user->homePath) + 1;

    result->pw_shell = (char*)bufPos;
    strcpy(result->pw_shell, user->shellPath);
}

enum nss_status _nss_kcoidc_getpwnam_r(const char* username, struct passwd* result, char* buffer, size_t buflen, int* errnop)
{
    #ifdef KC_VERBOSE
    printf("_nss_kcoidc_getpwnam_r: looking up user by username (%s)\n", username);
    #endif

    struct config config;
    read_config(CONFIG_PATH, &config);

    char oidcConfigUri[2048];
    sprintf(oidcConfigUri, "%s/realms/%s/.well-known/openid-configuration", config.kcBaseUri, config.realm);

    char kcUsersEndpointUri[2048];
    sprintf(kcUsersEndpointUri, "%s/admin/realms/%s/users", config.kcBaseUri, config.realm);

    char *tokenEndpointUri = NULL, *jwksUri = NULL;
    get_oidc_uris(oidcConfigUri, &tokenEndpointUri, &jwksUri);

    char* assertion = NULL;
    if (get_assertion_new(config.pemPath, config.shaBits, config.clientId, tokenEndpointUri, &assertion))
    {
        char* accessTokenString = NULL;
        if (get_service_account_access_token_new(config.tokenCachePath, tokenEndpointUri, config.clientId, assertion, &accessTokenString))
        {
            enum oidc_client_status validationResult = validate_access_token(jwksUri, accessTokenString);
            if (validationResult == OIDC_OK)
            {
                struct user_representation user = {};
                if (get_user_representation_by_username_new(kcUsersEndpointUri, accessTokenString, username, &user))
                {
                    populate_passwd(&user, result, buffer);

                    id_token_free(user);

                    *errnop = NSS_STATUS_SUCCESS;
                    return NSS_STATUS_SUCCESS;
                }
            }

            free (accessTokenString);
        }

        free(assertion);
    }

    return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_kcoidc_getpwuid_r(uid_t uid, struct passwd* result, char* buffer, size_t buflen, int* errnop)
{
    #ifdef KC_VERBOSE
    printf("_nss_kcoidc_getpwuid_r: looking up user by uid (%u)\n", uid);
    #endif

    struct config config;
    read_config(CONFIG_PATH, &config);

    char oidcConfigUri[2048];
    sprintf(oidcConfigUri, "%s/realms/%s/.well-known/openid-configuration", config.kcBaseUri, config.realm);

    char kcUsersEndpointUri[2048];
    sprintf(kcUsersEndpointUri, "%s/admin/realms/%s/users", config.kcBaseUri, config.realm);

    char *tokenEndpointUri = NULL, *jwksUri = NULL;
    get_oidc_uris(oidcConfigUri, &tokenEndpointUri, &jwksUri);

    char* assertion = NULL;
    if (get_assertion_new(config.pemPath, config.shaBits, config.clientId, tokenEndpointUri, &assertion))
    {
        char* accessTokenString = NULL;
        if (get_service_account_access_token_new(config.tokenCachePath, tokenEndpointUri, config.clientId, assertion, &accessTokenString))
        {
            enum oidc_client_status validationResult = validate_access_token(jwksUri, accessTokenString);
            if (validationResult == OIDC_OK)
            {
                struct user_representation user = {};
                if (get_user_representation_by_id_new(kcUsersEndpointUri, accessTokenString, uid, &user))
                {
                    populate_passwd(&user, result, buffer);

                    id_token_free(user);

                    *errnop = NSS_STATUS_SUCCESS;
                    return NSS_STATUS_SUCCESS;
                }
            }

            free (accessTokenString);
        }

        free(assertion);
    }

    return NSS_STATUS_UNAVAIL;
}