#include <stdio.h>
#include <string.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "assertion.h"
#include "config.h"
#include "oidc_client.h"

#define CONFIG_PATH "/etc/kcoidc/kcoidc.conf"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char* argv[])
{
    #ifdef KC_VERBOSE
    FILE* log = fopen("/var/log/pam.log", "a+");
    fseek(log, 0, SEEK_SET);

    fprintf(log, "Attempting to authenticate.\n");
    fflush(log);
    #endif

    // Get the user name
    const char* user;
    int retval = pam_get_user(pamh, &user, NULL);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }

    // Get the password
    const char* password;
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }

    #ifdef KC_VERBOSE
    fprintf(log, "Username: %s\nPassword: %s\n", user, password);
    fflush(log);
    #endif

    struct config config;
    read_config(CONFIG_PATH, &config);

    char oidcConfigUri[2048];
    sprintf(oidcConfigUri, "%s/realms/%s/.well-known/openid-configuration", config.kcBaseUri, config.realm);

    char kcUsersEndpointUri[2048];
    sprintf(kcUsersEndpointUri, "%s/admin/realms/%s/users", config.kcBaseUri, config.realm);

    char *tokenEndpointUri = NULL, *jwksUri = NULL;
    get_oidc_uris(oidcConfigUri, &tokenEndpointUri, &jwksUri);

    //
    // ROPC ID Token
    //

    char* assertion = NULL;
    if (get_assertion_new(config.derPath, config.clientId, tokenEndpointUri, &assertion))
    {
        #ifdef KC_VERBOSE
        fprintf(log, "Generated assertion.\n");
        fflush(log);
        #endif

        char* idTokenString = NULL;
        if (get_ropc_id_token_new(tokenEndpointUri, config.clientId, assertion, user, password, &idTokenString))
        {
            #ifdef KC_VERBOSE
            fprintf(log, "Acquired ID Token.\n");
            fflush(log);
            #endif

            // Validate Token

            struct user_representation idToken = {};
            if (get_validated_id_token_new(jwksUri, idTokenString, &idToken))
            {
                #ifdef KC_VERBOSE
                fprintf(log, "Validated ID Token.\n");
                fflush(log);
                #endif

                id_token_free(idToken);

                #ifdef KC_VERBOSE
                fprintf(log, "Authentication successful.\n");
                fclose(log);
                #endif

                return PAM_SUCCESS;
            }

            free(idTokenString);
        }

        free(assertion);
    }

    return PAM_AUTH_ERR;
}

int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char* argv[])
{
    return PAM_SUCCESS;
}
