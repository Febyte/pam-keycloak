#include <stdbool.h>

#include <sys/types.h>

#include <uuid/uuid.h>

#include <openssl/evp.h>

struct user_representation
{
    const char* userName;
    uuid_t subject;
    uid_t userId;
    gid_t groupId;
    const char* displayName;
    const char* homePath;
    const char* shellPath;
};

enum oidc_client_status
{
    OIDC_UNSPECIFIED_ERROR = 0,
    OIDC_OK = 1,
    OIDC_HTTP_INIT_FAILURE,
    OIDC_HTTP_REQUEST_FAILURE,
    OIDC_JWK_NOT_FOUND,
    OIDC_UNSUPPORTED_ALGORITHM,
    OIDC_INVALID_SIGNATURE
};

void global_init();

enum oidc_client_status get_oidc_uris(const char* oidcConfigUri, char** tokenEndpointUri, char** jwksUri);

enum oidc_client_status get_oidc_rs256_key(const char* jwksUri, const char* kid, EVP_PKEY** publicKey);

bool get_service_account_access_token_new(const char* tokenCachePath, const char* tokenEndpointUri, const char* clientId, const char* assertion, char** accessToken);

bool get_ropc_id_token_new(const char* tokenEndpointUri, const char* clientId, const char* assertion, const char* username, const char* password, char** idToken);

enum oidc_client_status validate_access_token(const char* jwksUri, const char* accessTokenBase64Url);

enum oidc_client_status get_validated_id_token_new(const char* jwksUri, const char* idTokenBase64Url, struct user_representation* tokenOut);

bool get_user_representation_by_id_new(const char* userEndpointUri, const char* accessToken, uid_t userId, struct user_representation* user);

bool get_user_representation_by_username_new(const char* userEndpointUri, const char* accessToken, const char* userName, struct user_representation* user);

void id_token_free(struct user_representation token);

void global_dispose();
