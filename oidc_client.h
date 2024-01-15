#include <stdbool.h>

#include <uuid/uuid.h>

#include <openssl/evp.h>

struct id_token
{
    uuid_t subject;
    const char* userName;
    const char* displayName;
    const char* homePath;
};

void global_init();

bool get_oidc_uris(const char* oidcConfigUri, char** tokenEndpointUri, char** jwksUri);

bool get_oidc_rs256_key(const char* jwksUri, const char* kid, EVP_PKEY** publicKey);

bool get_ropc_id_token_new(const char* tokenEndpointUri, const char* clientId, const char* assertion, const char* username, const char* password, char** idToken);

bool get_validated_id_token_new(const char* jwksUri, const char* idTokenBase64Url, struct id_token* tokenOut);

void id_token_free(struct id_token token);

void global_dispose();
