#include <stdbool.h>

#include <openssl/evp.h>

void global_init();

bool get_oidc_uris(const char* oidcConfigUri, char** tokenEndpointUri, char** jwksUri);

bool get_oidc_rs256_key(const char* jwksUri, const char* kid, EVP_PKEY** publicKey);

void global_dispose();
