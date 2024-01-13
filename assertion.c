#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <uuid/uuid.h>

#include "assertion.h"

#include "base64util.h"

bool get_der_new(const char* path, unsigned char** der, long* derLength)
{
    FILE* derFile = fopen(path, "r");
    if (derFile == NULL)
    {
        fprintf(stderr, "Could not open DER key!\n");
        return false;
    }

    fseek(derFile, 0, SEEK_END);
    *derLength = ftell(derFile);

    fseek(derFile, 0, SEEK_SET);

    *der = malloc(*derLength);
    fread(*der, *derLength, 1, derFile);

    fclose(derFile);

    return true;
}

void sha256_hash(const void* data, size_t dataLength, unsigned char* hash)
{
    EVP_Digest(data, dataLength, hash, NULL, EVP_sha256(), NULL);
}

bool get_signature_sha256_new(const unsigned char* der, long derLength, const unsigned char* digest, unsigned char** signature, size_t* sigLength)
{
    EVP_PKEY* key = d2i_PrivateKey(EVP_PKEY_RSA, NULL, (const unsigned char**)&der, derLength);
    if (key == NULL)
    {
        unsigned long err = ERR_get_error();
        fprintf(stderr, "Could not read key (0x%lx)!\n", err);
        return false;
    }

    // Create signing context.
    EVP_PKEY_CTX* keyContext = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (keyContext == NULL)
    {
        fprintf(stderr, "Failed to create signing context\n");
        return false;
    }

    // Initialize context for signing and set options.
    EVP_PKEY_sign_init(keyContext);
    EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PADDING);
    EVP_PKEY_CTX_set_signature_md(keyContext, EVP_sha256());

    // Determine length of signature.
    if (EVP_PKEY_sign(keyContext, NULL, sigLength, digest, SHA256_DIGEST_LENGTH) == 0)
    {
        fprintf(stderr, "Failed to get signature length\n");
        return false;
    }

    // Allocate memory for signature.
    *signature = OPENSSL_malloc(*sigLength);
    if (*signature == NULL) {
        fprintf(stderr, "Failed to allocate memory for signature\n");
        return false;
    }

    // Generate signature.
    if (EVP_PKEY_sign(keyContext, *signature, sigLength, digest, SHA256_DIGEST_LENGTH) != 1)
    {
        fprintf(stderr, "Failed to sign\n");
        return false;
    }

    EVP_PKEY_CTX_free(keyContext);
    EVP_PKEY_free(key);

    return true;
}

char* get_assertion_message_new(const char* clientId, const char* tokenEndpointUri)
{
    const char* header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    char* headerB64 = convert_to_base64url_new(header, strlen(header), NULL);

    uuid_t uuid;
    uuid_generate(uuid);

    char jti[37];
    uuid_unparse(uuid, jti);

    int i = strlen(jti);

    time_t currentTime = time(NULL);
    time_t notBefore = currentTime - 60 * 5;
    time_t expiresAt = currentTime + 60 * 5;

    char payloadBuffer[512];
    sprintf(payloadBuffer, "{\"sub\":\"%s\",\"jti\":\"%s\",\"nbf\":%ld,\"exp\":%ld,\"iss\":\"%s\",\"aud\":\"%s\"}", clientId, jti, notBefore, expiresAt, clientId, tokenEndpointUri);
    char* payloadB64 = convert_to_base64url_new(payloadBuffer, strlen(payloadBuffer), NULL);

    char* message = (char*)malloc(strlen(headerB64) + strlen(payloadB64) + 1);
    sprintf(message, "%s.%s", headerB64, payloadB64);

    free(payloadB64);
    free(headerB64);

    return message;
}

bool get_assertion_new(const char* derPath, const char* clientId, const char* tokenEndpointUri, char** assertion)
{
    unsigned char* der = NULL;
    long derLength;
    if (!get_der_new(derPath, &der, &derLength))
    {
        return false;
    }

    char* message = get_assertion_message_new(clientId, tokenEndpointUri);
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    sha256_hash(message, strlen(message), digest);
    
    unsigned char* signature = NULL;
    size_t sigLength;
    if (!get_signature_sha256_new(der, derLength, digest, &signature, &sigLength))
    {
        return false;
    }

    free(der);

    char* signatureB64 = convert_to_base64url_new(signature, sigLength, NULL);

    OPENSSL_free(signature);

    *assertion = (char*)malloc(strlen(message) + strlen(signatureB64) + 1);
    sprintf(*assertion, "%s.%s", message, signatureB64);

    free(signatureB64);
    free(message);

    return true;
}
