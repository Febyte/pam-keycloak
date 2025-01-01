#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
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

bool get_signature_sha_new(const unsigned char* der, long derLength, const char* message, int shaBits, unsigned char** signature, size_t* sigLength)
{
    EVP_PKEY* key = d2i_AutoPrivateKey(NULL, (const unsigned char**)&der, derLength);
    if (key == NULL)
    {
        unsigned long err = ERR_get_error();
        fprintf(stderr, "Could not read key (0x%lx)!\n", err);
        return false;
    }

    EVP_MD_CTX* mdContext = EVP_MD_CTX_new();
    if (mdContext == NULL)
    {
        fprintf(stderr, "Failed to create signing context\n");
        return false;
    }

    const EVP_MD* mdAlgorithm = NULL;
    switch (shaBits)
    {
    case 256:
        mdAlgorithm = EVP_sha256();
        break;
    case 384:
        mdAlgorithm = EVP_sha384();
        break;
    case 512:
        mdAlgorithm = EVP_sha512();
        break;
    default:
        fprintf(stderr, "Invalid SHA bit length\n");
        return false;
    }

    if (EVP_DigestSignInit(mdContext, NULL, mdAlgorithm, NULL, key) == 0)
    {
        fprintf(stderr, "Failed to initialize digest signing\n");
        return false;
    }

    // Calculate digest.
    if (EVP_DigestSignUpdate(mdContext, message, strlen(message)) == 0)
    {
        fprintf(stderr, "Failed to calculate digest\n");
        return false;
    }

    // Determine length of signature.
    if (EVP_DigestSignFinal(mdContext, NULL, sigLength) == 0)
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
    if (EVP_DigestSignFinal(mdContext, *signature, sigLength) == 0)
    {
        fprintf(stderr, "Failed to sign\n");
        return false;
    }

    EVP_MD_CTX_free(mdContext);
    EVP_PKEY_free(key);

    return true;
}

char* get_assertion_message_new(const char* clientId, const char* tokenEndpointUri)
{
    const char* header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    char* headerB64 = string_to_base64urlstring_new(header);

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
    char* payloadB64 = string_to_base64urlstring_new(payloadBuffer);

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

    unsigned char* signature = NULL;
    size_t sigLength;
    if (!get_signature_sha_new(der, derLength, message, 256, &signature, &sigLength))
    {
        return false;
    }

    free(der);

    char* signatureB64 = bin_to_base64urlstring_new(signature, sigLength);

    OPENSSL_free(signature);

    *assertion = (char*)malloc(strlen(message) + strlen(signatureB64) + 1);
    sprintf(*assertion, "%s.%s", message, signatureB64);

    free(signatureB64);
    free(message);

    return true;
}
