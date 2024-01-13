#include <stdio.h>
#include <string.h>

#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <uuid/uuid.h>

#include "assertion.h"

bool alloc_der(const char* path, unsigned char** der, long* derLength)
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

bool alloc_signature_sha256_digest(const unsigned char* der, long derLength, const unsigned char* digest, unsigned char** signature, size_t* sigLength)
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

void base64_to_url(char* base64String)
{
    size_t base64Length = strlen(base64String);
    // Replace characters.
    for (int i = 0; i < base64Length; i++)
    {
        char* c = &base64String[i];
        switch (*c)
        {
            case '+':
            *c = '-';
            break;

            case '/':
            *c = '_';
            break;
        }
    }

    // Remove padding.
    for (int i = 1; i < 4; i++)
    {
        char* c = &base64String[base64Length - i];
        if (*c == '=')
        {
            *c = '\0';
        }
        else
        {
            break;
        }
    }
}

char* alloc_base64url(const void* data, int dataLength, size_t* b64Length)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);

    BIO_write(b64, data, dataLength);
    BIO_flush(b64);

    BUF_MEM* bptr = NULL;
    BIO_get_mem_ptr(b64, &bptr);

    // Add room for null terminator.
    char* buf = (char*)malloc(bptr->length + 1);
    memcpy(buf, bptr->data, bptr->length);

    // Add null terminator.
    buf[bptr->length] = 0;

    BIO_free_all(b64);

    base64_to_url(buf);

    if (b64Length != NULL)
    {
        *b64Length = bptr->length + 1;
    }

    return buf;
}

char* alloc_assertion_message(const char* clientId, const char* tokenEndpointUri)
{
    const char* header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    char* headerB64 = alloc_base64url(header, strlen(header), NULL);

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
    char* payloadB64 = alloc_base64url(payloadBuffer, strlen(payloadBuffer), NULL);

    char* message = (char*)malloc(strlen(headerB64) + strlen(payloadB64) + 1);
    sprintf(message, "%s.%s", headerB64, payloadB64);

    free(payloadB64);
    free(headerB64);

    return message;
}

bool alloc_assertion(const char* derPath, const char* clientId, const char* tokenEndpointUri, char** assertion)
{
    unsigned char* der = NULL;
    long derLength;
    if (!alloc_der(derPath, &der, &derLength))
    {
        return false;
    }

    char* message = alloc_assertion_message(clientId, tokenEndpointUri);
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    sha256_hash(message, strlen(message), digest);
    
    unsigned char* signature = NULL;
    size_t sigLength;
    if (!alloc_signature_sha256_digest(der, derLength, digest, &signature, &sigLength))
    {
        return false;
    }

    free(der);

    char* signatureB64 = alloc_base64url(signature, sigLength, NULL);

    OPENSSL_free(signature);

    *assertion = (char*)malloc(strlen(message) + strlen(signatureB64) + 1);
    sprintf(*assertion, "%s.%s", message, signatureB64);

    free(signatureB64);
    free(message);

    return true;
}
