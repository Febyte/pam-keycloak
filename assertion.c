#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <uuid/uuid.h>

#include "assertion.h"

#include "base64util.h"

bool get_signature_sha_new(EVP_PKEY* key, const char* message, int shaBits, unsigned char** signature, size_t* sigLength)
{
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

    // JAS: If we're using EC we need to convert the signature to IEEE P1363.
    if (EVP_PKEY_get_id(key) == EVP_PKEY_EC)
    {
        // Parse the signature.
        unsigned char* oldSig = *signature;
        ECDSA_SIG* signatureObj = d2i_ECDSA_SIG(NULL, (const unsigned char**)signature, *sigLength);
        if (!signatureObj) {
            fprintf(stderr, "Failed to parse signature\n");
            return false;
        }

        const BIGNUM *r, *s;
        ECDSA_SIG_get0(signatureObj, &r, &s);

        int rLength = BN_num_bytes(r);
        int sLength = BN_num_bytes(s);
        unsigned char* signatureP1363 = OPENSSL_malloc(rLength + sLength);
        if (!signatureP1363)
        {
            fprintf(stderr, "Failed to allocate IEEE P1363 signature\n");
        }

        BN_bn2bin(r, signatureP1363);
        BN_bn2bin(s, signatureP1363 + rLength);

        OPENSSL_free(oldSig);
        *signature = signatureP1363;
        *sigLength = rLength + sLength;

        ECDSA_SIG_free(signatureObj);
    }

    EVP_MD_CTX_free(mdContext);

    return true;
}

char* get_assertion_message_new(const char* clientId, const char* tokenEndpointUri, const char* alg)
{
    char* header = malloc(32);
    sprintf(header, "{\"alg\":\"%s\",\"typ\":\"JWT\"}", alg);
    char* headerB64 = string_to_base64urlstring_new(header);
    free(header);

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

bool get_assertion_new(const char* pemPath, int shaBits, const char* clientId, const char* tokenEndpointUri, char** assertion)
{
    FILE* pemFile = fopen(pemPath, "r");
    EVP_PKEY* key = PEM_read_PrivateKey(pemFile, NULL, NULL, NULL);
    if (key == NULL)
    {
        unsigned long err = ERR_get_error();
        fprintf(stderr, "Could not read key (0x%lx)!\n", err);
        return false;
    }

    fclose(pemFile);

    char alg[6];

    int keyId = EVP_PKEY_get_id(key);
    switch (keyId)
    {
    case EVP_PKEY_RSA:
        alg[0] = 'R';
        alg[1] = 'S';

        break;
    case EVP_PKEY_EC:
    {
        alg[0] = 'E';
        alg[1] = 'S';

        // JAS: For ECDSA, the key bits align with the SHA bits.
        shaBits = EVP_PKEY_get_bits(key);

        break;
    }
    default:
        fprintf(stderr, "Private key is an unsupported algorithm (%d)\n", keyId);
        return false;
    }

    sprintf(alg + 2, "%d", shaBits);

    char* message = get_assertion_message_new(clientId, tokenEndpointUri, alg);

    unsigned char* signature = NULL;
    size_t sigLength;
    if (!get_signature_sha_new(key, message, shaBits, &signature, &sigLength))
    {
        return false;
    }

    EVP_PKEY_free(key);

    char* signatureB64 = bin_to_base64urlstring_new(signature, sigLength);

    OPENSSL_free(signature);

    *assertion = (char*)malloc(strlen(message) + strlen(signatureB64) + 1);
    sprintf(*assertion, "%s.%s", message, signatureB64);

    free(signatureB64);
    free(message);

    return true;
}
