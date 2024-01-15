#include <memory.h>

#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/param_build.h>

#include "oidc_client.h"

#include "base64util.h"

void global_init()
{
    curl_global_init(CURL_GLOBAL_ALL);
}

struct memory {
    char* response;
    size_t size;
};

size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    size_t realsize = size * nmemb;
    struct memory* mem = (struct memory*)userdata;

    char* allocPtr = realloc(mem->response, mem->size + realsize + 1);
    if(!allocPtr)
    {
        // out of memory!
        return 0;
    }

    mem->response = allocPtr;
    memcpy(&(mem->response[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}

bool get_oidc_uris(const char* oidcConfigUri, char** tokenEndpointUri, char** jwksUri)
{
    CURL* curl = curl_easy_init();
    if(curl == NULL)
    {
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, oidcConfigUri);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    struct memory chunk = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

    CURLcode res = curl_easy_perform(curl);
    if(res != CURLE_OK)
    {
        return false;
    }

    struct json_object* root = json_tokener_parse(chunk.response);

    struct json_object* tokenEndpointObj = json_object_object_get(root, "token_endpoint");
    *tokenEndpointUri = (char*)json_object_get_string(tokenEndpointObj);

    struct json_object* jwksUriObj = json_object_object_get(root, "jwks_uri");
    *jwksUri = (char*)json_object_get_string(jwksUriObj);

    curl_easy_cleanup(curl);

    return true;
}

bool get_rsa_public_key_new(const char* nStr, const char* eStr, EVP_PKEY** publicKey)
{
    // Create a new EVP_PKEY structure
    *publicKey = EVP_PKEY_new();

    // Convert n and e from hexadecimal strings to BIGNUMs
    int nBinLength = 0, eBinLength = 0;
    char* nBin = base64urlstring_to_bin_new(nStr, &nBinLength);
    char* eBin = base64urlstring_to_bin_new(eStr, &eBinLength);
    
    BIGNUM *n = BN_new(), *e = BN_new();
    BN_bin2bn(nBin, nBinLength, n);
    BN_bin2bn(eBin, eBinLength, e);

    // Create an OSSL_PARAM_BLD structure and push the n and e values
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, "n", n);
    OSSL_PARAM_BLD_push_BN(bld, "e", e);

    // Convert the OSSL_PARAM_BLD structure to an OSSL_PARAM array
    OSSL_PARAM* keyParams = OSSL_PARAM_BLD_to_param(bld);

    // Create an EVP_PKEY_CTX structure for RSA key generation
    EVP_PKEY_CTX* keyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    // Initialize the key generation and set the parameters
    EVP_PKEY_fromdata_init(keyContext);
    EVP_PKEY_fromdata(keyContext, publicKey, EVP_PKEY_PUBLIC_KEY, keyParams);

    EVP_PKEY_CTX_free(keyContext);
    OSSL_PARAM_BLD_free(bld);
    BN_free(e);
    BN_free(n);

    free(eBin);
    free(nBin);

    return false;
}

bool get_oidc_rs256_key(const char* jwksUri, const char* kid, EVP_PKEY** publicKey)
{
    CURL* curl = curl_easy_init();
    if(curl == NULL)
    {
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, jwksUri);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    struct memory chunk = {};
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

    CURLcode res = curl_easy_perform(curl);
    if(res != CURLE_OK)
    {
        return false;
    }

    struct json_object* root = json_tokener_parse(chunk.response);
    struct json_object* keysObj = json_object_object_get(root, "keys");
    size_t keyCount = json_object_array_length(keysObj);

    bool foundKid = false;
    for (size_t i = 0; i < keyCount; i++)
    {
        struct json_object* curKey = json_object_array_get_idx(keysObj, i);
        
        struct json_object* curKidObj = json_object_object_get(curKey, "kid");
        const char* curKid = json_object_get_string(curKidObj);

        struct json_object* curKtyObj = json_object_object_get(curKey, "kty");
        const char* curKty = json_object_get_string(curKtyObj);

        struct json_object* curAlgObj = json_object_object_get(curKey, "alg");
        const char* curAlg = json_object_get_string(curAlgObj);

        struct json_object* curUseObj = json_object_object_get(curKey, "use");
        const char* curUse = json_object_get_string(curUseObj);

        if (!strcmp(curKid, kid) && !strcmp(curKty, "RSA") && !strcmp(curAlg, "RS256") && !strcmp(curUse, "sig"))
        {
            struct json_object* nObj = json_object_object_get(curKey, "n");
            const char* nStr = json_object_get_string(nObj);

            struct json_object* eObj = json_object_object_get(curKey, "e");
            const char* eStr = json_object_get_string(eObj);

            get_rsa_public_key_new(nStr, eStr, publicKey);

            // Debug
            #if 0
                BIO* bio = BIO_new(BIO_s_mem());
                if (EVP_PKEY_print_public(bio, *publicKey, 0, NULL) > 0)
                {
                    char* pem = NULL;
                    long len = BIO_get_mem_data(bio, &pem);
                    fwrite(pem, 1, len, stdout);
                }
                BIO_free(bio);
            #endif

            foundKid = true;
            break;
        }
    }

    curl_easy_cleanup(curl);

    return foundKid;
}

bool get_ropc_id_token_new(const char* tokenEndpointUri, const char* clientId, const char* assertion, const char* username, const char* password, char** idToken)
{
    CURL* curl = curl_easy_init();
    if(curl == NULL)
    {
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_URL, tokenEndpointUri);
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    struct memory chunk = {};
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

    struct curl_slist* headers = curl_slist_append(NULL, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    char* payload = (char*)malloc(2048);
    sprintf(payload, "client_id=%s&grant_type=password&client_assertion_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Aclient-assertion-type%%3Ajwt-bearer&client_assertion=%s&username=%s&password=%s&scope=openid", clientId, assertion, username, password);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    
    CURLcode res = curl_easy_perform(curl);
    free(payload);

    if (res != CURLE_OK)
    {
        return false;
    }

    // Parse ID Token

    struct json_object* tokenRoot = json_tokener_parse(chunk.response);
    struct json_object* idTokenObject = json_object_object_get(tokenRoot, "id_token");

    const char* idTokenStr = json_object_get_string(idTokenObject);
    int idTokenLength = json_object_get_string_len(idTokenObject);

    *idToken = (char*)malloc(idTokenLength);
    memcpy(*idToken, idTokenStr, idTokenLength);

    json_object_put(tokenRoot);

    curl_easy_cleanup(curl);

    return true;
}

bool get_validated_id_token_new(const char* jwksUri, const char* idTokenBase64Url, struct id_token* tokenOut)
{
    //
    // Parse the id_token.
    //

    intptr_t tokenHeaderEndMarker = (intptr_t)strchr(idTokenBase64Url, '.');
    uint32_t tokenHeaderLength = (uint32_t)(tokenHeaderEndMarker - (intptr_t)idTokenBase64Url);

    intptr_t tokenPayloadStart = tokenHeaderEndMarker + 1;
    intptr_t tokenPayloadEndMarker = (intptr_t)strchr((const char*)tokenPayloadStart, '.');
    uint32_t tokenPayloadLength = (uint32_t)(tokenPayloadEndMarker - tokenPayloadStart);

    intptr_t tokenSignatureStart = tokenPayloadEndMarker + 1;
    intptr_t tokenSignatureEnd = (intptr_t)idTokenBase64Url + strlen(idTokenBase64Url);
    uint32_t tokenSignatureLength = (uint32_t)(tokenSignatureEnd - tokenSignatureStart);

    // Deserialize the id_token header.

    EVP_PKEY* publicKey = NULL;
    {
        char* idTokenHeaderJson = base64urlbin_to_string_new(idTokenBase64Url, tokenHeaderLength);
        struct json_object* idTokenHeaderRoot = json_tokener_parse(idTokenHeaderJson);

        struct json_object* algObj = json_object_object_get(idTokenHeaderRoot, "alg");
        const char* alg = json_object_get_string(algObj);

        // JAS: TODO: Add support for other algorithms.
        if (strcmp(alg, "RS256"))
        {
            return false;
        }

        struct json_object* kidObj = json_object_object_get(idTokenHeaderRoot, "kid");
        const char* kid = json_object_get_string(kidObj);

        bool getPublicKeyResult = get_oidc_rs256_key(jwksUri, kid, &publicKey);
        
        json_object_put(idTokenHeaderRoot);
        free(idTokenHeaderJson);

        if (!getPublicKeyResult)
        {
            EVP_PKEY_free(publicKey);
            return false;
        }
    }

    // Validate the signature against the public key.

    {
        EVP_MD_CTX* context = EVP_MD_CTX_new();
        if (context == NULL)
        {
            EVP_PKEY_free(publicKey);
            return false;
        }

        if (!EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, publicKey))
        {
            EVP_MD_CTX_free(context);
            EVP_PKEY_free(publicKey);
            return false;
        }

        // Message: "{tokenHeader}.{tokenPayload}"
        if (!EVP_DigestVerifyUpdate(context, idTokenBase64Url, tokenHeaderLength + tokenPayloadLength + 1))
        {
            EVP_MD_CTX_free(context);
            EVP_PKEY_free(publicKey);
            return false;
        }

        int tokenSignatureBinLength = 0;
        char* tokenSignatureBin = base64urlbin_to_bin_new((const char*)tokenSignatureStart, (int)tokenSignatureLength, &tokenSignatureBinLength);

        int verificationResult = EVP_DigestVerifyFinal(context, (const unsigned char*)tokenSignatureBin, tokenSignatureBinLength);

        EVP_MD_CTX_free(context);
        free(tokenSignatureBin);
        EVP_PKEY_free(publicKey);

        if (!verificationResult)
        {
            return false;
        }
    }

    char* idTokenPayloadJson = base64urlbin_to_string_new((const char*)tokenPayloadStart, tokenPayloadLength);

    struct json_object* root = json_tokener_parse(idTokenPayloadJson);
    struct json_object* subObj = json_object_object_get(root, "sub");
    const char* subString = json_object_get_string(subObj);
    uuid_t sub = {};
    if (!uuid_parse(subString, sub))
    {
        uuid_copy(tokenOut->subject, sub);

        struct json_object* userNameObj = json_object_object_get(root, "preferred_username");
        uint32_t userNameLength = json_object_get_string_len(userNameObj);
        char* userNameBuf = (char*)malloc(userNameLength + 1);
        if (userNameBuf != NULL)
        {
            const char* userNameString = json_object_get_string(userNameObj);
            strcpy(userNameBuf, userNameString);
            tokenOut->userName = userNameBuf;

            struct json_object* displayNameObj = json_object_object_get(root, "name");
            uint32_t displayNameLength = json_object_get_string_len(displayNameObj);
            char* displayNameBuf = (char*)malloc(displayNameLength + 1);
            if (displayNameBuf != NULL)
            {
                const char* displayNameString = json_object_get_string(displayNameObj);
                strcpy(displayNameBuf, displayNameString);
                tokenOut->displayName = displayNameBuf;

                struct json_object* homeObj = json_object_object_get(root, "home");
                uint32_t homeLength = json_object_get_string_len(homeObj);
                char* homeBuf = (char*)malloc(homeLength + 1);
                if (homeBuf != NULL)
                {
                    const char* homeString = json_object_get_string(homeObj);
                    strcpy(homeBuf, homeString);
                    tokenOut->homePath = homeBuf;

                    json_object_put(root);
                    free(idTokenPayloadJson);

                    return true;
                }
                else
                {
                    free(displayNameBuf);
                    free(userNameBuf);
                }
            }
            else
            {
                free(userNameBuf);
            }
        }
    }

    json_object_put(root);
    free(idTokenPayloadJson);

    return false;
}

void id_token_free(struct id_token token)
{
    free((void*)token.displayName);
    free((void*)token.homePath);
    free((void*)token.userName);
}

void global_dispose()
{
    curl_global_cleanup();
}
