#include <memory.h>

#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/param_build.h>

#include "httpclient.h"

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
    char* nBin = convert_from_base64url_new(nStr, &nBinLength);
    char* eBin = convert_from_base64url_new(eStr, &eBinLength);
    
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

void global_dispose()
{
    curl_global_cleanup();
}
