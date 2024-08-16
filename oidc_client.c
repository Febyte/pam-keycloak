#include <memory.h>
#include <stdio.h>
#include <unistd.h>

#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/param_build.h>

#include "base64util.h"
#include "oidc_client.h"

void global_init()
{
    curl_global_init(CURL_GLOBAL_ALL);
}

struct curl_slist* get_common_headers()
{
    struct curl_slist* headers = curl_slist_append(NULL, "User-Agent: OIDCClient/1.0");
    headers = curl_slist_append(headers, "Accept: application/json");

    return headers;
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

enum oidc_client_status get_oidc_uris(const char* oidcConfigUri, char** tokenEndpointUri, char** jwksUri)
{
    CURL* curl = curl_easy_init();
    if(curl == NULL)
    {
        return OIDC_HTTP_INIT_FAILURE;
    }

    curl_easy_setopt(curl, CURLOPT_URL, oidcConfigUri);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    struct memory chunk = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

    struct curl_slist* headers = get_common_headers();
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    if(res != CURLE_OK)
    {
        return OIDC_HTTP_REQUEST_FAILURE;
    }

    struct json_object* root = json_tokener_parse(chunk.response);

    struct json_object* tokenEndpointObj = json_object_object_get(root, "token_endpoint");
    *tokenEndpointUri = (char*)json_object_get_string(tokenEndpointObj);

    struct json_object* jwksUriObj = json_object_object_get(root, "jwks_uri");
    *jwksUri = (char*)json_object_get_string(jwksUriObj);

    curl_easy_cleanup(curl);

    return OIDC_OK;
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

enum oidc_client_status get_oidc_rs256_key(const char* jwksUri, const char* kid, EVP_PKEY** publicKey)
{
    CURL* curl = curl_easy_init();
    if(curl == NULL)
    {
        return OIDC_HTTP_INIT_FAILURE;
    }

    curl_easy_setopt(curl, CURLOPT_URL, jwksUri);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    struct memory chunk = {};
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

    struct curl_slist* headers = get_common_headers();
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    if(res != CURLE_OK)
    {
        return OIDC_HTTP_REQUEST_FAILURE;
    }

    struct json_object* root = json_tokener_parse(chunk.response);
    struct json_object* keysObj = json_object_object_get(root, "keys");
    size_t keyCount = json_object_array_length(keysObj);

    bool foundKid = OIDC_JWK_NOT_FOUND;
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

            foundKid = OIDC_OK;
            break;
        }
    }

    curl_easy_cleanup(curl);

    return foundKid;
}

bool get_token_new(const char* tokenEndpointUri, const char* tokenField, const char* payload, char** token)
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

    struct curl_slist* headers = get_common_headers();
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        return false;
    }

    int32_t responseCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
    if (responseCode != 200)
    {
        return false;
    }

    // Parse Token

    struct json_object* tokenRoot = json_tokener_parse(chunk.response);
    struct json_object* tokenObject = json_object_object_get(tokenRoot, tokenField);

    const char* tokenStr = json_object_get_string(tokenObject);
    int tokenLength = json_object_get_string_len(tokenObject);

    *token = (char*)malloc(tokenLength + 1);
    strcpy(*token, tokenStr);

    json_object_put(tokenRoot);

    curl_easy_cleanup(curl);

    return true;
}

bool get_service_account_access_token_new(const char* tokenCachePath, const char* tokenEndpointUri, const char* clientId, const char* assertion, char** accessToken)
{
    char* payload = (char*)malloc(2048);
    sprintf(payload, "client_id=%s&grant_type=client_credentials&client_assertion_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Aclient-assertion-type%%3Ajwt-bearer&client_assertion=%s", clientId, assertion);

    bool result = false;

    // Check the cache.
    FILE* tokenCache = fopen(tokenCachePath, "r+");

    char cachedToken[4096] = {};
    //int numElements = fscanf(tokenCache, "%s", cachedToken);
    if (fgets(cachedToken, 4096, tokenCache) == NULL)
    {
        result = get_token_new(tokenEndpointUri, "access_token", payload, accessToken);
        fputs(*accessToken, tokenCache);

        #ifdef KC_VERBOSE
        printf("get_service_account_access_token_new: Cache is empty. %s token to put in cache.\n", result ? "Acquired" : "Failed to acquire");
        #endif
    }
    else
    {
        #ifdef KC_VERBOSE
        //printf("get_service_account_access_token_new: Cached token:\n%s\n", cachedToken);
        #endif

        intptr_t tokenHeaderEndMarker = (intptr_t)strchr(cachedToken, '.');
        uint32_t tokenHeaderLength = (uint32_t)(tokenHeaderEndMarker - (intptr_t)cachedToken);

        intptr_t tokenPayloadStart = tokenHeaderEndMarker + 1;
        intptr_t tokenPayloadEndMarker = (intptr_t)strchr((const char*)tokenPayloadStart, '.');
        uint32_t tokenPayloadLength = (uint32_t)(tokenPayloadEndMarker - tokenPayloadStart);

        char* tokenJson = base64urlbin_to_string_new((const char*)tokenPayloadStart, tokenPayloadLength);
        struct json_object* tokenRoot = json_tokener_parse(tokenJson);
        struct json_object* expObj = json_object_object_get(tokenRoot, "exp");
        int64_t exp = json_object_get_int64(expObj);
        int64_t currentTime = (int64_t)time(NULL);
        json_object_put(tokenRoot);
        free(tokenJson);

        // Check if cached token is still good.
        if (exp > currentTime)
        {
            #ifdef KC_VERBOSE
            printf("get_service_account_access_token_new: Cached token is good for %d seconds.\n", (int)(exp - currentTime));
            #endif
            
            *accessToken = (char*)malloc(strlen(cachedToken) + 1);
            strcpy(*accessToken, cachedToken);

            result = true;
        }
        else
        {
            result = get_token_new(tokenEndpointUri, "access_token", payload, accessToken);
            fseek(tokenCache, 0, SEEK_SET);
            fputs(*accessToken, tokenCache);
            int fd = fileno(tokenCache);
            ftruncate(fd, strlen(*accessToken));

            #ifdef KC_VERBOSE
            printf("get_service_account_access_token_new: Cached token expired. %s token to put in cache.\n", result ? "Acquired" : "Failed to acquire");
            #endif
        }
    }
    
    fclose(tokenCache);
    free(payload);

    return result;
}

bool get_ropc_id_token_new(const char* tokenEndpointUri, const char* clientId, const char* assertion, const char* username, const char* password, char** idToken)
{
    char* payload = (char*)malloc(2048);
    sprintf(payload, "client_id=%s&grant_type=password&client_assertion_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Aclient-assertion-type%%3Ajwt-bearer&client_assertion=%s&username=%s&password=%s&scope=openid", clientId, assertion, username, password);

    bool result = get_token_new(tokenEndpointUri, "id_token", payload, idToken);
    free(payload);

    return result;
}

enum oidc_client_status get_public_key_from_jwt_new(const char* jwksUri, const char* jwtHeaderBase64UrlBin, int length, EVP_PKEY** publicKey)
{
    char* idTokenHeaderJson = base64urlbin_to_string_new(jwtHeaderBase64UrlBin, length);
    struct json_object* idTokenHeaderRoot = json_tokener_parse(idTokenHeaderJson);

    struct json_object* algObj = json_object_object_get(idTokenHeaderRoot, "alg");
    const char* alg = json_object_get_string(algObj);

    // JAS: TODO: Add support for other algorithms.
    if (strcmp(alg, "RS256"))
    {
        return OIDC_UNSUPPORTED_ALGORITHM;
    }

    struct json_object* kidObj = json_object_object_get(idTokenHeaderRoot, "kid");
    const char* kid = json_object_get_string(kidObj);

    enum oidc_client_status getPublicKeyResult = get_oidc_rs256_key(jwksUri, kid, publicKey);
    
    json_object_put(idTokenHeaderRoot);
    free(idTokenHeaderJson);

    if (!getPublicKeyResult)
    {
        EVP_PKEY_free(*publicKey);
        return false;
    }

    return OIDC_OK;
}

bool validate_signature(const char* idTokenBase64UrlBin, int messageLength, const char* signatureBase64UrlBin, int signatureLength, EVP_PKEY* publicKey)
{
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == NULL)
    {
        return false;
    }

    if (!EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, publicKey))
    {
        EVP_MD_CTX_free(context);
        return false;
    }

    // Message: "{tokenHeader}.{tokenPayload}"
    if (!EVP_DigestVerifyUpdate(context, idTokenBase64UrlBin, messageLength))
    {
        EVP_MD_CTX_free(context);
        return false;
    }

    int tokenSignatureBinLength = 0;
    char* tokenSignatureBin = base64urlbin_to_bin_new(signatureBase64UrlBin, signatureLength, &tokenSignatureBinLength);

    int verificationResult = EVP_DigestVerifyFinal(context, (const unsigned char*)tokenSignatureBin, tokenSignatureBinLength);

    EVP_MD_CTX_free(context);
    free(tokenSignatureBin);

    return verificationResult;
}

enum oidc_client_status validate_access_token(const char* jwksUri, const char* accessTokenBase64Url)
{
    //
    // Parse the Access Token.
    //

    intptr_t tokenHeaderEndMarker = (intptr_t)strchr(accessTokenBase64Url, '.');
    uint32_t tokenHeaderLength = (uint32_t)(tokenHeaderEndMarker - (intptr_t)accessTokenBase64Url);

    intptr_t tokenPayloadStart = tokenHeaderEndMarker + 1;
    intptr_t tokenPayloadEndMarker = (intptr_t)strchr((const char*)tokenPayloadStart, '.');
    uint32_t tokenPayloadLength = (uint32_t)(tokenPayloadEndMarker - tokenPayloadStart);

    intptr_t tokenSignatureStart = tokenPayloadEndMarker + 1;
    intptr_t tokenSignatureEnd = (intptr_t)accessTokenBase64Url + strlen(accessTokenBase64Url);
    uint32_t tokenSignatureLength = (uint32_t)(tokenSignatureEnd - tokenSignatureStart);

    EVP_PKEY* publicKey = NULL;
    if (!get_public_key_from_jwt_new(jwksUri, accessTokenBase64Url, tokenHeaderLength, &publicKey))
    {
        return false;
    }

    #ifdef KC_VERBOSE
    printf("validate_access_token: JWKs URI: %s\n", jwksUri);
    printf("validate_access_token: Access Token: %s\n", accessTokenBase64Url);
    #endif

    // Validate the signature against the public key.
    bool validationStatus = validate_signature(accessTokenBase64Url, tokenHeaderLength + tokenPayloadLength + 1, (const char*)tokenSignatureStart, tokenSignatureLength, publicKey);
    EVP_PKEY_free(publicKey);

    #ifdef KC_VERBOSE
    printf(validationStatus ? "validate_access_token: Validation successful.\n" : "validate_access_token: Validation failed.\n");
    #endif

    if (validationStatus)
    {
        return OIDC_OK;
    }

    return OIDC_INVALID_SIGNATURE;
}

enum oidc_client_status get_validated_id_token_new(const char* jwksUri, const char* idTokenBase64Url, struct user_representation* tokenOut)
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
    if (!get_public_key_from_jwt_new(jwksUri, idTokenBase64Url, tokenHeaderLength, &publicKey))
    {
        return false;
    }

    // Validate the signature against the public key.
    bool validationStatus = validate_signature(idTokenBase64Url, tokenHeaderLength + tokenPayloadLength + 1, (const char*)tokenSignatureStart, tokenSignatureLength, publicKey);
    EVP_PKEY_free(publicKey);
    if (!validationStatus)
    {
        return OIDC_INVALID_SIGNATURE;
    }

    char* idTokenPayloadJson = base64urlbin_to_string_new((const char*)tokenPayloadStart, tokenPayloadLength);

    // JAS: NOTE: Older versions of Keycloak did not use GUIDs for User IDs.
    struct json_object* root = json_tokener_parse(idTokenPayloadJson);
    struct json_object* subObj = json_object_object_get(root, "sub");
    const char* subString = json_object_get_string(subObj);
    uuid_t sub = {};
    if (!uuid_parse(subString, sub))
    {
        // UID
        {
            struct json_object* idObj = json_object_object_get(root, "uid");
            const char* idStr = json_object_get_string(idObj);
            uid_t uid = (uid_t)atol(idStr);
            tokenOut->userId = uid;
        }

        // GID
        {
            struct json_object* idObj = json_object_object_get(root, "gid");
            const char* idStr = json_object_get_string(idObj);
            gid_t gid = (gid_t)atol(idStr);
            tokenOut->groupId = gid;
        }

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

                    struct json_object* shellObj = json_object_object_get(root, "shell");
                    uint32_t shellLength = json_object_get_string_len(shellObj);
                    char* shellBuf = (char*)malloc(shellLength + 1);
                    if (shellBuf != NULL)
                    {
                        const char* shellString = json_object_get_string(shellObj);
                        strcpy(shellBuf, shellString);
                        tokenOut->shellPath = shellBuf;

                        json_object_put(root);
                        free(idTokenPayloadJson);

                        return OIDC_OK;
                    }

                    free(homeBuf);
                }

                free(displayNameBuf);
            }

            free(userNameBuf);
        }
    }

    json_object_put(root);
    free(idTokenPayloadJson);

    return false;
}

bool get_user_representation_from_json_new(struct json_object* userRepresentationObj, struct user_representation* user)
{
    // User GUID
    {
        struct json_object* userIdObject = json_object_object_get(userRepresentationObj, "id");
        const char* userIdString = json_object_get_string(userIdObject);
        uuid_parse(userIdString, user->subject);
    }

    // User Name
    {
        struct json_object* userNameObject = json_object_object_get(userRepresentationObj, "username");
        const char* userNameStr = json_object_get_string(userNameObject);
        int32_t userNameLength = json_object_get_string_len(userNameObject);
        user->userName = (char*)malloc(userNameLength + 1);
        strcpy((char*)user->userName, userNameStr);
    }

    // Display Name
    {
        struct json_object* firstNameObject = json_object_object_get(userRepresentationObj, "firstName");
        const char* firstNameStr = json_object_get_string(firstNameObject);
        int32_t firstNameLength = json_object_get_string_len(firstNameObject);

        struct json_object* lastNameObject = json_object_object_get(userRepresentationObj, "lastName");
        const char* lastNameStr = json_object_get_string(lastNameObject);
        int32_t lastNameLength = json_object_get_string_len(lastNameObject);

        user->displayName = (char*)malloc(firstNameLength + lastNameLength + 2);
        sprintf((char*)user->displayName, "%s %s", firstNameStr, lastNameStr);
    }

    // Attributes
    {
        struct json_object* attributesObj = json_object_object_get(userRepresentationObj, "attributes");

        // UID
        {
            struct json_object* idArrayObj = json_object_object_get(attributesObj, "uid");
            uint32_t idArrayLength = json_object_array_length(idArrayObj);
            if (idArrayLength != 1)
            {
                return false;
            }

            struct json_object* idObj = json_object_array_get_idx(idArrayObj, 0);
            const char* idStr = json_object_get_string(idObj);
            uid_t uid = (uid_t)atol(idStr);
            user->userId = uid;
        }

        // GID
        {
            struct json_object* idArrayObj = json_object_object_get(attributesObj, "gid");
            uint32_t idArrayLength = json_object_array_length(idArrayObj);
            if (idArrayLength != 1)
            {
                return false;
            }

            struct json_object* idObj = json_object_array_get_idx(idArrayObj, 0);
            const char* idStr = json_object_get_string(idObj);
            gid_t gid = (gid_t)atol(idStr);
            user->groupId = gid;
        }

        // Home Path
        {
            struct json_object* homeArrayObj = json_object_object_get(attributesObj, "home");
            uint32_t homeArrayLength = json_object_array_length(homeArrayObj);
            if (homeArrayLength != 1)
            {
                user->homePath = NULL;
            }
            else
            {
                struct json_object* homeObj = json_object_array_get_idx(homeArrayObj, 0);
                const char* homeStr = json_object_get_string(homeObj);
                int32_t homeLength = json_object_get_string_len(homeObj);
                user->homePath = (char*)malloc(homeLength + 1);
                strcpy((char*)user->homePath, homeStr);
            }
        }

        // Shell Path
        {
            struct json_object* shellArrayObj = json_object_object_get(attributesObj, "shell");
            uint32_t shellArrayLength = json_object_array_length(shellArrayObj);
            if (shellArrayLength != 1)
            {
                user->shellPath = NULL;
            }
            else
            {
                struct json_object* shellObj = json_object_array_get_idx(shellArrayObj, 0);
                const char* shellStr = json_object_get_string(shellObj);
                int32_t shellLength = json_object_get_string_len(shellObj);
                user->shellPath = (char*)malloc(shellLength + 1);
                strcpy((char*)user->shellPath, shellStr);
            }
        }
    }

    return true;
}

bool get_user_representation_by_id_new(const char* userEndpointUri, const char* accessToken, uid_t userId, struct user_representation* user)
{
    CURL* curl = curl_easy_init();
    if(curl == NULL)
    {
        return false;
    }

    // Allocate room for {userEndpointUri}?exact=true&q=uid:{uid}
    // strlen("?exact=true&q=uid:") = 18
    // Max length of the UID string is 10 characters
    char* userQueryUri = (char*)malloc(strlen(userEndpointUri) + 29);
    sprintf(userQueryUri, "%s?exact=true&q=uid:%u", userEndpointUri, userId);

    curl_easy_setopt(curl, CURLOPT_URL, userQueryUri);
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    struct memory chunk = {};
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

    char authorizationHeader[2048];
    sprintf(authorizationHeader, "Authorization: Bearer %s", accessToken);
    struct curl_slist* headers = get_common_headers();
    headers = curl_slist_append(headers, authorizationHeader);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);

    int32_t responseCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

    free(userQueryUri);

    if (res != CURLE_OK)
    {
        curl_easy_cleanup(curl);
        return false;
    }

    // HTTP OK
    if (responseCode == 200)
    {
        // Parse Token

        struct json_object* tokenRoot = json_tokener_parse(chunk.response);
        uint32_t userCount = json_object_array_length(tokenRoot);
        if (userCount != 1)
        {
            json_object_put(tokenRoot);
            curl_easy_cleanup(curl);
            return false;
        }

        struct json_object* userRepresentationObj = json_object_array_get_idx(tokenRoot, 0);

        bool userRepStatus = get_user_representation_from_json_new(userRepresentationObj, user);

        json_object_put(tokenRoot);

        curl_easy_cleanup(curl);

        return userRepStatus;
    }

    return false;
}

bool get_user_representation_by_username_new(const char* userEndpointUri, const char* accessToken, const char* userName, struct user_representation* user)
{
    CURL* curl = curl_easy_init();
    if(curl == NULL)
    {
        return false;
    }

    // Allocate room for {userEndpointUri}+?exact=true&username={userName}
    char* userQueryUri = (char*)malloc(strlen(userEndpointUri) + strlen(userName) + 22);
    sprintf(userQueryUri, "%s?exact=true&username=%s", userEndpointUri, userName);

    curl_easy_setopt(curl, CURLOPT_URL, userQueryUri);
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    struct memory chunk = {};
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

    char authorizationHeader[2048];
    sprintf(authorizationHeader, "Authorization: Bearer %s", accessToken);
    struct curl_slist* headers = get_common_headers();
    headers = curl_slist_append(headers, authorizationHeader);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);

    int32_t responseCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

    free(userQueryUri);

    if (res != CURLE_OK)
    {
        curl_easy_cleanup(curl);
        return false;
    }

    // HTTP OK
    if (responseCode == 200)
    {
        // Parse Token

        struct json_object* tokenRoot = json_tokener_parse(chunk.response);
        uint32_t userCount = json_object_array_length(tokenRoot);
        if (userCount != 1)
        {
            json_object_put(tokenRoot);
            curl_easy_cleanup(curl);
            return false;
        }

        struct json_object* userRepresentationObj = json_object_array_get_idx(tokenRoot, 0);

        bool userRepStatus = get_user_representation_from_json_new(userRepresentationObj, user);

        json_object_put(tokenRoot);

        curl_easy_cleanup(curl);

        return userRepStatus;
    }

    return false;
}

void id_token_free(struct user_representation token)
{
    if (token.displayName != NULL)
    {
        free((void*)token.displayName);
    }

    if (token.homePath != NULL)
    {
        free((void*)token.homePath);
    }

    if (token.userName != NULL)
    {
        free((void*)token.userName);
    }
}

void global_dispose()
{
    curl_global_cleanup();
}
