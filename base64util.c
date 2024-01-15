#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "base64util.h"

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

char* base64urlbin_to_base64string_new(const char* base64UrlString, size_t length)
{
    size_t base64Length = length + length % 4;

    char* buffer = (char*)malloc(base64Length + 1);
    memcpy(buffer, base64UrlString, length);
    
    // Replace characters.
    for (int i = 0; i < length; i++)
    {
        char* c = &buffer[i];
        switch (*c)
        {
            case '-':
            *c = '+';
            break;

            case '_':
            *c = '/';
            break;
        }
    }

    // Add padding.
    for (int i = 0; i < length % 4; i++)
    {
        buffer[length + i] = '=';
    }

    buffer[base64Length] = '\0';

    return buffer;
}

char* base64urlstring_to_base64urlstring_new(const char* base64UrlString)
{
    size_t base64UrlLength = strlen(base64UrlString);
    return base64urlbin_to_base64string_new(base64UrlString, base64UrlLength);
}

char* bin_to_base64urlstring_new(const void* data, int dataLength)
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
    buf[bptr->length] = '\0';

    BIO_free_all(b64);

    base64_to_url(buf);

    return buf;
}

char* string_to_base64urlstring_new(const char* dataString)
{
    int dataLength = strlen(dataString);
    return bin_to_base64urlstring_new(dataString, dataLength);
}

char* base64urlbin_to_bin_new(const char* base64Url, int inLength, int* outLength)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    char* base64String = base64urlbin_to_base64string_new(base64Url, inLength);
    BIO* mem = BIO_new_mem_buf(base64String, -1);
    BIO_push(b64, mem);

    *outLength = BIO_get_mem_data(mem, NULL);
    char* outputBuffer = (char*)malloc(*outLength);
    *outLength = BIO_read(b64, outputBuffer, *outLength);

    BIO_free_all(b64);
    free(base64String);

    return outputBuffer;
}

char* base64urlbin_to_string_new(const char* base64Url, int inLength)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    char* base64String = base64urlbin_to_base64string_new(base64Url, inLength);
    BIO* mem = BIO_new_mem_buf(base64String, -1);
    BIO_push(b64, mem);

    int outLength = BIO_get_mem_data(mem, NULL);
    char* outputBuffer = (char*)malloc(outLength + 1);
    int memLength = BIO_read(b64, outputBuffer, outLength);

    outputBuffer[memLength] = '\0';

    BIO_free_all(b64);
    free(base64String);

    return outputBuffer;
}

char* base64urlstring_to_bin_new(const char* base64Url, int* outLength)
{
    int inLength = strlen(base64Url);
    return base64urlbin_to_bin_new(base64Url, inLength, outLength);
}
