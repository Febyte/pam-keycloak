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

char* url_to_base64_new(const char* base64UrlString)
{
    size_t base64UrlLength = strlen(base64UrlString);
    size_t base64Length = base64UrlLength + base64UrlLength % 4;

    char* buffer = (char*)malloc(base64Length + 1);
    memcpy(buffer, base64UrlString, base64UrlLength);
    
    // Replace characters.
    for (int i = 0; i < base64UrlLength; i++)
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
    for (int i = 0; i < base64UrlLength % 4; i++)
    {
        buffer[base64UrlLength + i] = '=';
    }

    buffer[base64Length] = '\0';

    return buffer;
}

char* convert_to_base64url_new(const void* data, int dataLength, size_t* b64Length)
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

char* convert_from_base64url_new(const char* base64Url, int* length)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    size_t b64UrlLength = strlen(base64Url);
    char* base64String = url_to_base64_new(base64Url);
    BIO* mem = BIO_new_mem_buf(base64String, -1);
    BIO_push(b64, mem);

    *length = BIO_get_mem_data(mem, NULL);
    char* outputBuffer = (char*)malloc(*length);
    *length = BIO_read(b64, outputBuffer, *length);

    BIO_free_all(b64);
    free(base64String);

    return outputBuffer;
}
