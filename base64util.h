#include <stddef.h>

void base64_to_url(char* base64String);

char* convert_to_base64url_new(const void* data, int dataLength, size_t* b64Length);
char* convert_from_base64url_new(const char* base64Url, int* length);
