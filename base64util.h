#include <stddef.h>

void base64_to_url(char* base64String);

char* convert_to_base64url_new(const void* data, int dataLength, size_t* b64Length);
char* base64urlbin_to_bin_new(const char* base64Url, int inLength, int* outLength);
char* base64urlbin_to_string_new(const char* base64Url, int inLength);
char* base64urlstring_to_bin_new(const char* base64Url, int* outLength);
