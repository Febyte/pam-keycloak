#include <stddef.h>

void base64_to_url(char* base64String);

char* bin_to_base64urlstring_new(const void* data, int dataLength);

char* string_to_base64urlstring_new(const char* dataString);

char* base64urlbin_to_bin_new(const char* base64Url, int inLength, int* outLength);

char* base64urlbin_to_string_new(const char* base64Url, int inLength);

char* base64urlstring_to_bin_new(const char* base64Url, int* outLength);
