#ifndef _BASE64_H
#define _BASE64_H

#include <memory>
#include <cstring>
#include <string>
#include <openssl/evp.h>

 namespace eaes {
    std::string base64_decode_to_string(std::string in);
    std::unique_ptr<unsigned char[]> base64_decode(const char* in, int& outlen);
    std::unique_ptr<char[]> base64_encode(const unsigned char* in, int inlen);
 }

#endif