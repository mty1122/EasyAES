#ifndef _BASE64_H
#define _BASE64_H

#include <memory>
#include <cstring>
#include <openssl/evp.h>

std::unique_ptr<unsigned char[]> base64_decode(unsigned char* in);
std::unique_ptr<unsigned char[]> base64_encode(unsigned char* in);

#endif