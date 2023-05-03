#include "include/base64.h"

std::unique_ptr<unsigned char[]> base64_decode(const char* in, int& outlen) {
    if (in == nullptr)
        return nullptr;

    int inlen = strlen(in);

    if(strstr(in, "=="))
        outlen = inlen / 4 * 3 - 2;
    else if(strstr(in, "="))
        outlen = inlen / 4 * 3 -  1;
    else
        outlen = inlen / 4 * 3;

    std::unique_ptr<unsigned char[]> out(new unsigned char[outlen]);
    
    EVP_DecodeBlock(out.get(), (const unsigned char*)in, inlen);
    return out;
}

std::unique_ptr<char[]> base64_decode_to_string(const char* in) {
    if (in == nullptr)
        return nullptr;

    int inlen, outlen;
    inlen = strlen(in);

    if(strstr(in, "=="))
        outlen = inlen / 4 * 3 - 2;
    else if(strstr(in, "="))
        outlen = inlen / 4 * 3 -  1;
    else
        outlen = inlen / 4 * 3;

    std::unique_ptr<char[]> out(new char[outlen + 1]);
    out[outlen] = '\0';

    EVP_DecodeBlock((unsigned char*)out.get(), (const unsigned char*)in, inlen);
    return out;
}

std::unique_ptr<char[]> base64_encode(const unsigned char* in, int inlen) {
    if (in == nullptr)
        return nullptr;

    int outlen;

    if(inlen % 3 == 0)
        outlen = inlen / 3 * 4;
    else
        outlen = (inlen / 3 + 1) * 4;

    std::unique_ptr<char[]> out(new char[outlen + 1]);
    out[outlen]='\0';

    EVP_EncodeBlock((unsigned char*)out.get(), in, inlen);
    return out;
}