#include "include/base64.h"

std::unique_ptr<unsigned char[]> base64_decode(unsigned char* in) {
    if (in == nullptr)
        return nullptr;

    int inlen, outlen;
    inlen = strlen((const char*)in);

    if(strstr((const char*)in, "=="))
        outlen = inlen / 4 * 3 - 2;
    else if(strstr((const char*)in, "="))
        outlen = inlen / 4 * 3 -  1;
    else
        outlen = inlen / 4 * 3;

    std::unique_ptr<unsigned char[]> out(new unsigned char[outlen + 1]);
    out[outlen] = '\0';

    EVP_DecodeBlock(out.get(), in, inlen);
    return out;
}

std::unique_ptr<unsigned char[]> base64_encode(unsigned char* in) {
    if (in == nullptr)
        return nullptr;

    int inlen, outlen;
    inlen = strlen((const char*)in);

    if(inlen % 3 == 0)
        outlen = inlen / 3 * 4;
    else
        outlen = (inlen / 3 + 1) * 4;

    std::unique_ptr<unsigned char[]> out(new unsigned char[outlen + 1]);
    out[outlen]='\0';

    EVP_EncodeBlock(out.get(), in, inlen);
    return out;
}