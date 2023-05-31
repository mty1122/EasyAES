#include "include/base64.h"

std::unique_ptr<unsigned char[]> eaes::base64_decode(const char* in, int& outlen) {
    if (in == nullptr)
        return {};

    int inlen = (int)strlen(in);

    if(strstr(in, "==") != nullptr)
        outlen = inlen / 4 * 3 - 2;
    else if(strstr(in, "=") != nullptr)
        outlen = inlen / 4 * 3 - 1;
    else
        outlen = inlen / 4 * 3;

    std::unique_ptr<unsigned char[]> out(new unsigned char[outlen]);
    
    EVP_DecodeBlock(out.get(), (const unsigned char*)in, inlen);
    return out;
}

std::string eaes::base64_decode_to_string(std::string in) {
    size_t outlen;

    if(in.find("==") != std::string::npos)
        outlen = in.length() / 4 * 3 - 2;
    else if(in.find("=") != std::string::npos)
        outlen = in.length() / 4 * 3 - 1;
    else
        outlen = in.length() / 4 * 3;

    unsigned char outbuff[outlen];

    EVP_DecodeBlock(outbuff, (const unsigned char*)in.c_str(), in.length());
    return std::string((const char*)outbuff, outlen);
}

std::unique_ptr<char[]> eaes::base64_encode(const unsigned char* in, int inlen) {
    if (in == nullptr)
        return {};

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