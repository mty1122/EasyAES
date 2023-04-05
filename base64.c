#include<string.h>
#include<openssl/evp.h>

unsigned char* base64_decode(unsigned char* in) {
    if (in == NULL)
        return NULL;

    int inlen, outlen;
    inlen = strlen(in);

    if(strstr(in, "=="))
        outlen = inlen / 4 * 3 - 2;
    else if(strstr(in, "="))
        outlen = inlen / 4 * 3 -  1;
    else
        outlen = inlen / 4 * 3;

    unsigned char* out = malloc(sizeof(unsigned char) * outlen + 1);
    out[outlen] = '\0';

    EVP_DecodeBlock(out, in, inlen);
    return out;
}

unsigned char* base64_encode(unsigned char* in) {
    if (in == NULL)
        return NULL;

    int inlen, outlen;
    inlen = strlen(in);

    if(inlen % 3 == 0)
        outlen = inlen / 3 * 4;
    else
        outlen = (inlen / 3 + 1) * 4;

    unsigned char* out = malloc(sizeof(unsigned char) * outlen + 1);
    out[outlen]='\0';

    EVP_EncodeBlock(out, in, inlen);
    return out;
}