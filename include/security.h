#ifndef _SECURITY_H
#define _SECURITY_H

#include <openssl/aes.h>
#include <openssl/crypto.h>
#include "include/base64.h"

const struct keystore {
    const unsigned char key[16] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6'};
    const unsigned char iv[16] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6'};
} KETSTORE;

class Security {
private:
    unsigned char key[16];
public:
    Security(const unsigned char key[16]);
    std::unique_ptr<unsigned char[]> aes_ecb_128_decrypt(const char* ciphertext_base64, bool tostring = true);
    std::unique_ptr<char[]> aes_ecb_128_encrypt(const unsigned char* plaintext, int plaintext_len); 
};

#endif