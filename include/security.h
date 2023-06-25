#ifndef _SECURITY_H
#define _SECURITY_H

#include <random>
#include <chrono>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "include/base64.h"

namespace eaes{
    const struct keystore {
        const unsigned char key_16[16] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6'};
        const char* rsa_key_2048 = R"(-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAx1sydIfTezHGte/XBbze
oDW4s1AdwdUvAGqkCL05CW2sSiT2lmKVE2ywUvU2Hhal1q6BRz90J+1jv5eF5Ub0
M8rH6coeg077sFQmeIevoYEO6cPxgx6dlVjygQs/z23SZK9YqHXnwavNKyhlQTXp
Whj1f+J0uC9670L3BVS7lkbrYenihjNVcoGR/FDWjE8vQ28Fc48IN1cULKooD9W+
kWrcYrDYh9zCiQlXbGnJo116vrurn3enGp8VCtHZixlxypEAYVuN+fLWuF357UHL
IlgGIPqX6rXX3gYRpvuyIwH75+MgABomUP2zbfpxMmvZDjXgrS7nEYh6rzE8y9J6
vwIBAw==
-----END PUBLIC KEY-----
)";
    } KETSTORE;

    enum MODE {
        AES_128 = 128, AES_192 = 192, AES_256 = 256
    };

    struct GCM_ENCRYPT_RESULT {
        std::unique_ptr<char[]> ciphertext;
        std::unique_ptr<char[]> tag;
    };

    struct GCM_DECRYPT_RESULT {
        std::unique_ptr<unsigned char[]> plaintext;
        bool result;
    };

    class AES {
    private:
        unsigned char* key;
        MODE mode;
        const EVP_CIPHER* get_cipher();
    public:
        AES(const unsigned char* key, MODE mode);
        ~AES();
        std::unique_ptr<GCM_ENCRYPT_RESULT> gcm_encrypt(const unsigned char* plaintext, 
            int plaintext_len, const unsigned char* iv, int iv_len);
        std::unique_ptr<GCM_DECRYPT_RESULT> gcm_decrypt(const char* ciphertext_base64, 
            const unsigned char* iv, int iv_len, const char* tag_base64, bool tostring = true);
        std::unique_ptr<unsigned char[]> ecb_decrypt(const char* ciphertext_base64, bool tostring = true);
        std::unique_ptr<char[]> ecb_encrypt(const unsigned char* plaintext, int plaintext_len);   
    };

    std::unique_ptr<unsigned char[]> rand_iv(size_t len);
    std::unique_ptr<char[]> rsa_encrypt(const char* key, const unsigned char* plaintext, int plaintext_len);
}

#endif