#ifndef _SECURITY_H
#define _SECURITY_H

#include <openssl/aes.h>
#include <openssl/crypto.h>
#include "include/base64.h"

namespace eaes{
    const struct keystore {
        const unsigned char key_16[16] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6'};
        const unsigned char iv[16] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6'};
    } KETSTORE;

    typedef enum {
        AES_128, AES_192, AES_256
    } MODE;

    typedef struct {
        std::unique_ptr<char[]> ciphertext;
        std::unique_ptr<char[]> tag;
    } GCM_ENCRYPT_RESULT;

    typedef struct {
        std::unique_ptr<unsigned char[]> plaintext;
        bool result;
    } GCM_DECRYPT_RESULT;

    class AES_GCM {
    private:
        unsigned char* key;
        MODE mode;
        const EVP_CIPHER* get_cipher();
    public:
        AES_GCM(const unsigned char* key, int key_len);
        ~AES_GCM();
        std::unique_ptr<GCM_ENCRYPT_RESULT> encrypt(const unsigned char* plaintext, 
            int plaintext_len, const unsigned char* iv, int iv_len);
        std::unique_ptr<GCM_DECRYPT_RESULT> decrypt(const char* ciphertext_base64, 
            const unsigned char* iv, int iv_len, const char* tag_base64, bool tostring = true);
    };

    std::unique_ptr<unsigned char[]> aes_128_ecb_decrypt(const unsigned char key[16], 
        const char* ciphertext_base64, bool tostring = true);
    std::unique_ptr<char[]> aes_128_ecb_encrypt(const unsigned char key[16], 
        const unsigned char* plaintext, int plaintext_len); 
}

#endif