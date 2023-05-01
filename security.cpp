#include <openssl/aes.h>
#include <openssl/crypto.h>
#include "include/base64.h"
#include "include/security.h"

int aes_ecb_128_decrypt(char text[], unsigned char out[]) {
    std::unique_ptr<unsigned char[]> in = base64_decode((unsigned char *)text);
    AES_KEY aesKey;
    AES_set_decrypt_key((const unsigned char*)KETSTORE.key, 128, &aesKey);
    AES_ecb_encrypt((const unsigned char*)in.get(), out, &aesKey, AES_DECRYPT);
    return 1;
}