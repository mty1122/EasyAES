#include "include/security.h"

Security::Security(const unsigned char key[16]) {
    memcpy(Security::key, key, 16);
}

std::unique_ptr<unsigned char[]> Security::aes_ecb_128_decrypt(const char* ciphertext_base64, bool tostring) {
    int ciphertext_len;
    std::unique_ptr<unsigned char[]> ciphertext = base64_decode(ciphertext_base64, ciphertext_len);
    unsigned char outbuff[ciphertext_len];
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);
    //Decrypt ciphertext
    int group, position;
    for (group = 0; group < ciphertext_len / AES_BLOCK_SIZE; group++) {
        position = group * AES_BLOCK_SIZE;
        AES_ecb_encrypt((const unsigned char*)&ciphertext.get()[position], &outbuff[position], &aes_key, AES_DECRYPT);
    }
    //Unpadding
    int plaintext_len = ciphertext_len - (int)outbuff[ciphertext_len - 1];
    if (tostring) {
        std::unique_ptr<unsigned char[]> plaintext(new unsigned char[plaintext_len + 1]);
        memcpy(plaintext.get(), outbuff, plaintext_len);
        plaintext[plaintext_len] = '\0';
        return plaintext;
    } else {
        std::unique_ptr<unsigned char[]> plaintext(new unsigned char[plaintext_len]);
        memcpy(plaintext.get(), outbuff, plaintext_len);
        return plaintext;
    }
}

std::unique_ptr<char[]> Security::aes_ecb_128_encrypt(const unsigned char* plaintext, int plaintext_len) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    //Padding
    int remainder = plaintext_len % AES_BLOCK_SIZE;
    int padding = (remainder == 0) ? AES_BLOCK_SIZE : (AES_BLOCK_SIZE - remainder);
    int ciphertext_len = plaintext_len + padding;
    unsigned char inbuff[ciphertext_len], outbuff[ciphertext_len];
    memcpy(inbuff, plaintext, plaintext_len);
    for (int i = plaintext_len; i < ciphertext_len; i++) {
        inbuff[i] = (unsigned char)padding;
    }
    //Encrypt ciphertext
    int group, position;
    for (group = 0; group < ciphertext_len / AES_BLOCK_SIZE; group++) {
        position = group * AES_BLOCK_SIZE;
        AES_ecb_encrypt(&inbuff[position], &outbuff[position], &aes_key, AES_ENCRYPT);
    }
    return base64_encode(outbuff, ciphertext_len);
}