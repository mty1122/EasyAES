#include "include/security.h"

Security::Security(const unsigned char key[16]) {
    memcpy(Security::key, key, 16);
}

std::unique_ptr<unsigned char[]> Security::aes_ecb_128_decrypt(const char* ciphertext_base64, bool tostring) {
    int ciphertext_len;
    auto ciphertext = base64_decode(ciphertext_base64, ciphertext_len);
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
    //Encrypt plaintext
    int group, position;
    for (group = 0; group < ciphertext_len / AES_BLOCK_SIZE; group++) {
        position = group * AES_BLOCK_SIZE;
        AES_ecb_encrypt(&inbuff[position], &outbuff[position], &aes_key, AES_ENCRYPT);
    }
    return base64_encode(outbuff, ciphertext_len);
}

std::unique_ptr<GCM_RESULT> Security::aes_gcm_128_encrypt(const unsigned char* plaintext,
    int plaintext_len, const unsigned char* iv, int iv_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr); 
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    unsigned char outbuff[plaintext_len + AES_BLOCK_SIZE];
    int ciphertext_len, outlen;
    EVP_EncryptUpdate(ctx, outbuff, &outlen, plaintext, plaintext_len);
    ciphertext_len = outlen;
    EVP_EncryptFinal_ex(ctx, &outbuff[ciphertext_len], &outlen);
    ciphertext_len += outlen;
    auto ciphertext = base64_encode(outbuff, ciphertext_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outbuff);
    auto tag = base64_encode(outbuff, 16);
    EVP_CIPHER_CTX_free(ctx);
    auto result = std::make_unique<GCM_RESULT>();
    result->ciphertext = std::move(ciphertext);
    result->tag = std::move(tag);
    return result;
}