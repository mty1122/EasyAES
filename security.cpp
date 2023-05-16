#include "include/security.h"

using namespace eaes;

AES::AES(const unsigned char* key, MODE mode) {
    int key_len = mode / 8;
    this->mode = mode;
    this->key = new unsigned char[key_len];
    memcpy(this->key, key, key_len);
}

AES::~AES() {
    delete this->key;
}

const EVP_CIPHER* AES::get_cipher() {
    switch (mode) {
    case MODE::AES_128:
        return EVP_aes_128_gcm();
    
    case MODE::AES_192:
        return EVP_aes_192_gcm();

    default:
        return EVP_aes_256_gcm();   
    }
}

std::unique_ptr<GCM_ENCRYPT_RESULT> AES::gcm_encrypt(const unsigned char* plaintext,
    int plaintext_len, const unsigned char* iv, int iv_len) {
    auto ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, get_cipher(), nullptr, nullptr, nullptr);
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
    auto result = std::make_unique<GCM_ENCRYPT_RESULT>();
    result->ciphertext = std::move(ciphertext);
    result->tag = std::move(tag);
    return result;
}

std::unique_ptr<GCM_DECRYPT_RESULT> AES::gcm_decrypt(const char* ciphertext_base64, 
    const unsigned char* iv, int iv_len, const char* tag_base64, bool tostring) {
    int ciphertext_len;
    auto ciphertext = base64_decode(ciphertext_base64, ciphertext_len);
    unsigned char outbuff[ciphertext_len];    
    auto ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, get_cipher(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    int plaintext_len, outlen, tag_len;
    EVP_DecryptUpdate(ctx, outbuff, &outlen, ciphertext.get(), ciphertext_len);
    plaintext_len = outlen;
    auto tag = base64_decode(tag_base64, tag_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag.get());
    int decrypt_result = EVP_DecryptFinal_ex(ctx, &outbuff[plaintext_len], &outlen);
    plaintext_len += outlen;
    EVP_CIPHER_CTX_free(ctx);
    auto result = std::make_unique<GCM_DECRYPT_RESULT>();
    result->result = decrypt_result > 0;
    if (tostring) {
        std::unique_ptr<unsigned char[]> plaintext(new unsigned char[plaintext_len + 1]);
        memcpy(plaintext.get(), outbuff, plaintext_len);
        plaintext[plaintext_len] = '\0';
        result->plaintext = std::move(plaintext);
    } else {
        std::unique_ptr<unsigned char[]> plaintext(new unsigned char[plaintext_len]);
        memcpy(plaintext.get(), outbuff, plaintext_len);
        result->plaintext = std::move(plaintext);
    }
    return result;
}

std::unique_ptr<unsigned char[]> AES::ecb_decrypt(const char* ciphertext_base64, bool tostring) {
    int ciphertext_len;
    auto ciphertext = base64_decode(ciphertext_base64, ciphertext_len);
    unsigned char outbuff[ciphertext_len];
    AES_KEY aes_key;
    AES_set_decrypt_key(key, mode, &aes_key);
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

std::unique_ptr<char[]> AES::ecb_encrypt(const unsigned char* plaintext, int plaintext_len) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, mode, &aes_key);
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

std::unique_ptr<unsigned char[]> eaes::rand_iv(size_t len) {
    static thread_local std::uniform_int_distribution<unsigned> rand(1, 254);
    //static thread_local std::mt19937 engine(std::random_device{}()); //random_device in mingw has some problems
    static thread_local std::mt19937 engine(std::chrono::system_clock::now().time_since_epoch().count());
    std::unique_ptr<unsigned char[]> iv(new unsigned char[len]);
    for (size_t i = 0; i < len; ++i) {
        iv[i] = rand(engine);
    }
    return iv;
}