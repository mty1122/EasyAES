#include <iostream>
#include <windows.h>
#include "include/base64.h"
#include "include/security.h"

using namespace std;

int main() {
    //Base64 test
    auto code = base64_encode((const unsigned char*)"hello c++ !", strlen("hello c++ !"));
    auto text = base64_decode_to_string(code.get());
    cout << "base64 test:" << endl << code.get() << endl << text.get() << endl;

    //AES_128_ECB test
    eaes::AES security(eaes::KETSTORE.key_16, eaes::AES_128);
    auto plaintext = security.ecb_decrypt("yXVUkR45PFz0UfpbDB8/ew==");
    auto ciphertext = security.ecb_encrypt((const unsigned char*)"123456", 6);
    cout << "ecb test:" << endl << plaintext.get() << endl << ciphertext.get() << endl;   

    //AES_128_GCM test
    auto iv = eaes::rand_iv(16);
    auto encrypt_result = security.gcm_encrypt((const unsigned char*)"123456",6 , iv.get(), 16); 
    cout << "gcm test:" << endl << encrypt_result->ciphertext.get() << endl << encrypt_result->tag.get() << endl;
    auto decrypt_result = security.gcm_decrypt(encrypt_result->ciphertext.get(), iv.get(), 16, encrypt_result->tag.get());
    cout << (decrypt_result->result ? "SUCCESS" : "FAIL") << endl << decrypt_result->plaintext.get() << endl;
    
    system("pause");
    return 0;
}