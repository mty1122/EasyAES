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
    auto plaintext = eaes::aes_128_ecb_decrypt(eaes::KETSTORE.key_16, "yXVUkR45PFz0UfpbDB8/ew==");
    auto ciphertext = eaes::aes_128_ecb_encrypt(eaes::KETSTORE.key_16, (const unsigned char*)"123456", 6);
    cout << "aes test:" << endl << plaintext.get() << endl << ciphertext.get() << endl;   

    //AES_128_GCM test
    eaes::AES_GCM security(eaes::KETSTORE.key_16, sizeof(eaes::KETSTORE.key_16));
    auto encrypt_result = security.encrypt((const unsigned char*)"123456",6 , 
        eaes::KETSTORE.iv, sizeof(eaes::KETSTORE.iv)); 
    cout << "gcm test:" << endl << encrypt_result->ciphertext.get() << endl << encrypt_result->tag.get() << endl;
    auto decrypt_result = security.decrypt("t5bWiLJb", eaes::KETSTORE.iv, 
        sizeof(eaes::KETSTORE.iv), "JeX+N0D3j+1Dogw6c9O/eQ==");
    cout << (decrypt_result->result ? "SUCCESS" : "FAIL") << endl << decrypt_result->plaintext.get() << endl;
    
    system("pause");
    return 0;
}