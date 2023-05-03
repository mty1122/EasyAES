#include <iostream>
#include <windows.h>
#include "include/base64.h"
#include "include/security.h"

using namespace std;

int main() {
    auto code = base64_encode((const unsigned char*)"hello c++ !", strlen("hello c++ !"));
    auto text = base64_decode_to_string(code.get());
    cout << "base64 test:" << endl << code.get() << endl << text.get() << endl;

    Security security(KETSTORE.key);
    auto plaintext = security.aes_ecb_128_decrypt("yXVUkR45PFz0UfpbDB8/ew==");
    auto ciphertext = security.aes_ecb_128_encrypt((const unsigned char*)"123456", 6);
    cout << "aes test:" << endl << plaintext.get() << endl << ciphertext.get() << endl;   

    auto encrypt_result = security.aes_gcm_128_encrypt((const unsigned char*)"123456", 6, KETSTORE.iv, sizeof(KETSTORE.iv)); 
    cout << "gcm test:" << endl << encrypt_result->ciphertext.get() << endl << encrypt_result->tag.get() << endl;
    
    system("pause");
    return 0;
}