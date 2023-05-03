#include <iostream>
#include <windows.h>
#include "include/base64.h"
#include "include/security.h"

using namespace std;

int main() {
    unique_ptr<char[]> code = base64_encode((const unsigned char*)"hello c++ !", strlen("hello c++ !"));
    unique_ptr<char[]> text = base64_decode_to_string(code.get());
    cout << "base64 test:" << endl << code.get() << endl << text.get() << endl;

    Security security(KETSTORE.key);
    unique_ptr<unsigned char[]> plaintext = security.aes_ecb_128_decrypt("yXVUkR45PFz0UfpbDB8/ew==");
    unique_ptr<char[]> ciphertext = security.aes_ecb_128_encrypt((const unsigned char[]){'1', '2', '3', '4', '5', '6'}, 6);
    cout << "aes test:" << endl << plaintext.get() << endl << ciphertext.get() << endl;    
    
    system("pause");
    return 0;
}