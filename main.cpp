#include <iostream>
#include <windows.h>
#include "include/base64.h"

using namespace std;

int main() {

    unique_ptr<unsigned char[]> code = base64_encode((unsigned char*)"hello c++ !");
    unique_ptr<unsigned char[]> text = base64_decode(code.get());
    cout << code.get() << endl << text.get() << endl;

    system("pause");

    return 0;

}