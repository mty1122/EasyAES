#include <stdio.h>
#include <windows.h>
#include "include/base64.h"

int main() {

    unsigned char* base64 = base64_decode("aGVsbG8gd29ybGQ=");
    printf("%s\n", base64);
    system("pause");

    return 0;

}