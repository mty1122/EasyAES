#include <stdio.h>
#include <windows.h>
#include "include/base64.h"

int main() {

    unsigned char* code = base64_encode("hello world!");
    unsigned char* text = base64_decode(code);
    printf("%s\n", code);
    printf("%s\n", text);

    free(code);
    free(text);
    system("pause");

    return 0;

}