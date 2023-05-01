#ifndef _SECURITY_H
#define _SECURITY_H

const struct keystore {
    const char key[16] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6'};
    const char iv[16] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6'};
} KETSTORE;

int aes_ecb_128_decrypt(char text[], unsigned char out[]);

#endif