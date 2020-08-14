//
// Created by xsyin on 8/13/20.
//

#include <stdio.h>
#include "sm4.h"

/*
*   gcc sm4.h sm4.c sm4Test.c -o testsm4
*/

int main(int argc, char const *argv[])
{
    unsigned char plain[16] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE, 0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	unsigned char key[16] =   {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE, 0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};

    unsigned char cipher[16] = {0x68, 0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};

    unsigned int subkey[32] = {0};
    unsigned char out[16] = {0};
  
    Sms4ExtendKey(subkey, key);
    Sms4Encrypt(out, plain, subkey);
    printf("Sms4 encrypted, cipher:");
    for (size_t i = 0; i < 16; i++)
    {
        printf(" %02x", out[i]);
    }
    printf("\n");

    Sms4Decrypt(out, cipher, subkey);
    printf("Sms4 decrypted, plain:");
    for (size_t i = 0; i < 16; i++)
    {
        printf(" %02x", out[i]);
    }
    printf("\n");

    return 0;
}
