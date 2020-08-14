#include <stdio.h>
#include "SM2.h"
#include "utils.h"


void printHexStr(unsigned char* data_addr, int len) {
        int i = 0;
        printf("len = %d\n", len);
        for (i = 0; i < len; i++) {
                printf("%02X", *(data_addr + i));
                if(i%4 == 3)
                        printf(" ");
        }
         printf("\n");
}

void printSM2EncryptResult(unsigned char* data_addr, int len) {
        int i = 0;
        printf("len = %d\n", len);
        printf("%02x ", *(data_addr));
        for (i = 1; i < len; i++) {
                printf("%02X", *(data_addr + i));
                if(i%4 == 0)
                        printf(" ");
        }
         printf("\n");
}

int main(int argc, char const *argv[])
{
    unsigned char *publickey_str =
		(unsigned char*) "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";
    unsigned char* plain_str = (unsigned char*) "encryption standard";
    unsigned char* digest_str = (unsigned char*) "message digest";

    unsigned char publickey[64];
    unsigned char cipher[512] = {0};
    ULONG cipherLen;
    unsigned char plain[512] = {0};
    ULONG plainLen;
    unsigned char signature[512] = {0};
    int signatureLen;

    unsigned char random[33] = { 0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A, 0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D, 0xCC, 0xEF, 0x3C, 0xC1, 0xFA,
            0x3C, 0xDB, 0xE4, 0xCE, 0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21};
//     unsigned char* privatekey_str =
//             (unsigned char*)
//             "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B809F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";
    unsigned char* privatekey_str =
            (unsigned char*)
            "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    unsigned char  privatekey[96] = {0};
    unsigned out2[512] = {0};

    HexStrToByte((char *)publickey_str, publickey, strlen((char*)publickey_str));

    HexStrToByte((char *)privatekey_str, privatekey, strlen((char*)privatekey_str));

    if(verifyKeyPair(privatekey, 32, publickey, 64) != 0){
        printf("key pair error");
        return 0;
    } 
    printf("key pair verifyed !\n");
    //sm2 加密
    encryptMessage(cipher, &cipherLen, publickey, 64, plain_str, strlen((char*) plain_str),random, 32);
    printf("sm2 encrypt: cipher ");
    printSM2EncryptResult(cipher, cipherLen);
    // sm2 解密
    decryptMessage(plain, &plainLen, privatekey, 32, cipher, cipherLen);
    printf("sm2 decrypt: plain len = %d, plain = %s\n ", plainLen, plain);

    // sm2 签名
    SM2HashAndSignMessage(publickey, 64, privatekey, 32, digest_str, strlen(((char *)digest_str)), DEFAULT_USER_NAME, DEFAULT_USER_NAME_LENGTH, random, 32, signature, &signatureLen);
    printf("sm2 hash and sign: \n");
    printf("r: ");
    printHexStr(signature, signatureLen/2);
    printf("s: ");
    printHexStr(signature+signatureLen/2, signatureLen/2);
    // sm2 验签
    int res = verifyMessageSignature(publickey, 64, digest_str, strlen((char *)digest_str), signature, signatureLen, DEFAULT_USER_NAME, DEFAULT_USER_NAME_LENGTH);
    if(res != 0)
        return 0;
    printf("verifyed the message signature \n");

    return 0;
}
