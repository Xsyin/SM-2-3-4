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

    printHexStr(privatekey, 32);
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

    unsigned char *sponsorID = (unsigned char*)"1234567812345678";
    unsigned char *responsorID =(unsigned char*) "1234567812345678";
    unsigned char *sponsorPri_str = (unsigned char*)
    "81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029";
    unsigned char sponsorPri[32] = {0};
    HexStrToByte((char *)sponsorPri_str, sponsorPri, strlen((char *)sponsorPri_str));
    unsigned char *sponsorPub_str = (unsigned char*)"160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C942324A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F";
    unsigned char sponsorPub[64] = {0};
    HexStrToByte((char *)sponsorPub_str, sponsorPub, strlen((char *)sponsorPub_str));
    unsigned char *sponsor_rnd_str = (unsigned char*)"D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3";
    unsigned char sponsor_rnd[32] = {0};
    ULONG sponsor_rndLen = 32;
    HexStrToByte((char *)sponsor_rnd_str, sponsor_rnd, strlen((char *)sponsor_rnd_str));
    unsigned char *responsorPri_str = (unsigned char*)"785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5";
    unsigned char responsorPri[32] = {0};
    HexStrToByte((char *)responsorPri_str, responsorPri, strlen((char *)responsorPri_str));
    unsigned char *responsorPub_str = (unsigned char*)"6AE848C57C53C7B1B5FA99EB2286AF078BA64C64591B8B566F7357D576F16DFBEE489D771621A27B36C5C7992062E9CD09A9264386F3FBEA54DFF69305621C4D";
    unsigned char responsorPub[64] = {0};
    HexStrToByte((char *)responsorPub_str, responsorPub, strlen((char *)responsorPub_str));
    unsigned char *responsor_rnd_str = (unsigned char*)"7E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6";
     unsigned char responsor_rnd[32] = {0};
     ULONG responsor_rndLen = 32;
     HexStrToByte((char *)responsor_rnd_str, responsor_rnd, strlen((char *)responsor_rnd_str));
     unsigned char tempResponorPub[64] = {0};
     ULONG tempResponorPubLen = 64;
     unsigned char tempSponorPub[64] = {0};
     ULONG tempSponorPubLen = 64;
     unsigned char sessionKey[16] = {0};
     int sessionKeyLen = 16;

     if(verifyKeyPair(sponsorPri, 32, sponsorPub, 64) != 0){
        printf("key pair error");
        return 0;
     }

     if(verifyKeyPair(responsorPri, 32, responsorPub, 64) != 0){
        printf("key pair error");
        return 0;
    }
     int err = 0;

     // 响应方计算
     generateECCKeyPair(tempSponorPub, &tempSponorPubLen, sponsor_rnd, &sponsor_rndLen);
     printHexStr(tempSponorPub, tempSponorPubLen);
     computeKeyExchangeResult(sessionKey, &sessionKeyLen, sponsorPub, 64, (char *)sponsorID, strlen((char *)sponsorID), tempSponorPub, tempSponorPubLen, responsorPub, 64, responsorPri, 32, responsor_rnd, 32, (char *)responsorID, strlen((char *)responsorID), false);
     printf("responsor ----> sponsor: \n");
     printHexStr(sessionKey, sessionKeyLen);

     // 发起方计算
     err = generateECCKeyPair(tempResponorPub, &tempResponorPubLen, responsor_rnd, &responsor_rndLen);
     printHexStr(tempResponorPub, tempResponorPubLen);

     err = computeKeyExchangeResult(sessionKey, &sessionKeyLen, responsorPub, 64, (char *)responsorID, strlen((char *)responsorID), tempResponorPub, tempResponorPubLen, sponsorPub, 64, sponsorPri, 32, sponsor_rnd, 32, (char *)sponsorID, strlen((char *)sponsorID), true);

     printf("sponsor ----> responsor: \n");
     printHexStr(sessionKey, sessionKeyLen);
     
  



//      int lenA = CECCPrivateKey_GenerateKey(&keyA, random, rndLen);
// 	int lenB = CECCPrivateKey_GenerateKey(&keyB, random, rndLen);
// 	unsigned char out[512] = { 0 };
// 	int keybLen = CECCPublicKey_ExportPublicKey(&keyB.publickey, out);
// 	CECCPublicKey_SetPublicKey(&keyB.publickey, out, keybLen);
// 	int msgLenB = CEllipticCurve_KeyExchangeRndMsg(rndMsgB, random2, rndLen);
// 	unsigned char sessionKey[64] = { 0 };
// 	int sessionKeyLen = CECCPrivateKey_KeyExchangeResult(&keyA, sessionKey, 32, random, rndLen, usernameA, usernameLen, rndMsgB, msgLenB,
// 			&keyB.publickey, usernameB, usernameLen, 1);   
         

    return 0;
}
