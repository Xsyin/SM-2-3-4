//
// Created by Nick on 2017/3/13.
//

#ifndef SECURECORESERVICE_DEF_H
#define SECURECORESERVICE_DEF_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "sm3hash.h"

//#define DEBUG_TEST

//#define LOCAL_DATAKEY_DEBUG

#define MAX_PIN_RETRY_COUNT             10
#define ADMIN_TYPE                      0
#define USER_TYPE                       1
#define DEFAULT_PIN                    "123456"


#define MAX_MAC_LENGTH                  256
#define MAX_HASH_LENGTH                 128
#define MAX_CERT_LENGTH                 10240
#define MAX_RSA_SIGNATURE_LENGTH        1024

#define ECC_MAX_XCOORDINATE_BITS_LEN    512
#define ECC_MAX_YCOORDINATE_BITS_LEN    512
#define ECC_MAX_MODULUS_BITS_LEN        512
#define ECC_MAX_XCOORDINATE_BYTES_LEN   32
#define ECC_MAX_YCOORDINATE_BYTES_LEN   32
#define ECC_MAX_MODULUS_BYTES_LEN       ECC_MAX_MODULUS_BITS_LEN/8

#define MAX_RSA_MODULUS_LEN             256
#define MAX_RSA_EXPONENT_LEN            4
#define RANDOM_LENGTH                   32

#define MAX_PUB_KEY_LENGTH              1024
#define MAX_PRI_KEY_LENGTH              1024
#define SM2_PUB_KEY_LENGTH              64
#define SM2_PUB_KEY_LENGTH_HALF         32
#define SM2_PRI_KEY_LENGTH              32
#define SM2_SIGN_RESULT_LENGTH          64
#define SM2_SIGN_RESULT_LENGTH_HALF     32
#define SM3_HASH_LENGTH                 32
#define SMS4_KEY_LENGTH				(128/8)

#define SMALL_BUFFER_LENGTH             1024
#define BIG_BUFFER_LENGTH               10240
#define MAX_NAME_LENGTH                 256

#define MAX_USEID_LEN                   32

#define MAX_IV_LEN                      32



#define DEFAULT_USER_NAME           "1234567812345678"
#define DEFAULT_USER_NAME_LENGTH    16   //strlen(DEFAULT_USER_NAME)*8    //

#define PUBKEY_PREFIX           0x04

#define SAFE_DELETE(x) if((x)!=NULL){delete x; x=NULL;}
#define SAFE_FREE(x)  if((x)!=NULL){free(x);x=NULL;}
#define DELETE(x) {delete x; x=NULL;}

typedef int8_t CHAR;
typedef uint8_t BYTE;
typedef uint32_t ULONG;
typedef uint32_t DWORD;
typedef char *LPSTR;
typedef bool BOOL;
typedef unsigned long HANDLE;
typedef HANDLE DEVHANDLE;
typedef HANDLE HAPPLICATION;
typedef HANDLE HCONTAINER;



#define MAX_PRI_KEY_CIPHER_LENGTH (MAX_PRI_KEY_LENGTH+SMS4_BLOCK_LENGTH)



struct Hash {
    long algId;
    SM3_HASH_STATE state;//保存中间的状态
    unsigned char last_data[SM3_HASH_LENGTH];
    int last_data_len;
    sm3_context ctx;
};

struct Mac {
    long algId;
    unsigned char key[SMS4_KEY_LENGTH];
};


struct Agreement {
    unsigned char priKey[SM2_PRI_KEY_LENGTH];
    unsigned char pbId[MAX_USEID_LEN];
    int pbIdLength;
    unsigned long containerhandle;
    ULONG algId;
};

typedef struct Struct_ECCPUBLICKEYBLOB {
    ULONG BitLen;
    BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    BYTE YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
} ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

typedef struct Struct_ECCPRIVATEKEYBLOB {

    ULONG BitLen;
    BYTE PrivateKey[ECC_MAX_MODULUS_BITS_LEN / 8];
} ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

typedef struct Struct_ECCCIPHERBLOB {
    BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    BYTE YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
    BYTE HASH[32];
    ULONG CipherLen;
    BYTE *Cipher;
    ULONG coordinateLen;
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

typedef struct Struct_ECCSIGNATUREBLOB {
    BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    ULONG rsLength;
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

typedef struct Struct_BLOCKCIPHERPARAM {
    BYTE IV[MAX_IV_LEN];
    ULONG IVLen;
    ULONG PaddingType;
    ULONG FeedBitLen;
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

typedef struct SKF_ENVELOPEDKEYBLOB {

    ULONG Version;
    ULONG ulSymmAlgID;
    ULONG ulBits;
    BYTE cbEncryptedPriKey[64];   //SM1加密的加解密密钥对中的私钥
    ECCPUBLICKEYBLOB PubKey;      //加密钥密钥对中的公钥
    ECCCIPHERBLOB ECCCipherBlob;  //被签名密钥对中的公钥加密的SM1密钥
} ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

typedef struct Struct_FILEATTRIBUTE {
    char FileName[32];
    ULONG FileSize;
    ULONG ReadRights;
    ULONG WriteRights;
} FILEATTRIBUTE, *PFILEATTRIBUTE;

typedef struct Struct_RSAPUBLICKEYBLOB {
    ULONG AlgID;
    ULONG BitLen;
    BYTE Modulus[MAX_RSA_MODULUS_LEN];
    BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];
    ULONG exponentBitLen;
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

#define ENCRYPT_SMS4_KEY_LENGTH  (SM2_PUB_KEY_LENGTH+SM3_HASH_LENGTH+SMS4_KEY_LENGTH)
#define KEYID_LENGTH    32


enum PaddingType{
    NoPadding=0,
    PKCS5Padding=1
};

#endif //SECURECORESERVICE_DEF_H
