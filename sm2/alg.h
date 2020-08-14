//
// Created by Nick on 2017/4/7.
//

#ifndef SECURECORESERVICE_ALG_H
#define SECURECORESERVICE_ALG_H

#include "def.h"

#ifdef __cplusplus
extern "C" {
#endif
//ECB
ULONG encryptDataBySM4(const unsigned char *key, const unsigned char *plain, const ULONG plainLength,
                       const int paddingType, const int feedBitLength, unsigned char *cipher,
                       ULONG *cipherLength);

ULONG decryptDataBySM4(const unsigned char *key, const unsigned char *cipher, const ULONG cipherLength,
                       const int paddingType, const int feedBitLength, unsigned char *plain,
                       ULONG *plainLength);

//CBC加密
ULONG encryptDataByCBCSM4SubKey(const unsigned char *plain,
                                const ULONG plainLength, sm4_context *ctx, unsigned char *iv,
                                const int paddingType, const int feedBitLength, unsigned char *cipher,
                                ULONG *cipherLength);

ULONG decryptDataByCBCSM4SubKey(unsigned char *cipher,
                                const ULONG cipherLength, sm4_context *ctx, unsigned char *iv,
                                const int paddingType, const int feedBitLength, unsigned char *plain,
                                ULONG *plainLength);


ULONG encryptDataBySM4SubKey(const unsigned int *subkey, const unsigned char *plain, const ULONG plainLength,
                             const int paddingType, const int feedBitLength, unsigned char *cipher,
                             ULONG *cipherLength);

ULONG decryptDataBySM4SubKey(const unsigned int *subkey, const unsigned char *cipher, const ULONG cipherLength,
                             const int paddingType, const int feedBitLength, unsigned char *plain,
                             ULONG *plainLength);

ULONG generateECCKeyPair(unsigned char *pubKey, ULONG *pubKeyLength, unsigned char *priKey,
                         ULONG *priKeyLength);

ULONG generateECCKeyPairWithPublicKeyBlob(ECCPUBLICKEYBLOB *pubKeyBlob, unsigned char *priKey,
                                          int *priKeyLength);

ULONG
computeRootPublicKey(const unsigned char *P2, const unsigned int P2Length, const unsigned char *D1,
                     const unsigned int D1Length, unsigned char *P, unsigned int *PLength);

ULONG client_MSC_SM2Sign1(BYTE *K1, BYTE *Q1_X, BYTE *Q1_Y);

ULONG
client_MSC_SM2Sign2(const BYTE *pin, const int pinLength, const BYTE *w1, const BYTE *w2,
                    const BYTE *w3, const BYTE *K1, const BYTE *r, const BYTE *s2, const BYTE *s3,
                    BYTE *s);

void getRandom(unsigned char *rand, const int length);

ULONG client_MSC_SM2Dec1(const unsigned char *C1_X, const unsigned char *C1_Y, unsigned char *K,
                         unsigned char *T1_X, unsigned char *T1_Y);

ULONG client_MSC_SM2Dec2(const unsigned char *K, const unsigned char *pin, const int pinLength,
                         const unsigned char *w1, const unsigned char *w2, const unsigned char *w3,
                         const unsigned char *t3, const unsigned char *t7, const unsigned char *C1_X,
                         const unsigned char *C1_Y, const unsigned char *T2_X,
                         const unsigned char *T2_Y, const unsigned char *C2, unsigned char *M,
                         int C2Len, const unsigned char *hash);


ULONG verifyKeyPair(const unsigned char *privateKey, const int priviteKeyLength,
                    const unsigned char *pubKey, const int pubKeyLength);

void
computeMessageDigest(unsigned char *digest, const unsigned char *pubKey, const int pubKeyLength,
                     const unsigned char *message, const int messageLength, const char *userName,
                     const int userNameLength);

ULONG verifyMessageSignature(const unsigned char *pubKey, const int pubKeyLength,
                             const unsigned char *message, const int messageLength,
                             const unsigned char *signature, const int signatureLength,
                             const char *userName, const int userNameLength);

ULONG verifyHashSignature(const unsigned char *pubKey, const int pubKeyLength,
                          const unsigned char *hash, const int hashLength,
                          const unsigned char *signature, const int signatureLength);


ULONG encryptMessage(unsigned char *cipher, ULONG *cipherLength, const unsigned char *pubKey,
                     const int pubKeyLength, const unsigned char *plain, const ULONG plainLength,
                     const unsigned char *rnd, const int rndLength);

ULONG decryptMessage(unsigned char *plain, ULONG *plainLength, const unsigned char *priKey,
                     const int priKeyLength, const unsigned char *cipher, const ULONG cipherLength);

ULONG isPublicKeyValid(const unsigned char *key, const int keyLength);

ULONG computeKeyExchangeResult(unsigned char *key, int *keyLength, const unsigned char *sponsorPubKey,
                               const int sponsorPubKeyLength,
                               const char *sponsorID, const int sponsorIDLength,
                               const unsigned char *sponsorRnd, const int sponsorRndLength,
                               const unsigned char *pubKey, const int pubKeyLength,
                               const unsigned char *priKey, const int priKeyLength,
                               const unsigned char *rnd, const int rndLength,
                               const char *ID, const int IDLength,
                               bool fInit);

ULONG splitKeyWithRandom(const unsigned char *pin, const int pinLength, const unsigned char *d3, const int d3Length, const unsigned char *d7,
                         const int d7Length,
                         unsigned char *w1, int *w1Length,
                         unsigned char *w2, int *w2Length, unsigned char *w3, int *w3Length, unsigned char *t3, int *t3Length,
                         unsigned char *t7, int *t7Length, unsigned char *D,
                         int *DLength, unsigned char* P, int* PLength);

ULONG splitKey(const unsigned char *pin, const int pinLength, unsigned char *P, int *PLength,
               unsigned char *w1, int *w1Length,
               unsigned char *w2, int *w2Length, unsigned char *w3, int *w3Length, unsigned char *t3,
               int *t3Length,
               unsigned char *t7, int *t7Length, unsigned char *D,
               int *DLength);

ULONG resplitKey(const unsigned char *oldPIN, const int oldPINLength,
                 const unsigned char *oldw1, const int oldw1Length, const unsigned char *oldw2,
                 const int oldw2Length,
                 const unsigned char *oldw3, const int oldw3Length, const unsigned char *oldt3,
                 const int oldt3Length, const unsigned char *oldt7, const int oldt7Length,
                 const unsigned char *newPIN, const int newPINLength, unsigned char *neww1,
                 int *neww1Length, unsigned char *neww2, int *neww2Length,
                 unsigned char *neww3, int *neww3Length, unsigned char *newt3, int *newt3Length,
                 unsigned char *newt7, int *newt7Length);

ULONG resplitKeyWithRandom(const unsigned char *oldPIN, const int oldPINLength,
                           const unsigned char *oldw1, const int oldw1Length, const unsigned char *oldw2,
                           const int oldw2Length, const unsigned char *oldw3, const int oldw3Length, const unsigned char *oldt3,
                           const int oldt3Length, const unsigned char *oldt7, const int oldt7Length,
                           const unsigned char *newPIN, const int newPINLength, unsigned char *newd3, int* newd3Length,
                           unsigned char *newd7, int* newd7Length,
                           unsigned char *neww1, int *neww1Length, unsigned char *neww2, int *neww2Length,
                           unsigned char *neww3, int *neww3Length, unsigned char *newt3, int *newt3Length,
                           unsigned char *newt7, int *newt7Length);

ULONG restoreKey(unsigned char *D, const int DLength, const unsigned char *pin, const int pinLength,
                 const unsigned char *w1, const int w1Length, const unsigned char *w2,
                 const int w2Length,
                 const unsigned char *w3, const int w3Length);

ULONG pkcs5Padding(const unsigned char *src, const ULONG srcLength, const int blockSize,
                   unsigned char *paddedSrc, ULONG *paddedSrcLength);
ULONG pkcs5Unpadding(const unsigned char *paddedSrc, const ULONG paddedSrcLength, const int blockSize,
                     unsigned char *src, ULONG *srcLength);

ULONG hashUserID(unsigned char *out, const unsigned char *key, const ULONG keyLength, const char *user, const ULONG userLength);

ULONG
SM2HashAndSignMessage(const unsigned char *pubKey, const int pubKeyLength, const unsigned char *priKey, const int priKeyLength, const unsigned char *message,
                      const int messagLength, const char *userName, const int userNameLength, unsigned char *signature, int *signatureLength);

#ifdef __cplusplus
}
#endif

#endif //SECURECORESERVICE_ALG_H
