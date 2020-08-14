
#include "def.h"

#ifdef __cplusplus
extern "C" {
#endif

ULONG encryptMessage(unsigned char *cipher, ULONG *cipherLength, const unsigned char *pubKey,
                     const int pubKeyLength, const unsigned char *plain, const ULONG plainLength,
                     const unsigned char *rnd, const int rndLength);

ULONG decryptMessage(unsigned char *plain, ULONG *plainLength, const unsigned char *priKey,
                     const int priKeyLength, const unsigned char *cipher, const ULONG cipherLength);

ULONG generateECCKeyPair(unsigned char *pubKey, ULONG *pubKeyLength, unsigned char *priKey,
                         ULONG *priKeyLength);

void getRandom(unsigned char *rand, const int length);

ULONG verifyKeyPair(const unsigned char *privateKey, const int priviteKeyLength,
                    const unsigned char *pubKey, const int pubKeyLength);

ULONG computeKeyExchangeResult(unsigned char *key, int *keyLength, const unsigned char *sponsorPubKey,
                               const int sponsorPubKeyLength,
                               const char *sponsorID, const int sponsorIDLength,
                               const unsigned char *sponsorRnd, const int sponsorRndLength,
                               const unsigned char *pubKey, const int pubKeyLength,
                               const unsigned char *priKey, const int priKeyLength,
                               const unsigned char *rnd, const int rndLength,
                               const char *ID, const int IDLength,
                               bool fInit);
                               
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

ULONG hashUserID(unsigned char *out, const unsigned char *key, const ULONG keyLength, const char *user, const ULONG userLength);

ULONG
SM2HashAndSignMessage(const unsigned char *pubKey, const int pubKeyLength, const unsigned char *priKey, const int priKeyLength, const unsigned char *message,
                      const int messagLength, const char *userName, const int userNameLength, const unsigned char *rnd, const int rndLength, unsigned char *signature, int *signatureLength);
#ifdef __cplusplus
}
#endif                     