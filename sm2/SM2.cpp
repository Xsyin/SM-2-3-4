
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "def.h"
#include "SM2.h"
#include "EllipticCurve.h"
#include "sm3hash.h"
#include "err.h"

CEllipticCurve cc;

ULONG generateECCKeyPair(unsigned char *pubKey, ULONG *pubKeyLength, unsigned char *priKey,
                         ULONG *priKeyLength) {
    if (NULL == pubKey || NULL == priKey || NULL == pubKeyLength || NULL == priKeyLength)
        return SAR_INDATAERR;
    if (*pubKeyLength < SM2_PUB_KEY_LENGTH || *priKeyLength < SM2_PRI_KEY_LENGTH)
        return SAR_INDATALENERR;

    int keylength = cc.KeyExchangeRndMsg(pubKey, priKey, *priKeyLength);
    if (0 == keylength)
        return SAR_COMPUTEERR;

    //判断p1点是否满足要求
    CMpi P2_X_mpi, P2_Y_mpi;
    P2_X_mpi.Import(pubKey, keylength / 2);
    P2_Y_mpi.Import(pubKey + keylength / 2, keylength / 2);
    if (0 == cc.CheckPoint(P2_X_mpi, P2_Y_mpi))
        return SAR_COMPUTEERR;

    *pubKeyLength = keylength;
    return SAR_OK;
}

void getRandom(unsigned char *pbRandom, const int ulRandomLen) {
    for (int index = 0; index < ulRandomLen; index++)
        pbRandom[index] = (BYTE) rand();
}

ULONG verifyKeyPair(const unsigned char *priKey, const int priKeyLength, const unsigned char *pubKey,
                    const int pubKeyLength) {
    if (NULL == priKey || NULL == pubKey)
        return SAR_INDATAERR;
    if (priKeyLength != SM2_PRI_KEY_LENGTH ||
        pubKeyLength != SM2_PUB_KEY_LENGTH)
        return SAR_INDATALENERR;
    CMpi priKey_mpi;
    CMpi P_X_mpi, P_Y_mpi, P_Z_mpi;
    //计算私钥对应的公钥
    priKey_mpi.Import(priKey, priKeyLength);
    cc.MultiplyGByTable(P_X_mpi, P_Y_mpi, P_Z_mpi, priKey_mpi);
    cc.Jacobian2Stand(P_X_mpi, P_Y_mpi, P_Z_mpi);
    unsigned char tempPubKey[SM2_PUB_KEY_LENGTH];
    P_X_mpi.Export(tempPubKey, 32);
    P_Y_mpi.Export(tempPubKey + SM2_PUB_KEY_LENGTH_HALF, 32);
    return 0 == memcmp(pubKey, tempPubKey, SM2_PUB_KEY_LENGTH) ? SAR_OK : SAR_FAIL;
}

ULONG computeKeyExchangeResult(unsigned char *key, int *keyLength, const unsigned char *sponsorPubKey,
                               const int sponsorPubKeyLength,
                               const char *sponsorID, const int sponsorIDLength,
                               const unsigned char *sponsorRnd, const int sponsorRndLength,
                               const unsigned char *pubKey, const int pubKeyLength,
                               const unsigned char *priKey, const int priKeyLength,
                               const unsigned char *rnd, const int rndLength,
                               const char *ID, const int IDLength,
                               bool fInit) {
    if (NULL == key || NULL == keyLength || NULL == sponsorPubKey || NULL == sponsorID ||
        NULL == sponsorRnd || NULL == pubKey || NULL == priKey || NULL == rnd || NULL == ID)
        return SAR_INDATAERR;
    if (*keyLength < SMS4_KEY_LENGTH)
        return SAR_INDATALENERR;

    CECCPublicKey cpub;
    CECCPrivateKey cpri;
    if (0 == cpub.SetPublicKey(sponsorPubKey, sponsorPubKeyLength)
        || 0 == cpri.SetPublicKey(pubKey, pubKeyLength)
        || 0 == cpri.SetKey(priKey, priKeyLength))
        return SAR_INVALIDPARAMERR;

    *keyLength = cpri.KeyExchangeResult(key, *keyLength, rnd, rndLength, ID, IDLength, sponsorRnd,
                                        sponsorRndLength, &cpub, sponsorID, sponsorIDLength, fInit);

    return 0 == *keyLength ? SAR_FAIL : SAR_OK;
}


void
computeMessageDigest(unsigned char *digest, const unsigned char *pubKey, const int pubKeyLength,
                     const unsigned char *message, const int messageLength, const char *userName,
                     const int userNameLength) {
    CECCPrivateKey pri;
    pri.SetPublicKey(pubKey, pubKeyLength);
    pri.MessageDigest(digest, message, messageLength, userName, userNameLength);
}

ULONG verifyMessageSignature(const unsigned char *pubKey, const int pubKeyLength,
                             const unsigned char *message, const int messageLength,
                             const unsigned char *signature, const int signatureLength,
                             const char *userName, const int userNameLength) {
    if (NULL == pubKey || NULL == message || NULL == signature || NULL == userName)
        return SAR_INDATAERR;

    CECCPublicKey pub;
    if (0 == pub.SetPublicKey(pubKey, pubKeyLength))
        return SAR_INVALIDPARAMERR;
    if (0 ==
        pub.VerifyMessage(
                message,
                messageLength,
                signature,
                signatureLength,
                userName,
                userNameLength))
        return SAR_FAIL;
    return SAR_OK;
}

ULONG verifyHashSignature(const unsigned char *pubKey, const int pubKeyLength,
                          const unsigned char *hash, const int hashLength,
                          const unsigned char *signature, const int signatureLength) {
    if (NULL == pubKey || NULL == hash || NULL == signature)
        return SAR_INDATAERR;

    CECCPublicKey pub;
    if (0 == pub.SetPublicKey(pubKey, pubKeyLength))
        return SAR_INVALIDPARAMERR;
    if (0 ==
        pub.Verify(
                hash,
                hashLength,
                signature,
                signatureLength))
        return SAR_FAIL;
    return SAR_OK;
}

ULONG encryptMessage(unsigned char *cipher, ULONG *cipherLen, const unsigned char *pubKey,
                     const int pubKeyLength, const unsigned char *plain, const ULONG plainLength,
                     const unsigned char *rnd, const int rndLength) {
    if (NULL == cipher || NULL == cipherLen || NULL == pubKey || NULL == plain || NULL == rnd)
        return SAR_INDATAERR;

    CECCPublicKey pub;
    if (0 == pub.SetPublicKey(pubKey, pubKeyLength))
        return SAR_INVALIDPARAMERR;

    *cipherLen = pub.EncryptMessage(cipher, plain, plainLength, rnd, rndLength);
    return 0 == *cipherLen ? SAR_ENCRYPTERR : SAR_OK;
}

ULONG decryptMessage(unsigned char *plain, ULONG *plainLength, const unsigned char *priKey,
                     const int priKeyLength, const unsigned char *cipher, const ULONG cipherLength) {
    if (NULL == plain || NULL == plainLength || NULL == priKey || NULL == cipher)
        return SAR_INDATAERR;

    CECCPrivateKey pri;
    if (0 == pri.SetKey(priKey, priKeyLength))
        return SAR_INVALIDPARAMERR;
    *plainLength = pri.DecryptMessage(plain, cipher, cipherLength);
    return 0 == *plainLength ? SAR_DECRYPTERR : SAR_OK;
}

ULONG hashUserID(unsigned char *out, const unsigned char *key, const ULONG keyLength, const char *user, const ULONG userLength) {
    if (NULL == out)
        return SAR_INDATAERR;
    CECCPublicKey pubKey;
    if (0 == pubKey.SetPublicKey(key, keyLength))
        return SAR_INVALIDPARAMERR;
    pubKey.HashUserId(out, user, userLength);
    return SAR_OK;
}

ULONG
SM2HashAndSignMessage(const unsigned char *pubKey, const int pubKeyLength, const unsigned char *priKey, const int priKeyLength,
                      const unsigned char *message,
                      const int messagLength, const char *userName, const int userNameLength, const unsigned char *rnd, const int rndLength, unsigned char *signature, int *signatureLength) {
    if (NULL == pubKey || NULL == priKey || NULL == message || NULL == userName || NULL == signature || NULL == signatureLength)
        return SAR_INDATAERR;
    if (pubKeyLength != SM2_PUB_KEY_LENGTH || priKeyLength != SM2_PRI_KEY_LENGTH)
        return SAR_INVALIDPARAMERR;
    unsigned char key[SM2_PRI_KEY_LENGTH + SM2_PUB_KEY_LENGTH];
    memcpy(key, priKey, priKeyLength);
    memcpy(key + priKeyLength, pubKey, pubKeyLength);
    CECCPrivateKey pri;
    if (0 == pri.SetKey(key, SM2_PRI_KEY_LENGTH + SM2_PUB_KEY_LENGTH))
        return SAR_INVALIDPARAMERR;

    *signatureLength = pri.SignMessage(signature, message, messagLength, userName, userNameLength, rnd, rndLength);
    return 0 == *signatureLength ? SAR_FAIL : SAR_OK;
}
