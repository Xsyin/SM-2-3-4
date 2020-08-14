//
// Created by Nick on 2017/4/7.
//

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "cipher/EllipticCurve.h"
#include "alg.h"
#include "def.h"
#include "err.h"
#include "cipher/sm3hash.h"
#include "sys.h"
#include "cipher/SMS4.h"
#include "log.h"
#include "tool.h"

CEllipticCurve cc;

ULONG generateECCKeyPair(unsigned char *pubKey, ULONG *pubKeyLength, unsigned char *priKey,
                         ULONG *priKeyLength) {
    if (NULL == pubKey || NULL == priKey || NULL == pubKeyLength || NULL == priKeyLength)
        return SAR_INDATAERR;
    if (*pubKeyLength < SM2_PUB_KEY_LENGTH || *priKeyLength < SM2_PRI_KEY_LENGTH)
        return SAR_INDATALENERR;

    getRandom(priKey, SM2_PRI_KEY_LENGTH);
    *priKeyLength = SM2_PRI_KEY_LENGTH;

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

ULONG generateECCKeyPairWithPublicKeyBlob(ECCPUBLICKEYBLOB *pubKeyBlob, unsigned char *priKey,
                                          int *priKeyLength) {
    if (pubKeyBlob == NULL || NULL == priKey || NULL == priKeyLength)
        return SAR_INDATAERR;
    if (*priKeyLength < SM2_PRI_KEY_LENGTH)
        return SAR_INDATALENERR;

    getRandom(priKey, SM2_PRI_KEY_LENGTH);
    *priKeyLength = SM2_PRI_KEY_LENGTH;

    unsigned char pubKey[SM2_PUB_KEY_LENGTH];
    int keylength = cc.KeyExchangeRndMsg(pubKey, priKey, *priKeyLength);
    if (0 == keylength)
        return SAR_COMPUTEERR;

    //判断p1点是否满足要求
    CMpi P2_X_mpi, P2_Y_mpi;
    P2_X_mpi.Import(pubKey, keylength / 2);
    P2_Y_mpi.Import(pubKey + keylength / 2, keylength / 2);
    if (0 == cc.CheckPoint(P2_X_mpi, P2_Y_mpi))
        return SAR_COMPUTEERR;

    pubKeyBlob->BitLen = keylength * 4;
    memcpy(pubKeyBlob->XCoordinate, pubKey, keylength / 2);
    memcpy(pubKeyBlob->YCoordinate, pubKey + keylength / 2, keylength / 2);
    return SAR_OK;
}

void getRandom(unsigned char *pbRandom, const int ulRandomLen) {
    for (int index = 0; index < ulRandomLen; index++)
        pbRandom[index] = (BYTE) rand();
}

ULONG
computeRootPublicKey(const unsigned char *P2, const unsigned int P2Length, const unsigned char *D1,
                     const unsigned int D1Length, unsigned char *P, unsigned int *PLength) {

    if (NULL == P2 || NULL == D1 || NULL == P)
        return SAR_INDATAERR;

    if (P2Length != SM2_PUB_KEY_LENGTH)
        return SAR_INDATALENERR;

    CMpi D1_mpi, D1_inv_mpi;
    CMpi P2_X_mpi, P2_Y_mpi;
    CMpi D1_invP2_X_mpi, D1_invP2_Y_mpi, D1_invP2_Z_mpi;
    //把P1坐标导进来
    P2_X_mpi.Import(P2, SM2_PUB_KEY_LENGTH_HALF);
    P2_Y_mpi.Import(P2 + SM2_PUB_KEY_LENGTH_HALF, SM2_PUB_KEY_LENGTH_HALF);

    //判断p1点是否满足要求
    CEllipticCurve cc;
    if (0 == cc.CheckPoint(P2_X_mpi, P2_Y_mpi))
        return SAR_INVALIDPARAMERR;

    D1_mpi.Import(D1, D1Length);
    CMpl temp_l;
    temp_l = D1_mpi;
    temp_l %= g_paramN.m_oModulus;
    D1_mpi = temp_l.l;
    //D1的逆
    D1_inv_mpi = g_paramN.BinaryInverse(D1_mpi);
    //求D1_inv*P1,前三个参数为点乘后结果的三个坐标，第四个参数是系数，后两个为被点乘的点的坐标
    cc.Multiply(D1_invP2_X_mpi, D1_invP2_Y_mpi, D1_invP2_Z_mpi, D1_inv_mpi, P2_X_mpi, P2_Y_mpi);
    //-G操作后生成P
    CMpi tx, ty, tz;
    cc.MultiplyGByTable(tx, ty, tz, g_paramN.m_oModulus - 1);

    cc.AddMplJacobian(D1_invP2_X_mpi, D1_invP2_Y_mpi, D1_invP2_Z_mpi, tx, ty, tz);

    cc.Jacobian2Stand(D1_invP2_X_mpi, D1_invP2_Y_mpi, D1_invP2_Z_mpi);

    //导出P=D1inv_P1-G
    D1_invP2_X_mpi.Export(P, SM2_PUB_KEY_LENGTH_HALF);
    D1_invP2_Y_mpi.Export(P + SM2_PUB_KEY_LENGTH_HALF, SM2_PUB_KEY_LENGTH_HALF);
    *PLength = SM2_PUB_KEY_LENGTH;
    return SAR_OK;
}

ULONG client_MSC_SM2Sign1(BYTE *K1, BYTE *Q1_X, BYTE *Q1_Y) {
    CMpi K1_mpi;
    //Q1=K1G
    CMpi K1G_X_mpi, K1G_Y_mpi, K1G_Z_mpi;
    CEllipticCurve cc;
    do {
        getRandom(K1, RANDOM_LENGTH);
        //生成随机数
        K1_mpi.Import(K1, 32);
        CMpl temp_l;
        temp_l = K1_mpi;
        temp_l %= g_paramN.m_oModulus;
        K1_mpi = temp_l.l;

        //k1*G
        cc.MultiplyGByTable(K1G_X_mpi, K1G_Y_mpi, K1G_Z_mpi, K1_mpi);
        cc.Jacobian2Stand(K1G_X_mpi, K1G_Y_mpi, K1G_Z_mpi);

    } while (K1G_Y_mpi == 0);

    //Q1=K1*G
    K1G_X_mpi.Export(Q1_X, 32);
    K1G_Y_mpi.Export(Q1_Y, 32);
    K1_mpi.Export(K1, 32);

    return SAR_OK;
}

ULONG getHardwareFactor(unsigned char *d2, unsigned char *d4,
                        unsigned char *d6) {
    char cpu[SMALL_BUFFER_LENGTH], host[SMALL_BUFFER_LENGTH], mac[SMALL_BUFFER_LENGTH];
    int cpuLength = SMALL_BUFFER_LENGTH, hostLength = SMALL_BUFFER_LENGTH, macLength = SMALL_BUFFER_LENGTH;
    if (0 != getCPUSerialInfo(cpu, cpuLength) || 0 != getHostInfo(host, hostLength) ||
        0 != getMacInfo(mac, macLength))
        return SAR_HARDWAREERR;
    SM3_HASH_STATE state;
    Sm3HashInit(&state, (unsigned char *) cpu, (int)strlen(cpu));
    Sm3HashFinal(d2, &state);
    Sm3HashInit(&state, (unsigned char *) host, (int)strlen(host));
    Sm3HashFinal(d4, &state);
    Sm3HashInit(&state, (unsigned char *) mac, (int)strlen(mac));
    Sm3HashFinal(d6, &state);
    return SAR_OK;
}

void
getPINFactor(const unsigned char *pin, const int pinLength, unsigned char *d1, unsigned char *d5) {
    SM3_HASH_STATE state;
    Sm3HashInit(&state, pin, pinLength);
    Sm3HashFinal(d1, &state);
    Sm3HashInit(&state, pin, pinLength);
    Sm3HashFinal(d5, &state);
}

ULONG
client_MSC_SM2Sign2(const BYTE *pin, const int pinLength, const BYTE *w1, const BYTE *w2,
                    const BYTE *w3, const BYTE *K1, const BYTE *r, const BYTE *s2, const BYTE *s3,
                    BYTE *s) {
    if (NULL == pin || pinLength <= 0 || NULL == w1 || NULL == w2 || NULL == w3 || NULL == K1 ||
        NULL == r || NULL == s2 || NULL == s3 || NULL == s)
        return SAR_INDATAERR;
    unsigned char d2[SM3_HASH_LENGTH], d4[SM3_HASH_LENGTH], d6[SM3_HASH_LENGTH];

    if (SAR_OK != getHardwareFactor(d2, d4, d6))
        return SAR_HARDWAREERR;

    unsigned char d1[SM3_HASH_LENGTH], d5[SM3_HASH_LENGTH];
    getPINFactor(pin, pinLength, d1, d5);

    CMpi K1_mpi, r_mpi, s2_mpi, s3_mpi, s_mpi;
    //密钥的拆分因子
    CMpi d2_mpi, d4_mpi, d6_mpi;//设备信息
    CMpi d1_mpi, d5_mpi;//PIN码
    CMpi w1_mpi, w2_mpi, w3_mpi;

    //计算参数
    K1_mpi.Import(K1, 32);
    r_mpi.Import(r, 32);
    s2_mpi.Import(s2, 32);
    s3_mpi.Import(s3, 32);
    d2_mpi.Import(d2, 32);
    d4_mpi.Import(d4, 32);
    d6_mpi.Import(d6, 32);
    d1_mpi.Import(d1, 32);
    d5_mpi.Import(d5, 32);
    w1_mpi.Import(w1, 32);
    w2_mpi.Import(w2, 32);
    w3_mpi.Import(w3, 32);
    CMpl tmp_l, tmp_l2, tmp_l3;
    tmp_l = K1_mpi * s2_mpi;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l = tmp_l.l + s3_mpi;
    tmp_l %= g_paramN.m_oModulus;
    //d1+d2*d2
    //s= (d1 *(k1s2+s3) + d22*(k1s2+s3) + W2*W1 * (d4+d5*d6) *(k1s2+s3) + W3*W1*(k1s2+s3)-r) mod n
    tmp_l2 = d2_mpi * d2_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = tmp_l2.l + d1_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    //d7
    tmp_l3 = w1_mpi * w3_mpi;
    tmp_l3 %= g_paramN.m_oModulus;
    //d1+d2*d2+d7
    tmp_l2 = tmp_l2.l + tmp_l3.l;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l2 = tmp_l.l * tmp_l2.l;
    tmp_l2 %= g_paramN.m_oModulus;

    //d3*(d4+d5*d6)
    tmp_l3 = d5_mpi * d6_mpi;
    tmp_l3 %= g_paramN.m_oModulus;
    tmp_l3 = tmp_l3.l + d4_mpi;
    tmp_l3 %= g_paramN.m_oModulus;
    tmp_l3 = tmp_l3.l * w1_mpi;
    tmp_l3 %= g_paramN.m_oModulus;
    tmp_l3 = tmp_l3.l * w2_mpi;
    tmp_l3 %= g_paramN.m_oModulus;

    tmp_l3 = tmp_l3.l * tmp_l.l;
    tmp_l3 %= g_paramN.m_oModulus;

    //D1*(K1*S2+S3)
    tmp_l = tmp_l2.l + tmp_l3.l;
    tmp_l %= g_paramN.m_oModulus;
    //-r
    tmp_l = tmp_l.l + g_paramN.m_oModulus;
    // tmp_l %= g_paramN.m_oModulus;
    tmp_l2 = r_mpi;
    tmp_l -= tmp_l2;

    tmp_l %= g_paramN.m_oModulus;
    s_mpi = tmp_l.l;
    s_mpi.Export(s, 32);
    return SAR_OK;
}


//完整签名第2步
ULONG
client_MSC_SM2Sign2(const BYTE *D1, const BYTE *K1, const BYTE *r, const BYTE *s2, const BYTE *s3,
                    BYTE *s) {

    CMpi D1_mpi, K1_mpi, r_mpi, s2_mpi, s3_mpi, s_mpi;
    //将数据全部导进来
    D1_mpi.Import(D1, 32);
    K1_mpi.Import(K1, 32);
    r_mpi.Import(r, 32);
    s2_mpi.Import(s2, 32);
    s3_mpi.Import(s3, 32);

    CMpl tmp_l;
    CMpi tmp1_i, tmp2_i;
    //D1K1
    tmp_l = D1_mpi * K1_mpi;
    tmp_l %= g_paramN.m_oModulus;
    tmp1_i = tmp_l.l;
    //(D1K1)*s2
    tmp_l = tmp1_i * s2_mpi;
    tmp_l %= g_paramN.m_oModulus;
    tmp1_i = tmp_l.l;
    //D1s3
    tmp_l = D1_mpi * s3_mpi;
    tmp_l %= g_paramN.m_oModulus;
    tmp2_i = tmp_l.l;
    //s=(D1K1s2)+D1s3-r
    tmp_l = tmp1_i + tmp2_i;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l = tmp_l.l + g_paramN.m_oModulus;

    CMpl tmp_l1;
    tmp_l1 = r_mpi;

    tmp_l -= tmp_l1;

    //tmp_l = tmp_l.l-r_mpi;
    tmp_l %= g_paramN.m_oModulus;
    s_mpi = tmp_l.l;

    s_mpi.Export(s, 32);
    return SAR_OK;
}

ULONG client_MSC_SM2Dec1(const unsigned char *C1_X, const unsigned char *C1_Y, unsigned char *K,
                         unsigned char *T1_X, unsigned char *T1_Y) {
    CMpi K_mpi;
    CMpi C1_X_mpi, C1_Y_mpi;
    //T1=K*C1
    CMpi KC1_X_mpi, KC1_Y_mpi, KC1_Z_mpi;

    //先将C1点的坐标导进来
    C1_X_mpi.Import(C1_X, 32);
    C1_Y_mpi.Import(C1_Y, 32);

    if (0 == CEllipticCurve::CheckPoint(C1_X_mpi, C1_Y_mpi))
        return SAR_INVALIDPARAMERR;

    do {
        getRandom(K, RANDOM_LENGTH);
        //生成K
        K_mpi.Import(K, RANDOM_LENGTH);
        CMpl temp_l;
        temp_l = K_mpi;
        temp_l %= g_paramN.m_oModulus;
        K_mpi = temp_l.l;

        //求T1=K*C1
        cc.Multiply(KC1_X_mpi, KC1_Y_mpi, KC1_Z_mpi, K_mpi, C1_X_mpi, C1_Y_mpi);
        cc.Jacobian2Stand(KC1_X_mpi, KC1_Y_mpi, KC1_Z_mpi);

    } while (KC1_Y_mpi == 0);

    //T1=K*C1
    KC1_X_mpi.Export(T1_X, 32);
    KC1_Y_mpi.Export(T1_Y, 32);

    K_mpi.Export(K, RANDOM_LENGTH);
    return SAR_OK;
}

ULONG client_MSC_SM2Dec2(const unsigned char *K, const unsigned char *pin, const int pinLength,
                         const unsigned char *w1, const unsigned char *w2, const unsigned char *w3,
                         const unsigned char *t3, const unsigned char *t7, const unsigned char *C1_X,
                         const unsigned char *C1_Y, const unsigned char *T2_X,
                         const unsigned char *T2_Y, const unsigned char *C2, unsigned char *M,
                         int C2Len, const unsigned char *hash) {

    if (NULL == pin || pinLength <= 0 || NULL == w1 || NULL == w2 || NULL == w3 || NULL == K ||
        NULL == C1_X || NULL == C1_Y || NULL == T2_X || NULL == T2_Y || NULL == C2 || C2Len <= 0 ||
        NULL == M || NULL == t3 || NULL == t7 || NULL == hash)
        return SAR_INDATAERR;
    //unsigned char d1[SM3_HASH_LENGTH], d2[SM3_HASH_LENGTH], d3[SM3_HASH_LENGTH], d4[SM3_HASH_LENGTH], d5[SM3_HASH_LENGTH], d6[SM3_HASH_LENGTH], d7[SM3_HASH_LENGTH];
    unsigned char t1[RANDOM_LENGTH], t2[SM3_HASH_LENGTH], t4[SM3_HASH_LENGTH], t5[SM3_HASH_LENGTH], t6[SM3_HASH_LENGTH];
    /*
    if (0 != getKeyFactor(pin, pinLength, t2, t4, t6, t1, t5))
        return SYS_ERR;
    */
    if (0 != getHardwareFactor(t2, t4, t6))
        return SAR_HARDWAREERR;
    getPINFactor(pin, pinLength, t1, t5);


    //解密参数
    CMpi K_mpi, K_inv_mpi;
    CMpi C1_X_mpi, C1_Y_mpi;
    CMpi T2_X_mpi, T2_Y_mpi;

    //导入随机数
    K_mpi.Import(K, 32);
    K_inv_mpi = g_paramN.BinaryInverse(K_mpi);

    //先将C1,T2点的坐标导进来
    C1_X_mpi.Import(C1_X, 32);
    C1_Y_mpi.Import(C1_Y, 32);
    T2_X_mpi.Import(T2_X, 32);
    T2_Y_mpi.Import(T2_Y, 32);

    //私钥相关参数
    CMpi w1_mpi;
    CMpi t2_mpi, t4_mpi, t6_mpi;
    CMpi t5_mpi;
    CMpi t3_mpi, t7_mpi;

    w1_mpi.Import(w1, 32);

    t2_mpi.Import(t2, 32);
    t4_mpi.Import(t4, 32);
    t6_mpi.Import(t6, 32);
    //PIN码因子
    t5_mpi.Import(t5, 32);
    //随机数
    t3_mpi.Import(t3, 32);
    t7_mpi.Import(t7, 32);

    //
    CMpl tmp_l, tmp_l2, tmp_l3;

    tmp_l = t2_mpi * t3_mpi;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l = tmp_l.l + g_paramN.BinaryInverse(w1_mpi);
    tmp_l %= g_paramN.m_oModulus;

    //K_inv*(t1+t2*t3)
    tmp_l = tmp_l.l * K_inv_mpi;
    tmp_l %= g_paramN.m_oModulus;

    tmp_l2 = t6_mpi * t7_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = tmp_l2.l + t5_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = tmp_l2.l * t4_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = tmp_l2.l * t4_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    //K_inv*t4*t4(t5+t6*t7)
    tmp_l2 = tmp_l2.l * K_inv_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    // //K_inv*(t1+t2*t3+t4*t4*(t5+t6*t7))
    tmp_l = tmp_l.l + tmp_l2.l;
    tmp_l %= g_paramN.m_oModulus;
    CMpi Kinv_D1inv_T2_X_mpi, Kinv_D1inv_T2_Y_mpi, Kinv_D1inv_T2_Z_mpi;
    //(K_inv*D1_inv)*T2
    cc.Multiply(Kinv_D1inv_T2_X_mpi, Kinv_D1inv_T2_Y_mpi, Kinv_D1inv_T2_Z_mpi, tmp_l.l, T2_X_mpi,
                T2_Y_mpi);

    //-C1=(n-1) modn *C1
    CMpl tmp_k;
    CMpi C1inv_X_mpi, C1inv_Y_mpi, C1inv_Z_mpi;
    tmp_k = g_paramN.m_oModulus - 1;
    tmp_k %= g_paramN.m_oModulus;

    cc.Multiply(C1inv_X_mpi, C1inv_Y_mpi, C1inv_Z_mpi, tmp_k.l, C1_X_mpi, C1_Y_mpi);
    //+(-C1)
    cc.AddMplJacobian(Kinv_D1inv_T2_X_mpi, Kinv_D1inv_T2_Y_mpi, Kinv_D1inv_T2_Z_mpi, C1inv_X_mpi,
                      C1inv_Y_mpi, C1inv_Z_mpi);

    cc.Jacobian2Stand(Kinv_D1inv_T2_X_mpi, Kinv_D1inv_T2_Y_mpi, Kinv_D1inv_T2_Z_mpi);
    //导出结果
    BYTE X2[RANDOM_LENGTH], Y2[RANDOM_LENGTH];
    //X2_mpi,Y2_mpi
    Kinv_D1inv_T2_X_mpi.Export(X2, 32);
    Kinv_D1inv_T2_Y_mpi.Export(Y2, 32);

    //解密出明文
    //t=KDF(X2||Y2,kLen);C2=M^t
    BYTE pSecret[RANDOM_LENGTH * 2];
    memcpy(pSecret, X2, 32);
    memcpy(pSecret + 32, Y2, 32);

    unsigned char *t = (unsigned char *) malloc(sizeof(unsigned char) * (C2Len));

    KDF(t, C2Len, pSecret, sizeof(pSecret), 1);

    int i = 0;
    for (i = 0; i < C2Len; i++) {//最终异或得到明文
        M[i] = t[i] ^ *(C2 + i);
    }
    free(t);


    //验证是否被篡改
    unsigned char digest[HASH_256];
    CECCPublicKey pub;
    pub.AuthenticateMsg(digest, pSecret, M, C2Len);
    i = 0;
    while (i < HASH_256) {
        if (digest[i] != hash[i])
            return SAR_HASHNOTEQUALERR;
        i++;
    }

    return SAR_OK;

}

ULONG client_MSC_SM2Dec2(const unsigned char *K, const unsigned char *D1, const unsigned char *C1_X,
                         const unsigned char *C1_Y, const unsigned char *T2_X,
                         const unsigned char *T2_Y, const unsigned char *C2, unsigned char *M,
                         int C2Len) {

    CMpi K_mpi, K_inv_mpi;
    CMpi D1_mpi, D1_inv_mpi;
    CMpi C1_X_mpi, C1_Y_mpi;
    CMpi T2_X_mpi, T2_Y_mpi;

    CMpl tmp_l;
    CMpi K_inv_D1_inv_mpi;
    CMpi Kinv_D1inv_T2_X_mpi, Kinv_D1inv_T2_Y_mpi, Kinv_D1inv_T2_Z_mpi;


    //导入随机数
    K_mpi.Import(K, 32);
    D1_mpi.Import(D1, 32);

    //先将C1,T2点的坐标导进来
    C1_X_mpi.Import(C1_X, 32);
    C1_Y_mpi.Import(C1_Y, 32);
    T2_X_mpi.Import(T2_X, 32);
    T2_Y_mpi.Import(T2_Y, 32);

    //求K和D1的逆
    K_inv_mpi = g_paramN.BinaryInverse(K_mpi);
    D1_inv_mpi = g_paramN.BinaryInverse(D1_mpi);

    //求K_inv*D1_inv mod n
    tmp_l = K_inv_mpi * D1_inv_mpi;
    tmp_l %= g_paramN.m_oModulus;
    K_inv_D1_inv_mpi = tmp_l.l;

    //(K_inv*D1_inv)*T2
    cc.Multiply(Kinv_D1inv_T2_X_mpi, Kinv_D1inv_T2_Y_mpi, Kinv_D1inv_T2_Z_mpi, K_inv_D1_inv_mpi,
                T2_X_mpi, T2_Y_mpi);
    // cc.Jacobian2Stand(Kinv_D1inv_T2_X_mpi, Kinv_D1inv_T2_Y_mpi, Kinv_D1inv_T2_Z_mpi);

    //-C1=(n-1) modn *C1
    CMpl tmp_k;
    CMpi C1inv_X_mpi, C1inv_Y_mpi, C1inv_Z_mpi;
    tmp_k = g_paramN.m_oModulus - 1;
    tmp_k %= g_paramN.m_oModulus;

    cc.Multiply(C1inv_X_mpi, C1inv_Y_mpi, C1inv_Z_mpi, tmp_k.l, C1_X_mpi, C1_Y_mpi);
    //+(-C1)
    cc.AddMplJacobian(Kinv_D1inv_T2_X_mpi, Kinv_D1inv_T2_Y_mpi, Kinv_D1inv_T2_Z_mpi, C1inv_X_mpi,
                      C1inv_Y_mpi, C1inv_Z_mpi);

    cc.Jacobian2Stand(Kinv_D1inv_T2_X_mpi, Kinv_D1inv_T2_Y_mpi, Kinv_D1inv_T2_Z_mpi);

    //X2_mpi,Y2_mpi


    //t=KDF(X2||Y2,kLen)
    unsigned char pSecret[DCS_ECC_KEY_LENGTH * 2];
    Kinv_D1inv_T2_X_mpi.Export(pSecret, DCS_ECC_KEY_LENGTH);
    Kinv_D1inv_T2_Y_mpi.Export(pSecret + DCS_ECC_KEY_LENGTH, DCS_ECC_KEY_LENGTH);
    //此处t的长度即为数据的长度,以字节为单位
    unsigned char *t = (unsigned char *) malloc(sizeof(unsigned char) * C2Len);//此处t的长度即为数据的长度
    //不确定函数的正确与否
    KDF(t, C2Len, pSecret, sizeof(pSecret), 1);
    for (int i = 0; i < C2Len; i++)
        M[i] = t[i] ^ C2[i];
    free(t);

    return SAR_OK;
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

ULONG isPublicKeyValid(const unsigned char *key, const int keyLength) {
    if (NULL == key)
        return SAR_INDATAERR;
    CECCPublicKey PubKey;
    int pubKeyValid = PubKey.SetPublicKey(key, keyLength);
    return 0 == pubKeyValid ? SAR_FAIL : SAR_OK;
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

ULONG
combineKey(unsigned char *D, const int DLength, const unsigned char *d1, const unsigned char *d2,
           const unsigned char *d4, const unsigned char *d5, const unsigned char *d6,
           const unsigned char *w1, const unsigned char *w2, const unsigned char *w3) {
    if (NULL == d1 || NULL == d2 || NULL == d4 || NULL == d5 || NULL == d6 || NULL == w1 ||
        NULL == w2 || NULL == w3)
        return SAR_INDATAERR;
    if (DLength < SM2_PRI_KEY_LENGTH)
        return SAR_INDATALENERR;
    CMpi D_mpi, d1_mpi, d2_mpi, d4_mpi, d5_mpi, d6_mpi, w1_mpi, w2_mpi, w3_mpi;      //d2,d4,d6设备信息, d1,d5由PIN码生成
    CMpl tmp_l;

    d1_mpi.Import(d1, 32);
    d2_mpi.Import(d2, 32);
    d4_mpi.Import(d4, 32);
    d5_mpi.Import(d5, 32);
    d6_mpi.Import(d6, 32);
    w1_mpi.Import(w1, 32);
    w2_mpi.Import(w2, 32);
    w3_mpi.Import(w3, 32);

    //计算D1=(d1+d2*d2+d3(d4+d5*d6)+d7)mod n
    tmp_l = d2_mpi * d2_mpi;   //d2*d2
    tmp_l %= g_paramN.m_oModulus;

    tmp_l = d1_mpi + tmp_l.l;
    tmp_l %= g_paramN.m_oModulus; //d2*d2+d1

    CMpl tmp_l2, tmp_l3;
    tmp_l2 = d5_mpi * d6_mpi;    //d5*d6
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l2 = tmp_l2.l + d4_mpi;
    tmp_l2 %= g_paramN.m_oModulus; // d5*d6+d4

    tmp_l3 = w1_mpi * w2_mpi; // w1*w2
    tmp_l3 %= g_paramN.m_oModulus;

    tmp_l2 = tmp_l3.l * tmp_l2.l; //w1*w2*(d5*d6+d4)
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l3 = w1_mpi * w3_mpi; //w1*w3
    tmp_l3 %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l + tmp_l2.l; //d2*d2+d1+w1*w2*(d5*d6+d4)
    tmp_l %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l + tmp_l3.l; //d2*d2+d1+w1*w2*(d5*d6+d4)+w1*w3
    tmp_l %= g_paramN.m_oModulus;

    D_mpi = tmp_l.l;

    D_mpi.Export(D, 32);
    return SAR_OK;
}


ULONG restoreKey(unsigned char *D, const int DLength, const unsigned char *pin, const int pinLength,
                 const unsigned char *w1, const int w1Length, const unsigned char *w2,
                 const int w2Length,
                 const unsigned char *w3, const int w3Length) {
    if (NULL == D || NULL == pin)
        return SAR_INDATAERR;
    unsigned char d1[SM3_HASH_LENGTH], d2[SM3_HASH_LENGTH], d4[SM3_HASH_LENGTH], d5[SM3_HASH_LENGTH], d6[SM3_HASH_LENGTH];
    if (0 != getHardwareFactor(d2, d4, d6))
        return SAR_HARDWAREERR;
    getPINFactor(pin, pinLength, d1, d5);
    return combineKey(D, DLength, d1, d2, d4, d5, d6, w1, w2, w3);
}

void
get_T(const BYTE *t, const BYTE *t1, const BYTE *t2, const BYTE *t4, const BYTE *t5, const BYTE *t6,
      const BYTE *t7, unsigned char *t3, int *t3Length) {

    //计算t3 = ((t - t1 - t4*t4(t5+t6*t7))*t2_inv)
    CMpi t_mpi, t1_mpi, t2_mpi, t2_inv_mpi, t3_mpi, t4_mpi, t5_mpi, t6_mpi, t7_mpi;

    t_mpi.Import(t, 32);

    t1_mpi.Import(t1, 32);
    //设备信息
    t2_mpi.Import(t2, 32);
    t4_mpi.Import(t4, 32);
    t6_mpi.Import(t6, 32);
    //PIN码因子
    t5_mpi.Import(t5, 32);
    //随机数
    t7_mpi.Import(t7, 32);

    CMpl tmp_l, tmp_l2;
    //(t5+t6*t7)
    tmp_l = t6_mpi * t7_mpi;
    tmp_l %= g_paramN.m_oModulus;

    tmp_l = t5_mpi + tmp_l.l;
    tmp_l %= g_paramN.m_oModulus;

    //t4*t4
    tmp_l2 = t4_mpi * t4_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    //t4*t4(t5+t6*t7)
    tmp_l = tmp_l2.l * tmp_l.l;
    tmp_l %= g_paramN.m_oModulus;

    //t1 + t4*t4(t5+t6*t7)
    tmp_l = t1_mpi + tmp_l.l;
    tmp_l %= g_paramN.m_oModulus;

    //t -(t1 + t4*t4(t5+t6*t7))
    tmp_l2 = t_mpi + g_paramN.m_oModulus;

    tmp_l = tmp_l.l;

    tmp_l2 -= tmp_l;
    tmp_l2 %= g_paramN.m_oModulus;

    //t2_inv
    t2_inv_mpi = g_paramN.BinaryInverse(t2_mpi);

    //*t2_inv
    tmp_l = tmp_l2.l * t2_inv_mpi;
    tmp_l %= g_paramN.m_oModulus;

    t3_mpi = tmp_l.l;

    t3_mpi.Export(t3, 32);
    *t3Length = SM2_PRI_KEY_LENGTH;
}

ULONG splitKeyWithRandom(const unsigned char *pin, const int pinLength, const unsigned char *d3, const int d3Length, const unsigned char *d7,
                         const int d7Length,
                         unsigned char *w1, int *w1Length,
                         unsigned char *w2, int *w2Length, unsigned char *w3, int *w3Length, unsigned char *t3, int *t3Length,
                         unsigned char *t7, int *t7Length, unsigned char *D,
                         int *DLength, unsigned char* P, int *PLength) {
    if (NULL == pin || NULL==d3 ||  NULL == d7 ||  NULL == w1 || NULL == w2 || NULL == w3 || NULL == w1Length ||
        NULL == w2Length || NULL == w3Length || NULL == t3 ||
        NULL == t3Length || NULL == t7 || NULL == t7Length|| NULL == D || NULL == DLength || NULL==P || NULL == PLength)
        return SAR_INDATAERR;
    if ( SM2_PRI_KEY_LENGTH>d3Length || SM2_PRI_KEY_LENGTH  > d7Length || SM2_PRI_KEY_LENGTH > *w1Length ||
         SM2_PRI_KEY_LENGTH > *w2Length || SM2_PRI_KEY_LENGTH > *w3Length ||
         SM2_PRI_KEY_LENGTH > *DLength || SM2_PRI_KEY_LENGTH > *t3Length ||
         SM2_PRI_KEY_LENGTH > *t7Length || SM2_PUB_KEY_LENGTH>*PLength)
        return SAR_INDATALENERR;
    unsigned char d1[SM2_PRI_KEY_LENGTH], d2[SM2_PRI_KEY_LENGTH], d4[SM2_PRI_KEY_LENGTH], d5[SM2_PRI_KEY_LENGTH], d6[SM2_PRI_KEY_LENGTH];
    unsigned char t1[RANDOM_LENGTH];

    if (SAR_OK != getHardwareFactor(d2, d4, d6))
        return SAR_HARDWAREERR;
/*
    char d2str[256],d4str[256],d6str[256];
    unsignedCharToHexString(d2,SM2_PRI_KEY_LENGTH,d2str,256);
    unsignedCharToHexString(d4,SM2_PRI_KEY_LENGTH,d4str,256);
    unsignedCharToHexString(d6,SM2_PRI_KEY_LENGTH,d6str,256);
    writeLog("splitKeyWithRandom: d2=%s\n d4=%s\n d6=%s\n",d2str,d4str,d6str);
*/
    getPINFactor(pin, pinLength, d1, d5);
/*
    char d1str[256],d5str[256];
    unsignedCharToHexString(d1,SM2_PRI_KEY_LENGTH,d1str,256);
    unsignedCharToHexString(d5,SM2_PRI_KEY_LENGTH,d5str,256);
    writeLog("splitKeyWithRandom: d1=%s\n d5=%s\n",d1str,d5str);
*/

    CMpi d3_mpi, d7_mpi, t1_mpi, w1_mpi, w2_mpi, w3_mpi;
    CMpl tmp_l;
    CMpi D_mpi, p_x_mpi, p_y_mpi, p_z_mpi;

    do {
        //getRandom(d3, SM2_PRI_KEY_LENGTH);
        d3_mpi.Import(d3, SM2_PRI_KEY_LENGTH);
        tmp_l = d3_mpi;
        tmp_l %= g_paramN.m_oModulus;
        d3_mpi = tmp_l.l;

        //getRandom(d7, SM2_PRI_KEY_LENGTH);
        d7_mpi.Import(d7, SM2_PRI_KEY_LENGTH);
        tmp_l = d7_mpi;
        tmp_l %= g_paramN.m_oModulus;
        d7_mpi = tmp_l.l;

        getRandom(t1, SM2_PRI_KEY_LENGTH);
        t1_mpi.Import(t1, SM2_PRI_KEY_LENGTH);
        tmp_l = t1_mpi;
        tmp_l %= g_paramN.m_oModulus;
        t1_mpi = tmp_l.l;

        //w1=t1的逆
        w1_mpi = g_paramN.BinaryInverse(t1_mpi);

        //w2=d3*t1
        tmp_l = d3_mpi * t1_mpi;
        tmp_l %= g_paramN.m_oModulus;
        w2_mpi = tmp_l.l;

        //w3=d7*t1
        tmp_l = d7_mpi * t1_mpi;
        tmp_l %= g_paramN.m_oModulus;
        w3_mpi = tmp_l.l;

        w1_mpi.Export(w1, SM2_PRI_KEY_LENGTH);
        w2_mpi.Export(w2, SM2_PRI_KEY_LENGTH);
        w3_mpi.Export(w3, SM2_PRI_KEY_LENGTH);

        //求完整私钥
        combineKey(D, SM2_PRI_KEY_LENGTH, d1, d2, d4, d5, d6, w1, w2, w3);
        D_mpi.Import(D, SM2_PRI_KEY_LENGTH);
        //求公钥
        cc.MultiplyGByTable(p_x_mpi, p_y_mpi, p_z_mpi, D_mpi);
        cc.Jacobian2Stand(p_x_mpi, p_y_mpi, p_z_mpi);

    } while (D_mpi == 0|| p_y_mpi == 0);  //
    //导出公钥
    p_x_mpi.Export(P, SM2_PUB_KEY_LENGTH_HALF);
    p_y_mpi.Export(P + SM2_PUB_KEY_LENGTH_HALF, SM2_PUB_KEY_LENGTH_HALF);

    *DLength = SM2_PRI_KEY_LENGTH;
    *PLength=SM2_PUB_KEY_LENGTH;
    //*d3Length=*d7Length=SM2_PRI_KEY_LENGTH;
    *w1Length = *w2Length = *w3Length = SM2_PRI_KEY_LENGTH;

    CMpi D1_inv_mpi = g_paramN.BinaryInverse(D_mpi);
    unsigned char t[RANDOM_LENGTH];
    D1_inv_mpi.Export(t, 32);

    getRandom(t7, RANDOM_LENGTH);
    *t7Length = SM2_PRI_KEY_LENGTH;
    get_T(t, t1, d2, d4, d5, d6, t7, t3, t3Length);

    return SAR_OK;
}

ULONG splitKey(const unsigned char *pin, const int pinLength, unsigned char *P, int *PLength,
               unsigned char *w1, int *w1Length,
               unsigned char *w2, int *w2Length, unsigned char *w3, int *w3Length, unsigned char *t3,
               int *t3Length,
               unsigned char *t7, int *t7Length, unsigned char *D,
               int *DLength) {
    if (NULL == pin || NULL == w1 || NULL == w2 || NULL == w3 || NULL == w1Length ||
        NULL == w2Length || NULL == w3Length || NULL == D || NULL == DLength || NULL == t3 ||
        NULL == t3Length || NULL == t7 || NULL == t7Length)
        return SAR_INDATAERR;
    if (SM2_PUB_KEY_LENGTH > *PLength || SM2_PRI_KEY_LENGTH > *w1Length ||
        SM2_PRI_KEY_LENGTH > *w2Length || SM2_PRI_KEY_LENGTH > *w3Length ||
        SM2_PRI_KEY_LENGTH > *DLength || SM2_PRI_KEY_LENGTH > *t3Length ||
        SM2_PRI_KEY_LENGTH > *t7Length)
        return SAR_INDATALENERR;
    unsigned char d1[SM3_HASH_LENGTH], d2[SM3_HASH_LENGTH], d3[SM3_HASH_LENGTH], d4[SM3_HASH_LENGTH], d5[SM3_HASH_LENGTH], d6[SM3_HASH_LENGTH], d7[SM3_HASH_LENGTH];
    unsigned char t1[RANDOM_LENGTH];

    if (SAR_OK != getHardwareFactor(d2, d4, d6))
        return SAR_HARDWAREERR;
    getPINFactor(pin, pinLength, d1, d5);

    CMpi d3_mpi, d7_mpi, t1_mpi, w1_mpi, w2_mpi, w3_mpi;
    CMpl tmp_l;
    CMpi D_mpi, p_x_mpi, p_y_mpi, p_z_mpi;
    //unsigned char t[RANDOM_LENGTH];

    do {
        getRandom(d3, RANDOM_LENGTH);
        d3_mpi.Import(d3, RANDOM_LENGTH);
        tmp_l = d3_mpi;
        tmp_l %= g_paramN.m_oModulus;
        d3_mpi = tmp_l.l;

        getRandom(d7, RANDOM_LENGTH);
        d7_mpi.Import(d7, RANDOM_LENGTH);
        tmp_l = d7_mpi;
        tmp_l %= g_paramN.m_oModulus;
        d7_mpi = tmp_l.l;

        getRandom(t1, RANDOM_LENGTH);
        t1_mpi.Import(t1, RANDOM_LENGTH);
        tmp_l = t1_mpi;
        tmp_l %= g_paramN.m_oModulus;
        t1_mpi = tmp_l.l;

        //w1=t1的逆
        w1_mpi = g_paramN.BinaryInverse(t1_mpi);

        //w2=d3*t1
        tmp_l = d3_mpi * t1_mpi;
        tmp_l %= g_paramN.m_oModulus;
        w2_mpi = tmp_l.l;

        //w3=d7*t1
        tmp_l = d7_mpi * t1_mpi;
        tmp_l %= g_paramN.m_oModulus;
        w3_mpi = tmp_l.l;

        w1_mpi.Export(w1, RANDOM_LENGTH);
        w2_mpi.Export(w2, RANDOM_LENGTH);
        w3_mpi.Export(w3, RANDOM_LENGTH);

        //求完整私钥
        combineKey(D, SM2_PRI_KEY_LENGTH, d1, d2, d4, d5, d6, w1, w2, w3);
        D_mpi.Import(D, SM2_PRI_KEY_LENGTH);
        //求公钥
//        cc.MultiplyGByTable(p_x_mpi, p_y_mpi, p_z_mpi, D_mpi);
//        cc.Jacobian2Stand(p_x_mpi, p_y_mpi, p_z_mpi);

    } while (D_mpi == 0);  //|| p_y_mpi == 0
    //导出公钥
    //p_x_mpi.Export(P, SM2_PUB_KEY_LENGTH_HALF);
    //p_y_mpi.Export(P + SM2_PUB_KEY_LENGTH_HALF, SM2_PUB_KEY_LENGTH_HALF);
    *DLength = SM2_PRI_KEY_LENGTH;
    *w1Length = *w2Length = *w3Length = SM2_PRI_KEY_LENGTH;

    CMpi D1_inv_mpi = g_paramN.BinaryInverse(D_mpi);
    unsigned char t[RANDOM_LENGTH];
    D1_inv_mpi.Export(t, 32);

    getRandom(t7, RANDOM_LENGTH);
    *t7Length = SM2_PRI_KEY_LENGTH;
    get_T(t, t1, d2, d4, d5, d6, t7, t3, t3Length);

#ifdef DEBUG_LOG
/*
    writeLog("Root key splited");
    char factor[1024];
    writeLog("PIN:%s\n", pin);
    unsignedCharToHexString(d1, sizeof(d1), factor, 1024);
    writeLog("d1:%s\n", factor);
    unsignedCharToHexString(d2, sizeof(d2), factor, 1024);
    writeLog("d2:%s\n", factor);
    unsignedCharToHexString(d3, sizeof(d3), factor, 1024);
    writeLog("d3:%s\n", factor);
    unsignedCharToHexString(d4, sizeof(d4), factor, 1024);
    writeLog("d4:%s\n", factor);
    unsignedCharToHexString(d5, sizeof(d5), factor, 1024);
    writeLog("d5:%s\n", factor);
    unsignedCharToHexString(d6, sizeof(d6), factor, 1024);
    writeLog("d6:%s\n", factor);
    unsignedCharToHexString(d7, sizeof(d7), factor, 1024);
    writeLog("d7:%s\n", factor);
    unsignedCharToHexString(w1, *w1Length, factor, 1024);
    writeLog("w1:%s\n", factor);
    unsignedCharToHexString(w2, *w2Length, factor, 1024);
    writeLog("w2:%s\n", factor);
    unsignedCharToHexString(w3, *w3Length, factor, 1024);
    writeLog("w3:%s\n", factor);
    unsignedCharToHexString(t, sizeof(t), factor, 1024);
    writeLog("t:%s\n", factor);
    unsignedCharToHexString(t1, sizeof(t1), factor, 1024);
    writeLog("t1:%s\n", factor);
    unsignedCharToHexString(t3, *t3Length, factor, 1024);
    writeLog("t3:%s\n", factor);
    unsignedCharToHexString(t7, *t7Length, factor, 1024);
    writeLog("t7:%s\n", factor);

    unsignedCharToHexString(D, *DLength, factor, 1024);
    writeLog("D:%s\n", factor);
    unsignedCharToHexString(P, *PLength, factor, 1024);
    writeLog("P:%s\n", factor);
*/
#endif

    return SAR_OK;
}

ULONG resplitKeyWithRandom(const unsigned char *oldPIN, const int oldPINLength,
                           const unsigned char *oldw1, const int oldw1Length, const unsigned char *oldw2,
                           const int oldw2Length, const unsigned char *oldw3, const int oldw3Length, const unsigned char *oldt3,
                           const int oldt3Length, const unsigned char *oldt7, const int oldt7Length,
                           const unsigned char *newPIN, const int newPINLength, unsigned char *newd3, int* newd3Length,
                           unsigned char *newd7, int* newd7Length,
                           unsigned char *neww1, int *neww1Length, unsigned char *neww2, int *neww2Length,
                           unsigned char *neww3, int *neww3Length, unsigned char *newt3, int *newt3Length,
                           unsigned char *newt7, int *newt7Length) {
    if (NULL == oldPIN || NULL == oldw1 || NULL == oldw2 || NULL == oldw3 || NULL == oldt3 || NULL == oldt7 || NULL == newPIN || NULL == newd3 ||
        NULL == newd3Length ||
        NULL == newd7 || NULL == newd7Length || NULL == neww1 || NULL == neww1Length || NULL == neww2 || NULL == neww2Length || NULL == neww3 ||
        NULL == neww3Length ||
        NULL == newt3 || NULL == newt3Length || NULL == newt7 || NULL == newt7Length)
        return SAR_INDATAERR;
    if(SM2_PRI_KEY_LENGTH>oldw1Length || SM2_PRI_KEY_LENGTH>oldw2Length || SM2_PRI_KEY_LENGTH>oldw3Length || SM2_PRI_KEY_LENGTH > oldt3Length || SM2_PRI_KEY_LENGTH>oldt7Length)
        return SAR_INDATALENERR;
    unsigned char oldd1[SM3_HASH_LENGTH], d2[SM3_HASH_LENGTH], d4[SM3_HASH_LENGTH], oldd5[SM3_HASH_LENGTH], d6[SM3_HASH_LENGTH];
    unsigned char newt1[RANDOM_LENGTH], newd1[SM3_HASH_LENGTH], newd5[SM3_HASH_LENGTH];

    if (SAR_OK != getHardwareFactor(d2, d4, d6))
        return SAR_HARDWAREERR;
    getPINFactor(oldPIN, oldPINLength, oldd1, oldd5);

    //求新的d7
    CMpi d2_mpi, d4_mpi, d6_mpi;
    CMpi old_d1_mpi, old_d5_mpi, old_w1_mpi, old_w2_mpi, old_w3_mpi;
    CMpi new_d1_mpi, new_d5_mpi, new_w1_mpi, new_w2_mpi, new_w3_mpi;
    CMpi new_t1_mpi, new_d3_mpi, new_d7_mpi;

    //随机生成新的t1,d3
    //region 计算新的 d1,d3,d5, t1, w1,w2,w3 (d2,d4,d6不变)
    getRandom(newt1, RANDOM_LENGTH);
    getRandom(newd3, RANDOM_LENGTH);
    getPINFactor(newPIN, newPINLength, newd1, newd5);
    d2_mpi.Import(d2, 32);
    d4_mpi.Import(d4, 32);
    d6_mpi.Import(d6, 32);
    old_d1_mpi.Import(oldd1, 32);
    old_d5_mpi.Import(oldd5, 32);
    old_w1_mpi.Import(oldw1, 32);
    old_w2_mpi.Import(oldw2, 32);
    old_w3_mpi.Import(oldw3, 32);

    new_t1_mpi.Import(newt1, 32);
    new_d1_mpi.Import(newd1, 32);
    new_d3_mpi.Import(newd3, 32);
    new_d5_mpi.Import(newd5, 32);

    //求取新的d7
    CMpl tmp_l, tmp_l2;
    //d1 + d3*(d4+d5*d6)+d7
    tmp_l = old_d5_mpi * d6_mpi;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l = d4_mpi + tmp_l.l;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l = old_w1_mpi * tmp_l.l;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l = old_w2_mpi * tmp_l.l;
    tmp_l %= g_paramN.m_oModulus;
    //+d1
    tmp_l = tmp_l.l + old_d1_mpi;
    tmp_l %= g_paramN.m_oModulus;
    //+d7
    tmp_l2 = old_w1_mpi * old_w3_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l + tmp_l2.l;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l2 = new_d5_mpi * d6_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = d4_mpi + tmp_l2.l;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = tmp_l2.l * new_d3_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = tmp_l2.l + new_d1_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l + g_paramN.m_oModulus;
    tmp_l -= tmp_l2;
    tmp_l %= g_paramN.m_oModulus;
    //求出d7
    new_d7_mpi = tmp_l.l;
    //求出新的w1,w2,w3
    new_w1_mpi = g_paramN.BinaryInverse(new_t1_mpi);

    tmp_l = new_t1_mpi * new_d3_mpi;
    tmp_l %= g_paramN.m_oModulus;
    new_w2_mpi = tmp_l.l;

    tmp_l = new_t1_mpi * new_d7_mpi;
    tmp_l %= g_paramN.m_oModulus;
    new_w3_mpi = tmp_l.l;

    new_d7_mpi.Export(newd7, 32);
    //endregion

    new_w1_mpi.Export(neww1, 32);
    new_w2_mpi.Export(neww2, 32);
    new_w3_mpi.Export(neww3, 32);
    *neww1Length = *neww2Length = *neww3Length = SM2_PRI_KEY_LENGTH;
    //region 计算新的t3,t7
    getRandom(newt7, 32);

    CMpi t2_mpi, t4_mpi, t6_mpi;

    CMpi old_t5_mpi;
    CMpi new_t5_mpi;

    CMpi old_t3_mpi, old_t7_mpi;
    CMpi new_t3_mpi, new_t7_mpi;

    t2_mpi.Import(d2, 32);
    t4_mpi.Import(d4, 32);
    t6_mpi.Import(d6, 32);
    //旧PIN码因子
    old_t5_mpi.Import(oldd5, 32);
    //旧随机数
    old_t3_mpi.Import(oldt3, 32);
    old_t7_mpi.Import(oldt7, 32);

    //新PIN码因子
    new_t5_mpi.Import(newd5, 32);
    //新随机数
    new_t7_mpi.Import(newt7, 32);

    //求新的拆分因子t3
    tmp_l = t6_mpi * old_t7_mpi;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l = old_d5_mpi + tmp_l.l;
    tmp_l %= g_paramN.m_oModulus;

    tmp_l2 = d4_mpi * d4_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l * tmp_l2.l;
    tmp_l %= g_paramN.m_oModulus;

    tmp_l2 = t2_mpi * old_t3_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l + tmp_l2.l;
    tmp_l %= g_paramN.m_oModulus;

    //+t1
    tmp_l = tmp_l.l + g_paramN.BinaryInverse(old_w1_mpi);
    tmp_l %= g_paramN.m_oModulus;

    CMpl tmp_l3;
    tmp_l2 = t6_mpi * new_t7_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = tmp_l2.l + new_t5_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l3 = t4_mpi * t4_mpi;
    tmp_l3 %= g_paramN.m_oModulus;

    //*d4*d4
    tmp_l2 = tmp_l2.l * tmp_l3.l;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l2 = tmp_l2.l + new_t1_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l + g_paramN.m_oModulus;
    tmp_l -= tmp_l2;
    tmp_l %= g_paramN.m_oModulus;

    //*t2的逆
    tmp_l = tmp_l.l * g_paramN.BinaryInverse(t2_mpi);
    tmp_l %= g_paramN.m_oModulus;

    //求出new_t3
    new_t3_mpi = tmp_l.l;
    //endregion

    //保存新的拆分因子
    new_t3_mpi.Export(newt3, 32);
    new_t7_mpi.Export(newt7, 32);
    *newt3Length = *newt7Length = SM2_PRI_KEY_LENGTH;

    return SAR_OK;
}

ULONG resplitKey(const unsigned char *oldPIN, const int oldPINLength,
                 const unsigned char *oldw1, const int oldw1Length, const unsigned char *oldw2,
                 const int oldw2Length,
                 const unsigned char *oldw3, const int oldw3Length, const unsigned char *oldt3,
                 const int oldt3Length, const unsigned char *oldt7, const int oldt7Length,
                 const unsigned char *newPIN, const int newPINLength, unsigned char *neww1,
                 int *neww1Length, unsigned char *neww2, int *neww2Length,
                 unsigned char *neww3, int *neww3Length, unsigned char *newt3, int *newt3Length,
                 unsigned char *newt7, int *newt7Length) {
    if (NULL == oldPIN || NULL == oldw1 || NULL == oldw2 || NULL == oldw3 || NULL == oldt3 ||
        NULL == oldt7 || NULL == newPIN || NULL == neww1 || NULL == neww1Length || NULL == neww2 ||
        NULL == neww2Length
        || NULL == neww3 || NULL == neww3Length || NULL == newt3 || NULL == newt3Length ||
        NULL == newt7 || NULL == newt7Length)
        return SAR_INDATAERR;
    if(SM2_PRI_KEY_LENGTH>oldw1Length || SM2_PRI_KEY_LENGTH>oldw2Length || SM2_PRI_KEY_LENGTH>oldw3Length || SM2_PRI_KEY_LENGTH>oldt3Length||SM2_PRI_KEY_LENGTH>oldt7Length){
        return SAR_INDATALENERR;
    }

    unsigned char oldd1[SM3_HASH_LENGTH], d2[SM3_HASH_LENGTH], d4[SM3_HASH_LENGTH], oldd5[SM3_HASH_LENGTH], d6[SM3_HASH_LENGTH];
    unsigned char newt1[RANDOM_LENGTH], newd1[SM3_HASH_LENGTH], newd5[SM3_HASH_LENGTH], newd3[SM3_HASH_LENGTH], newd7[SM3_HASH_LENGTH];

    if (SAR_OK != getHardwareFactor(d2, d4, d6))
        return SAR_HARDWAREERR;
    getPINFactor(oldPIN, oldPINLength, oldd1, oldd5);

    //求新的d7
    CMpi d2_mpi, d4_mpi, d6_mpi;
    CMpi old_d1_mpi, old_d5_mpi, old_w1_mpi, old_w2_mpi, old_w3_mpi;
    CMpi new_d1_mpi, new_d5_mpi, new_w1_mpi, new_w2_mpi, new_w3_mpi;
    CMpi new_t1_mpi, new_d3_mpi, new_d7_mpi;

    //随机生成新的t1,d3
    //region 计算新的 d1,d3,d5, t1, w1,w2,w3 (d2,d4,d6不变)
    getRandom(newt1, RANDOM_LENGTH);
    getRandom(newd3, RANDOM_LENGTH);
    getPINFactor(newPIN, newPINLength, newd1, newd5);
    d2_mpi.Import(d2, 32);
    d4_mpi.Import(d4, 32);
    d6_mpi.Import(d6, 32);
    old_d1_mpi.Import(oldd1, 32);
    old_d5_mpi.Import(oldd5, 32);
    old_w1_mpi.Import(oldw1, 32);
    old_w2_mpi.Import(oldw2, 32);
    old_w3_mpi.Import(oldw3, 32);

    new_t1_mpi.Import(newt1, 32);
    new_d1_mpi.Import(newd1, 32);
    new_d3_mpi.Import(newd3, 32);
    new_d5_mpi.Import(newd5, 32);

    //求取新的d7
    CMpl tmp_l, tmp_l2;
    //d1 + d3*(d4+d5*d6)+d7
    tmp_l = old_d5_mpi * d6_mpi;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l = d4_mpi + tmp_l.l;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l = old_w1_mpi * tmp_l.l;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l = old_w2_mpi * tmp_l.l;
    tmp_l %= g_paramN.m_oModulus;
    //+d1
    tmp_l = tmp_l.l + old_d1_mpi;
    tmp_l %= g_paramN.m_oModulus;
    //+d7
    tmp_l2 = old_w1_mpi * old_w3_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l + tmp_l2.l;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l2 = new_d5_mpi * d6_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = d4_mpi + tmp_l2.l;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = tmp_l2.l * new_d3_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = tmp_l2.l + new_d1_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l + g_paramN.m_oModulus;
    tmp_l -= tmp_l2;
    tmp_l %= g_paramN.m_oModulus;
    //求出d7
    new_d7_mpi = tmp_l.l;
    //求出新的w1,w2,w3
    new_w1_mpi = g_paramN.BinaryInverse(new_t1_mpi);

    tmp_l = new_t1_mpi * new_d3_mpi;
    tmp_l %= g_paramN.m_oModulus;
    new_w2_mpi = tmp_l.l;

    tmp_l = new_t1_mpi * new_d7_mpi;
    tmp_l %= g_paramN.m_oModulus;
    new_w3_mpi = tmp_l.l;

    new_d7_mpi.Export(newd7, 32);
    //endregion

    new_w1_mpi.Export(neww1, 32);
    new_w2_mpi.Export(neww2, 32);
    new_w3_mpi.Export(neww3, 32);
    *neww1Length = *neww2Length = *neww3Length = SM2_PRI_KEY_LENGTH;
    //region 计算新的t3,t7
    getRandom(newt7, 32);

    CMpi t2_mpi, t4_mpi, t6_mpi;

    CMpi old_t5_mpi;
    CMpi new_t5_mpi;

    CMpi old_t3_mpi, old_t7_mpi;
    CMpi new_t3_mpi, new_t7_mpi;

    t2_mpi.Import(d2, 32);
    t4_mpi.Import(d4, 32);
    t6_mpi.Import(d6, 32);
    //旧PIN码因子
    old_t5_mpi.Import(oldd5, 32);
    //旧随机数
    old_t3_mpi.Import(oldt3, 32);
    old_t7_mpi.Import(oldt7, 32);

    //新PIN码因子
    new_t5_mpi.Import(newd5, 32);
    //新随机数
    new_t7_mpi.Import(newt7, 32);

    //求新的拆分因子t3
    tmp_l = t6_mpi * old_t7_mpi;
    tmp_l %= g_paramN.m_oModulus;
    tmp_l = old_d5_mpi + tmp_l.l;
    tmp_l %= g_paramN.m_oModulus;

    tmp_l2 = d4_mpi * d4_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l * tmp_l2.l;
    tmp_l %= g_paramN.m_oModulus;

    tmp_l2 = t2_mpi * old_t3_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l + tmp_l2.l;
    tmp_l %= g_paramN.m_oModulus;

    //+t1
    tmp_l = tmp_l.l + g_paramN.BinaryInverse(old_w1_mpi);
    tmp_l %= g_paramN.m_oModulus;

    CMpl tmp_l3;
    tmp_l2 = t6_mpi * new_t7_mpi;
    tmp_l2 %= g_paramN.m_oModulus;
    tmp_l2 = tmp_l2.l + new_t5_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l3 = t4_mpi * t4_mpi;
    tmp_l3 %= g_paramN.m_oModulus;

    //*d4*d4
    tmp_l2 = tmp_l2.l * tmp_l3.l;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l2 = tmp_l2.l + new_t1_mpi;
    tmp_l2 %= g_paramN.m_oModulus;

    tmp_l = tmp_l.l + g_paramN.m_oModulus;
    tmp_l -= tmp_l2;
    tmp_l %= g_paramN.m_oModulus;

    //*t2的逆
    tmp_l = tmp_l.l * g_paramN.BinaryInverse(t2_mpi);
    tmp_l %= g_paramN.m_oModulus;

    //求出new_t3
    new_t3_mpi = tmp_l.l;
    //endregion

    //保存新的拆分因子
    new_t3_mpi.Export(newt3, 32);
    new_t7_mpi.Export(newt7, 32);
    *newt3Length = *newt7Length = SM2_PRI_KEY_LENGTH;

#ifdef DEBUG_LOG
/*
    writeLog("Root key resplited");
    char factor[1024];
    writeLog("Old PIN:%s\n", oldPIN);
    writeLog("New PIN:%s\n", newPIN);
    unsignedCharToHexString(newd1, sizeof(newd1), factor, 1024);
    writeLog("d1:%s\n", factor);
    unsignedCharToHexString(d2, sizeof(d2), factor, 1024);
    writeLog("d2:%s\n", factor);
    unsignedCharToHexString(newd3, sizeof(newd3), factor, 1024);
    writeLog("d3:%s\n", factor);
    unsignedCharToHexString(d4, sizeof(d4), factor, 1024);
    writeLog("d4:%s\n", factor);
    unsignedCharToHexString(newd5, sizeof(newd5), factor, 1024);
    writeLog("d5:%s\n", factor);
    unsignedCharToHexString(d6, sizeof(d6), factor, 1024);
    writeLog("d6:%s\n", factor);
    unsignedCharToHexString(newd7, sizeof(newd7), factor, 1024);
    writeLog("d7:%s\n", factor);
    unsignedCharToHexString(neww1, *neww1Length, factor, 1024);
    writeLog("w1:%s\n", factor);
    unsignedCharToHexString(neww2, *neww2Length, factor, 1024);
    writeLog("w2:%s\n", factor);
    unsignedCharToHexString(neww3, *neww3Length, factor, 1024);
    writeLog("w3:%s\n", factor);
    unsignedCharToHexString(newt1, sizeof(newt1), factor, 1024);
    writeLog("t1:%s\n", factor);
    unsignedCharToHexString(newt3, *newt3Length, factor, 1024);
    writeLog("t3:%s\n", factor);
    unsignedCharToHexString(newt7, *newt7Length, factor, 1024);
    writeLog("t7:%s\n", factor);
*/
#endif

    return SAR_OK;
}

ULONG pkcs5Padding(const unsigned char *src, const ULONG srcLength, const int blockSize, unsigned char *paddedSrc, ULONG *paddedSrcLength) {
    if (NULL == src || NULL == paddedSrc || NULL == paddedSrcLength)
        return SAR_INDATAERR;
    int paddingLength = blockSize - (srcLength % blockSize);
    int newLength = srcLength + paddingLength;
    if (newLength > *paddedSrcLength)
        return SAR_INDATALENERR;
    memcpy(paddedSrc, src, (size_t) srcLength);
    memset(paddedSrc + srcLength, (unsigned char) paddingLength, (size_t) paddingLength);
    *paddedSrcLength = newLength;
    return SAR_OK;
}

ULONG pkcs5Unpadding(const unsigned char *paddedSrc, const ULONG paddedSrcLength, const int blockSize, unsigned char *src, ULONG *srcLength) {
    if (NULL == paddedSrc || NULL == src || NULL == srcLength)
        return SAR_INDATAERR;
    if (paddedSrcLength < blockSize)
        return SAR_INDATALENERR;
    int paddingLength = paddedSrc[paddedSrcLength - 1];
    int newLength = paddedSrcLength - paddingLength;
    if (newLength > *srcLength)
        return SAR_INDATALENERR;
    memcpy(src, paddedSrc, (size_t) newLength);
    *srcLength = newLength;
    return SAR_OK;
}

ULONG encryptDataBySM4(const unsigned char *key, const unsigned char *plain, const ULONG plainLength,
                       const int paddingType, const int feedBitLength, unsigned char *cipher,
                       ULONG *cipherLength) {
    if (NULL == key)
        return SAR_INDATAERR;

    sm4_context context;
    context.mode = sm4_mode::SM4_ENCRYPT;
    Sms4ExtendKey(context.sk, key);
    return encryptDataBySM4SubKey(context.sk, plain, plainLength, paddingType, feedBitLength, cipher, cipherLength);
}

ULONG encryptDataBySM4SubKey(const unsigned int *subkey, const unsigned char *plain,
                             const ULONG plainLength,
                             const int paddingType, const int feedBitLength, unsigned char *cipher,
                             ULONG *cipherLength) {
    if (NULL == subkey || NULL == plain || NULL == cipher || NULL == cipherLength)
        return SAR_INDATAERR;
    ULONG ret = SAR_OK;
    ULONG paddedPlainLength = 0;
    unsigned char *paddedPlain = NULL;
    switch (paddingType) {
        case PaddingType::NoPadding:
            if (plainLength % SMS4_BLOCK_LENGTH != 0)
                ret = SAR_INVALIDPARAMERR;
            else {
                paddedPlainLength = plainLength;
                paddedPlain = (unsigned char *) malloc(paddedPlainLength);
                memcpy(paddedPlain, plain, paddedPlainLength);
            }
            break;
        case PaddingType::PKCS5Padding:
            paddedPlainLength = (plainLength / SMS4_BLOCK_LENGTH + 1) * SMS4_BLOCK_LENGTH;
            if (paddedPlainLength > *cipherLength)
                ret = SAR_INDATALENERR;
            else {
                paddedPlain = (unsigned char *) malloc(paddedPlainLength);
                if (SAR_OK != pkcs5Padding(plain, plainLength, SMS4_BLOCK_LENGTH, paddedPlain,
                                           &paddedPlainLength))
                    ret = SAR_DECRYPTPADERR;
            }
            break;
        default:
            ret = SAR_NOTSUPPORTYETERR;
            break;
    }
    if (SAR_OK == ret) {
        if (*cipherLength < paddedPlainLength)
            ret = SAR_BUFFERTOOSMALL;
        else {
            int blockCount = paddedPlainLength / SMS4_BLOCK_LENGTH;
            *cipherLength = paddedPlainLength;
            for (int index = 0; index < blockCount; index++)
                Sms4Encrypt(cipher + index * SMS4_BLOCK_LENGTH,
                            paddedPlain + index * SMS4_BLOCK_LENGTH,
                            subkey);
        }
    }
    SAFE_FREE(paddedPlain)
    return ret;
}


ULONG decryptDataBySM4(const unsigned char *key, const unsigned char *cipher, const ULONG cipherLength,
                       const int paddingType, const int feedBitLength, unsigned char *plain,
                       ULONG *plainLength) {
    if (NULL == key)
        return SAR_INDATAERR;
    sm4_context context;
    context.mode = sm4_mode::SM4_DECRYPT;
    Sms4ExtendKey(context.sk, key);
    return decryptDataBySM4SubKey(context.sk, cipher, cipherLength, paddingType, feedBitLength, plain, plainLength);
}

ULONG decryptDataBySM4SubKey(const unsigned int *subkey, const unsigned char *cipher,
                             const ULONG cipherLength,
                             const int paddingType, const int feedBitLength, unsigned char *plain,
                             ULONG *plainLength) {
    if (NULL == subkey || NULL == cipher || NULL == plain || NULL == plainLength)
        return SAR_INDATAERR;
    if (0 != cipherLength % SMS4_BLOCK_LENGTH)
        return SAR_INDATALENERR;
    unsigned char *paddedPlain = (unsigned char *) malloc(cipherLength);
    int blockCount = cipherLength / SMS4_BLOCK_LENGTH;

    for (int index = 0; index < blockCount; index++)
        Sms4Decrypt(paddedPlain + index * SMS4_BLOCK_LENGTH, cipher + index * SMS4_BLOCK_LENGTH,
                    subkey);
    ULONG ret = SAR_OK;
    switch (paddingType) {
        case PaddingType::NoPadding:
            if (cipherLength > *plainLength)
                ret = SAR_DECRYPTPADERR;
            else {
                *plainLength = cipherLength;
                memcpy(plain, paddedPlain, *plainLength);
            }
            break;
        case PaddingType::PKCS5Padding:
            ret = pkcs5Unpadding(paddedPlain, cipherLength, SMS4_BLOCK_LENGTH, plain, plainLength);
            break;
        default:
            ret = SAR_NOTSUPPORTYETERR;
            break;
    }

    SAFE_FREE(paddedPlain)
    return ret;
}

ULONG encryptDataByCBCSM4SubKey(const unsigned char *plain,
                                const ULONG plainLength, sm4_context *ctx, unsigned char *iv,
                                const int paddingType, const int feedBitLength, unsigned char *cipher,
                                ULONG *cipherLength) {
    if (NULL == plain || NULL == cipher || NULL == cipherLength)
        return SAR_INDATAERR;
    //printHexString("encryptDataByCBCSM4SubKey:IV",iv,16);
    //printHexString("encryptDataByCBCSM4SubKey:plain",plain,plainLength);
    ULONG ret = SAR_OK;
    ULONG paddedPlainLength = 0;
    unsigned char *paddedPlain = NULL;
    switch (paddingType) {
        case PaddingType::NoPadding:
            if (plainLength % SMS4_BLOCK_LENGTH != 0)
                ret = SAR_INVALIDPARAMERR;
            else if (NULL == cipher) {
                *cipherLength = plainLength;
                return ret;
            } else {
                paddedPlainLength = plainLength;
                paddedPlain = (unsigned char *) malloc(paddedPlainLength);
                memcpy(paddedPlain, plain, paddedPlainLength);
            }
            break;
        case PaddingType::PKCS5Padding:
            paddedPlainLength = (plainLength / SMS4_BLOCK_LENGTH + 1) * SMS4_BLOCK_LENGTH;
            if (NULL == cipher) {
                *cipherLength = paddedPlainLength;
                return ret;
            }
            if (paddedPlainLength > *cipherLength)
                ret = SAR_INDATALENERR;
            else {
                paddedPlain = (unsigned char *) malloc(paddedPlainLength);
                if (SAR_OK != pkcs5Padding(plain, plainLength, SMS4_BLOCK_LENGTH, paddedPlain,
                                           &paddedPlainLength))
                    ret = SAR_ENCRYPTPADERR;
            }
            break;
        default:
            ret = SAR_NOTSUPPORTYETERR;
            break;
    }
    if (SAR_OK == ret) {
        if (*cipherLength < paddedPlainLength)
            ret = SAR_BUFFERTOOSMALL;
        else {
            *cipherLength = paddedPlainLength;
             sm4_crypt_cbc(ctx, SM4_ENCRYPT, paddedPlainLength, iv, paddedPlain, cipher);
            //printHexString("encryptDataByCBCSM4SubKey:cihper", cipher, paddedPlainLength);
        }
    }
    SAFE_FREE(paddedPlain)
    return ret;
}

ULONG decryptDataByCBCSM4SubKey(unsigned char *cipher,
                                const ULONG cipherLength,sm4_context*ctx,unsigned char *iv,
                                const int paddingType, const int feedBitLength, unsigned char *plain,
                                ULONG *plainLength) {
    if (NULL==iv||NULL==ctx||NULL == cipher || NULL == plain || NULL == plainLength)
        return SAR_INDATAERR;
    if (0 != cipherLength % SMS4_BLOCK_LENGTH)
        return SAR_INDATALENERR;
    //printHexString("decryptDataByCBCSM4SubKey:IV",iv,16);
    //printHexString("decryptDataByCBCSM4SubKey:cihper",cipher,cipherLength);
    unsigned char *paddedPlain = (unsigned char *) malloc(cipherLength);
    sm4_crypt_cbc(ctx, SM4_DECRYPT, cipherLength, iv, cipher, paddedPlain);

    ULONG ret = SAR_OK;
    switch (paddingType) {
        case PaddingType::NoPadding:
            if (cipherLength > *plainLength)
                ret = SAR_DECRYPTPADERR;
            else if(NULL==plain){
                *plainLength=cipherLength;;
            }else{
                *plainLength = cipherLength;
                memcpy(plain, paddedPlain, *plainLength);
            }
            break;
        case PaddingType::PKCS5Padding:
            if(NULL==plain){
                int paddingLength=paddedPlain[cipherLength-1];
                int newLength=cipherLength-paddingLength;
                *plainLength=newLength;
            }else{
                ret = pkcs5Unpadding(paddedPlain, cipherLength, SMS4_BLOCK_LENGTH, plain, plainLength);
            }
            break;
        default:
            ret=SAR_NOTSUPPORTYETERR;
            break;
    }
    //printHexString("decryptDataByCBCSM4SubKey:plain",plain,*plainLength);
    SAFE_FREE(paddedPlain)
    return ret;
}

void testSM4Cryptography() {
    unsigned char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char plain[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char plain2[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    unsigned char cipher[64], tempPlain[64];
    ULONG cipherLength = 64, tempPlainLength = 64;

    encryptDataBySM4(key, plain, 16, 0, 0, cipher, &cipherLength);

    decryptDataBySM4(key, cipher, cipherLength, 0, 0, tempPlain, &tempPlainLength);

    int ok = memcmp(plain, tempPlain, tempPlainLength);

    cipherLength = 64;
    tempPlainLength = 64;

    encryptDataBySM4(key, plain2, 8, 0, 0, cipher, &cipherLength);
    decryptDataBySM4(key, cipher, cipherLength, 0, 0, tempPlain, &tempPlainLength);

    ok = memcmp(plain2, tempPlain, tempPlainLength);
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
                      const int messagLength, const char *userName, const int userNameLength, unsigned char *signature, int *signatureLength) {
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
    unsigned char rnd[RANDOM_LENGTH];
    *signatureLength = pri.SignMessage(signature, message, messagLength, userName, userNameLength, rnd, RANDOM_LENGTH);
    return 0 == *signatureLength ? SAR_FAIL : SAR_OK;
}