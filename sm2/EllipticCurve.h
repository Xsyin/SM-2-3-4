//
// Created by lxb on 3/8/16.
//

#if !defined(AFX_ELLIPTICCURVE_H__0372B568_C633_4807_B268_B59E2CDE28B5__INCLUDED_)
#define AFX_ELLIPTICCURVE_H__0372B568_C633_4807_B268_B59E2CDE28B5__INCLUDED_

#ifdef _MSC_VER
#if _MSC_VER > 1000
    #pragma once
#endif // _MSC_VER > 1000
#endif // _MSC_VER

#define DCS_ECC_KEY_LENGTH				32		// 256 = 8 * 32, in bytes, SM2�㷨��׼, 256 bits

#ifndef NULL
#define NULL    0
#endif



#define KDF				Sm3KDF
#define HASH_256		SM3_HASH_256
#define HASH_192		SM3_HASH_192
#define HASH_STATE		SM3_HASH_STATE
#define HashInit		Sm3HashInit
#define HashPending		Sm3HashPending
#define HashFinal		Sm3HashFinal

#include "Mpi.h"

// ����point at infinity, ��Ϊ(0, 0)
extern CModulus g_paramFieldP;

// �����������Բ����
class CEllipticCurve
{
public:
    int KeyExchangeRndMsg(unsigned char *pbRndMsg, const unsigned char *pbRnd, int iLenOfRnd);	// ��ԿЭ��ʱ���͵��������Ϣ
    static bool CheckPoint(const CMpi &x, const CMpi &y);


    CEllipticCurve();

    static void Jacobian2Stand(CMpi &x, CMpi &y, CMpi &z);		// ���ת��

    static void InitParam();		// �����ֵ

    const CMpi *GetN();

    int ExportPoint(unsigned char *pbOut, const CMpi &x, const CMpi &y, bool fCompression = false) const;
    int ImportPoint(const unsigned char *pbIn, int iInLen, CMpi &x, CMpi &y);

    void MultiplyGByTable(CMpi &x, CMpi &y, const CMpi &m);
    void MultiplyGByTable(CMpi &x, CMpi &y, CMpi &z, const CMpi &m);

    // (x, y) = m*(Gx, GY)
    void Multiply(CMpi &x, CMpi &y, const CMpi &m, const CMpi &Gx, const CMpi &Gy);
    // ����������ʹ�ñ�׼���
    void Multiply(CMpi &x, CMpi &y, CMpi &z, const CMpi &m, const CMpi &Gx, const CMpi &Gy);
    // ����ʹ�ñ�׼���(ǿ��z=1)�����ʹ��Jacobian���

    void DoubleMplJacobian(CMpi &x, CMpi &y, CMpi &z);		// (x, y, z) = (x, y, z) + (x, y, z)
    void DoubleMplJacobian(CMpi &x2, CMpi &y2, CMpi &z2, const CMpi &x, const CMpi &y, const CMpi &z);		// (x, y, z) = (x, y, z) + (x, y, z)
    // ����֮ǰ������CheckPoint

    // (x, y, z) = (x, y, z) + (mx, my, mz)
    void AddMplJacobian(CMpi &x, CMpi &y, CMpi &z, const CMpi &mx, const CMpi &my, const CMpi &mz);
    void AddMplJacobian(CMpi &x, CMpi &y, CMpi &z, const CMpi &mx, const CMpi &my);		// only for mz == 1
};



class CECCPublicKey : public CEllipticCurve
{
public:
    CECCPublicKey();

    int SetPublicKey(const unsigned char *pKey, int iLen);
    int ExportPublicKey(unsigned char *pOut) const;

    int HashUserId(unsigned char *pbOut, const char *pUserName, int iLenOfName) const;
    //  ǩ��ʱ, ��ǩ���ߵ�id���д���
    int MessageDigest(unsigned char *pbDigest, const unsigned char *pMsg, int iLenOfMsg, const char *pUserName, int iLenOfUserName);
    // ǩ��ʱ, ����������������
    int AuthenticateMsg(unsigned char *pDigest, const unsigned char *pSecret, const unsigned char *pMsg, int iLenOfMsg);
    // ����ʱ, ����У��ֵ

    int EncryptMessage(unsigned char *pbOut, const unsigned char *pbIn, int iLenOfIn, const unsigned char *pRnd, int iLenOfRnd);
    // ʹ��SM2�㷨, ���SM3 HASH�㷨��

    int VerifyMessage(const unsigned char *pMsg, int iLenOfMsg, const unsigned char *pSig, int iLenOfSig, const char *pUserName, int iLenOfUserName);

    const CMpi * GetParamPx() const { return &m_pntPx; };
    const CMpi * GetParamPy() const { return &m_pntPy; };
    int GetParamFieldPLength() const {return g_paramFieldP.GetLengthInBytes();};
    int Verify(const unsigned char *pDigest, int iLenOfDigest, const unsigned char *pSig, int iLenOfSig);

protected:
    int SetKey(const CMpi &paramPx, const CMpi &paramPy);		// ����ʱ, ����Px/Py���м��


    int Encrypt(unsigned char *pbCipher1, unsigned char *pbX2, unsigned char *pbY2, const unsigned char *pRnd, int iLenOfRnd);
    // pbCipher1 = k*G
    // pbCipher2(x2, y2) = [k*inv(h)]*[h]*P

    CMpi m_pntPx;			// ��ԿP��, P = D*G
    CMpi m_pntPy;
};

class CECCPrivateKey : public CECCPublicKey
{
public:
    CECCPrivateKey();

    int GenerateKey(const unsigned char *pRandomUser, // �������ṩ��������ṩ�������?
                    int iLenOfRandom); // pRandomUser��ָ�����ݳ���, in bytes


    int SetKey(const unsigned char *pKey, int iLen, bool fDataWithPublicKey = false);
    int OutputKey(unsigned char *pKey) const;

    int SignMessage(unsigned char *pOut, const unsigned char *pMsg, int iLenOfMsg, const char *pUserName, int iLenOfUserName, const unsigned char *pRnd, int iLenOfRnd);
    int DecryptMessage(unsigned char *pbOut, const unsigned char *pbIn, int iLenOfIn);

    int KeyExchangeResult(unsigned char *pOut, int iLenOut,
                          const unsigned char *pbMyRnd, int iLenOfRnd, const char *pMyUserName, int iLenOfMyUserName,
                          const unsigned char *pbOtherRndMsg, int iLenOfRndMsg, const CECCPublicKey *pOtherPublicKey, const char *pOtherUserName, int iLenOfOtherUserName,
                          bool fInit);

    const CMpi * GetParamD() const { return &m_paramD; };
    int Sign(unsigned char *pOut, const unsigned char *pIn, int iLen, const unsigned char *pRnd, int iLenOfRnd);


protected:
    int SetKey(const CMpi &paramD, bool fComputePubKey = true);		// fComputePubKey�Ƿ�Ҫ���㹫Կ��


    int Decrypt(const unsigned char *pbCipher1, int iLenOfCipher1, unsigned char *pbX2, unsigned char *pbY2);

    CMpi m_paramD;				// ˽Կ
    CMpi m_inverseDplus1;			// ���ڼ�ǩ�����

};

extern CModulus g_paramFieldP;
extern CModulus g_paramN;


#endif // !defined(AFX_ELLIPTICCURVE_H__0372B568_C633_4807_B268_B59E2CDE28B5__INCLUDED_)
