//
// Created by lxb on 3/8/16.
//

#include "global.h"

#ifndef TESTNDK_MPI_H
#define TESTNDK_MPI_H

#endif //TESTNDK_MPI_H


#if !defined(AFX_MPI_H__B3328615_E05B_11D4_961E_0050FC0F4715__INCLUDED_)
#define AFX_MPI_H__B3328615_E05B_11D4_961E_0050FC0F4715__INCLUDED_

#ifdef _MSC_VER
#if _MSC_VER > 1000
    #pragma once
#endif // _MSC_VER > 1000
#endif // _MSC_VER

#if !defined(BYTE)
typedef unsigned char BYTE;
#endif

#ifndef NULL
#define NULL	0L
#endif // NULL


#define MPI_LENGTH		8


#define POSITIVE 1
#define NEGTIVE (-1)

#define HEX28BITS 0xFFFFFFF
#define HEX32BITS 0xFFFFFFFF
// #define MPI_INFINITE 0xFFFFFFF
#define UNSIGNEDLEFTBIT 0x80000000
#define BITS_OF_INT 32


#ifdef WIN32
#define DOUBLE_INT unsigned __int64
#else	// ARM ads
#define DOUBLE_INT unsigned long long
#define __max(x,y) (x>y?x:y)
#define __min(x,y) (x<y?x:y)
#endif

class CMpl;
class CModulus;

class CMpi
{
protected:
    unsigned int m_aiMyInt[MPI_LENGTH];
    unsigned int m_iCarry;
    int m_iMySign;
    int m_iLengthInInts;
public:
    int IsNegative() const;
    int GetLengthInBits() const;
    int Export(BYTE *abOutBytes, int iMinLength = 0) const;
    int Import(const BYTE *abContent, int iLength);
    int GetLengthInBytes() ;

    CMpi & BitShiftLeft(const int iShiftBits);
    CMpi & BitShiftRight(const int iShiftBits);
    void Regularize();
    void ChangeSign();
    CMpl FastSquare() const;
    CMpi & operator =(const CMpl &l) ;
    CMpl operator *(const CMpi &m) const;
    CMpi & operator *=(const unsigned int n);
    int operator !=(const unsigned int n) const;
    int operator ==(const unsigned int n) const;
    int operator !=(const CMpi &m) const;
    int operator ==(const CMpi &m) const;
    CMpi & operator <<=(const int n);
    CMpi & operator >>=(const int n);
    int operator << (const CMpi &m) const;
    int operator >> (const CMpi &m) const;
    int operator > (const CMpi &m) const;
    int operator < (const CMpi &m) const;
    CMpi & operator -=(const CMpi &m);
    CMpi operator -(const CMpi &m) const;
    CMpi operator -() const;
    CMpi operator + (const CMpi &m) const;
    CMpi & operator +=(const CMpi &m);

    CMpi(unsigned int iInitial);
    CMpi();
    friend class CMpl;
    friend class CModulus;
    friend class CEllipticCurve;
};


class CMpl
{
public:
    CMpl & BitShiftRight(const int iShiftBits);
    CMpl & BitShiftLeft(const int iShiftBits);
    CMpl();

    CMpl(const CMpi &m);
    CMpi & operator %=(const CMpi &m);
    CMpl & operator <<=(const int n);
    CMpl & operator >>=(const int n);
    CMpl & operator -=(const CMpl &oMpl);
    CMpl & operator +=(const CMpl &oMpl);
    int operator ==(const CMpl &oMpl) const;
    friend class CMpi;
    friend class CModulus;
    friend class CEllipticCurve;
    friend class CECCPrivateKey;

    CMpi h;
    CMpi l;
protected:
    void Reduction(const CMpi &m);
    void FastReduction(const CMpi &m);	// for P
};

class CModulus
{
public:
    CMpi m_oModulus;
    int GetLengthInBytes();
    CModulus(const CMpi &oMpi);
    CMpi BinaryInverse(const CMpi &oMpi);
    CModulus();
#define SIMUL_BINARY_CNT	MAX_SIM_QIUNI
    void SimultaneousBinaryInverse(CMpi *pOut, const CMpi *pIn, int cnt = SIMUL_BINARY_CNT);

};

#endif // !defined(AFX_MPI_H__B3328615_E05B_11D4_961E_0050FC0F4715__INCLUDED_)

