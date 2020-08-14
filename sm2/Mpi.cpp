//
// Created by lxb on 3/8/16.
//

#include "Mpi.h"
#include <string.h>
CMpi::CMpi()
{
    m_iCarry = 0;
}

CMpi::CMpi(unsigned int iInitial)
{
    m_iMySign = POSITIVE;

    if (iInitial==0)
        m_iLengthInInts = 0;
    else
        m_iLengthInInts = 1;
    m_aiMyInt[0]= iInitial;

    m_iCarry = 0;
}

CMpi & CMpi::operator +=(const CMpi &m)
{
    int i,j;
    register DOUBLE_INT direg;
    CMpi temp;
    m_iCarry = 0;
//	if (m_iMySign == MPI_INFINITE)
//		return *this;
//	if (m.m_iMySign == MPI_INFINITE)
//	{
//		m_iMySign = MPI_INFINITE;
//		return *this;
//	}
    if (m_iMySign==POSITIVE)
    {
        if (m.m_iMySign!=POSITIVE)
        {
            temp= -m;
            return operator -=(temp);
        }
    }
    else
    {
        if (m.m_iMySign==POSITIVE)
        {
            temp = -(*this);
            *this = m - temp ;
            return *this;
        }
    }

    j=__min(m_iLengthInInts,m.m_iLengthInInts);
    direg=0;
    for (i=0;i<j;i++)
    {
        direg+=m_aiMyInt[i];
        direg+=m.m_aiMyInt[i];
        m_aiMyInt[i]=(unsigned int)direg;
        direg>>=32;
    }

    if (m_iLengthInInts > m.m_iLengthInInts)
    {
        j = m_iLengthInInts;
        for (; i < j; i++)
        {
            direg+=m_aiMyInt[i];
            m_aiMyInt[i]=(unsigned int)direg;
            direg>>=32;
        }
    }
    else
    {
        j = m.m_iLengthInInts;
        for (; i < j; i++)
        {
            direg+=m.m_aiMyInt[i];
            m_aiMyInt[i]=(unsigned int)direg;
            direg>>=32;
        }
    }

    if (j==MPI_LENGTH)
    {
        m_iCarry = (unsigned int)direg;
        m_iLengthInInts = j;
    }
    else
    {
        m_aiMyInt[j]=(unsigned int)direg;
        if (m_aiMyInt[j])
            m_iLengthInInts=j+1;
        else
            m_iLengthInInts=j;
    }
    return *this;
}


CMpi CMpi::operator +(const CMpi &m) const
{
    CMpi Temp;
    Temp = *this;
    Temp += m;
    return Temp;
}

CMpi CMpi::operator -() const
{
    CMpi temp;
    temp = *this;
//	if (m_iMySign == MPI_INFINITE)
//		return temp;
    if (m_iMySign == POSITIVE)
        temp.m_iMySign = NEGTIVE;
    else
        temp.m_iMySign = POSITIVE;

    return temp;
}

CMpi CMpi::operator -(const CMpi &m) const
{
    CMpi temp = *this;
    temp -= m;
    return temp;
}

CMpi & CMpi::operator -=(const CMpi &m)
{
    int i,j;
    register DOUBLE_INT direg;
    const unsigned int *pm1, *pm2;
    int len2;

    m_iCarry = 0;
    if (m_iMySign!=m.m_iMySign)
    {
        CMpi temp;
        temp = -m;
        return operator +=(temp);
    }

    if (m >> *this)
    {
        pm2= m_aiMyInt;
        len2 = m_iLengthInInts;
        pm1= m.m_aiMyInt;

        if (m.m_iMySign == POSITIVE)
            m_iMySign = NEGTIVE;
        else
            m_iMySign = POSITIVE;
    }
    else
    {
        pm1 = m_aiMyInt;
        pm2 = m.m_aiMyInt;
        len2 = m.m_iLengthInInts;
    }
    j=__max(m_iLengthInInts,m.m_iLengthInInts);

#ifdef _MSC_VER
    direg=0x100000000L + pm1[0];
#else
    direg=0x100000000ll+ pm1[0];
#endif
    for (i=0;i<len2;i++)
    {
        direg -= pm2[i];
        m_aiMyInt[i]=(unsigned int)direg;
        direg >>= 32;
        direg += pm1[i+1];
        direg += 0xffffffffL;
    }

    for (; i < j; i++)
    {
        m_aiMyInt[i]=(unsigned int)direg;
        direg >>= 32;
        direg += pm1[i+1];
        direg += 0xffffffffL;
    }

    m_iLengthInInts=j;
    for (i=j-1;i>=0;i--)
    {
        if (m_aiMyInt[i])
            break;
        m_iLengthInInts=i;
    }
    return *this;
}

int CMpi::operator >>(const CMpi &m) const
{
    int i,j;
    j = __max(m_iLengthInInts,m.m_iLengthInInts);
    for (i=j-1;i>=0;i--)
    {
        if (m_iLengthInInts>i && m.m_iLengthInInts>i)
        {
            if (m_aiMyInt[i]>m.m_aiMyInt[i])
                return 1;
            if (m_aiMyInt[i]<m.m_aiMyInt[i])
                return 0;
        }
        else
        {
            if (m_iLengthInInts<=i)
            {
                if (m.m_aiMyInt[i])
                    return 0;
                else
                    continue;
            }
            if (m.m_iLengthInInts<=i)
            {
                if (m_aiMyInt[i])
                    return 1;
                else
                    continue;
            }
        }
    }
    return 0;
}

int CMpi::operator <<(const CMpi &m) const
{
    return (m>>(*this));
}

int CMpi::operator ==(const CMpi &m) const
{
    int i,j;
    j = __max(m_iLengthInInts,m.m_iLengthInInts);
    for (i=j-1;i>=0;i--)
    {
        if (m_iLengthInInts>i && m.m_iLengthInInts>i)
        {
            if (m_aiMyInt[i]!=m.m_aiMyInt[i])
                return 0;
            else
                continue;
        }
        if (m_iLengthInInts<=i)
        {
            if (m.m_aiMyInt[i])
                return 0;
            else
                continue;
        }
        if (m.m_iLengthInInts<=i)
        {
            if (m_aiMyInt[i])
                return 0;
            else
                continue;
        }
    }
    return 1;
}

CMpi & CMpi::operator *=(const unsigned int n)
{
    register DOUBLE_INT direg;
    unsigned int icarry = 0;
    int i;
    m_iCarry = 0;
    if (n==0)
    {
        m_iMySign = POSITIVE;
        m_iLengthInInts=0;
        m_aiMyInt[0]= 0;
        return (*this);
    }

    for (i=0;i<m_iLengthInInts;i++)
    {
        direg = m_aiMyInt[i];
        direg *= n;
        direg += icarry;
        m_aiMyInt[i] = (unsigned int) direg;
        icarry = (unsigned int)(direg>>32);
    }
    if (i==MPI_LENGTH)
    {
        m_iCarry = icarry;
    }
    else
    {
        if ((m_aiMyInt[i]=icarry))
            m_iLengthInInts=i+1;
    }
    return *this;
}

//		g_paramA.m_aiMyInt[0] = 0xFFFFFFFC;
//		g_paramA.m_aiMyInt[1] = 0xFFFFFFFF;
//		g_paramA.m_aiMyInt[2] = 0x00000000;
//		g_paramA.m_aiMyInt[3] = 0xFFFFFFFF;
//		g_paramA.m_aiMyInt[4] = 0xFFFFFFFF;
//		g_paramA.m_aiMyInt[5] = 0xFFFFFFFF;
//		g_paramA.m_aiMyInt[6] = 0xFFFFFFFF;
//		g_paramA.m_aiMyInt[7] = 0xFFFFFFFE;

/*
CMpl CMpi::FastMultiplication(const CMpi &m) const
{
	CMpl temp(*this);
	temp <<= MPI_LENGTH;

	CMpl temp2(*this);
	temp2 <<= (MPI_LENGTH-1);
	temp -= temp2;

	temp2 = *this;
	temp2 <<= 3;
	temp -= temp2;

	temp2 = *this;
	temp2 <<= 2;
	temp += temp2;

	temp2 = *this;
	temp2.BitShiftLeft(2);

	return temp -= temp2;
}
*/

CMpl CMpi::operator *(const CMpi &m) const
{
//	if (m.m_aiMyInt[0] == 0xFFFFFFFC
//		&& m.m_aiMyInt[1] == 0xFFFFFFFF
//		&& m.m_aiMyInt[2] == 0x00000000
//		&& m.m_aiMyInt[3] == 0xFFFFFFFF
//		&& m.m_aiMyInt[4] == 0xFFFFFFFF
//		&& m.m_aiMyInt[5] == 0xFFFFFFFF
//		&& m.m_aiMyInt[6] == 0xFFFFFFFF
//		&& m.m_aiMyInt[7] == 0xFFFFFFFE
//		&& m.m_iLengthInInts == MPI_LENGTH)
//	{
//		return FastMultiplication(m);
//	}

    CMpl temp;
    DOUBLE_INT direg = 0,sum;
    int i,j,k,len, n;
    unsigned int r[MPI_LENGTH*2] = {
            0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
    };

    int rlen = 0;
    len = m_iLengthInInts + m.m_iLengthInInts;

    for (i=0;i<MPI_LENGTH*2;i++)
        r[i]=0;

    for (k=0;k<len;k++)
    {
        for (i=0, n=k-i;i<=k;i++, n--)
        {
            if ((m_iLengthInInts>i) && m.m_iLengthInInts>n)
            {
                direg = m_aiMyInt[i];
                direg *= m.m_aiMyInt[n];

                sum = direg+r[k];
                r[k] = (unsigned int)sum;
                sum >>= BITS_OF_INT;

                sum += r[k+1];
                r[k+1] = (unsigned int)sum;
                sum >>= BITS_OF_INT;

                j = k+2;
                while (sum)
                {
                    sum += r[j];
                    r[j++] = (unsigned int)sum;
                    sum >>= BITS_OF_INT;
                }
            }

        }
    }

    for (i=MPI_LENGTH*2-1;i>=0;i--)
    {
        if (r[i])
            break;
    }
    rlen = i+1;

    if (rlen>MPI_LENGTH)
    {
        temp.l.m_iLengthInInts = MPI_LENGTH;
        temp.h.m_iLengthInInts = rlen - MPI_LENGTH;

        for (i=0;i<temp.h.m_iLengthInInts;i++)
            temp.h.m_aiMyInt[i]=r[i+MPI_LENGTH];
    }
    else
    {
        temp.l.m_iLengthInInts = rlen;
        temp.h.m_iLengthInInts = 0;
    }
    for (i=0;i<temp.l.m_iLengthInInts;i++)
        temp.l.m_aiMyInt[i]=r[i];

    if (m_iMySign == m.m_iMySign)
        temp.h.m_iMySign = temp.l.m_iMySign = POSITIVE;
    else
        temp.h.m_iMySign = temp.l.m_iMySign = NEGTIVE;

    return temp;
}

CMpi & CMpi::operator =(const CMpl &l)
{
    *this = l.l;
    m_iCarry = 0;
    return *this;
}

int CMpi::operator ==(const unsigned int n) const
{
    int i;
    if ((m_iLengthInInts==1 ) && (n==m_aiMyInt[0]))
        return 1;
    if ((m_iLengthInInts==0 ) && n==0)
        return 1;
    for (i=1;i<m_iLengthInInts;i++)
    {
        if (m_aiMyInt[i])
            return 0;
    }
    if (n==m_aiMyInt[0])
        return 1;
    return 0;
}

int CMpi::operator !=(const unsigned int n) const
{
    return !(operator ==(n));
}

// g_paramFieldP.m_oModulus.m_aiMyInt[0] = 0xFFFFFFFF;
// g_paramFieldP.m_oModulus.m_aiMyInt[1] = 0xFFFFFFFF;
// g_paramFieldP.m_oModulus.m_aiMyInt[2] = 0x00000000;
// g_paramFieldP.m_oModulus.m_aiMyInt[3] = 0xFFFFFFFF;
// g_paramFieldP.m_oModulus.m_aiMyInt[4] = 0xFFFFFFFF;
// g_paramFieldP.m_oModulus.m_aiMyInt[5] = 0xFFFFFFFF;
// g_paramFieldP.m_oModulus.m_aiMyInt[6] = 0xFFFFFFFF;
// g_paramFieldP.m_oModulus.m_aiMyInt[7] = 0xFFFFFFFE;

void CMpl::FastReduction(const CMpi &m)
{
    int i, tflag;
    CMpl tempH;

    tflag = l.m_iMySign;
    h.m_iMySign = l.m_iMySign = POSITIVE;

    i = h.m_iLengthInInts;
    while (--i >= 0)
    {
        while (h.m_aiMyInt[i])
        {
            tempH.h = 0;
            tempH.l.m_aiMyInt[7] = tempH.l.m_aiMyInt[0] = h.m_aiMyInt[i];
            tempH.l.m_aiMyInt[6] = tempH.l.m_aiMyInt[5] = tempH.l.m_aiMyInt[4] = tempH.l.m_aiMyInt[2] = tempH.l.m_aiMyInt[1] = 0;
            tempH.l.m_aiMyInt[2] = 0 - h.m_aiMyInt[i];
            tempH.l.m_aiMyInt[3] = h.m_aiMyInt[i] - 1;
            tempH.l.m_iLengthInInts = 8;

            tempH <<= i;

            h.m_aiMyInt[i] = 0;

            // add
            (*this) += tempH;
        }
    }

    h.m_iLengthInInts = 0;
    h.m_iMySign = tflag;

    // here, m must > 0. The field.
    if (l > m)
        l -= m;

    if (l == m)
        l = 0;
    else
        l.m_iMySign = tflag;
}

void CMpl::Reduction(const CMpi &m)
{
    if (m.m_aiMyInt[0] == 0xFFFFFFFF
        && m.m_aiMyInt[1] == 0xFFFFFFFF
        && m.m_aiMyInt[2] == 0x00000000
        && m.m_aiMyInt[3] == 0xFFFFFFFF
        && m.m_aiMyInt[4] == 0xFFFFFFFF
        && m.m_aiMyInt[5] == 0xFFFFFFFF
        && m.m_aiMyInt[6] == 0xFFFFFFFF
        && m.m_aiMyInt[7] == 0xFFFFFFFE
        && m.m_iLengthInInts == MPI_LENGTH)
    {
        FastReduction(m);
        return;
    }

    CMpi odiv;
    CMpi mt(m);
    CMpl temp,tdiv;
    int i,j,mflag,len;
    unsigned int ui,uj,flag;
    DOUBLE_INT t64;

    mflag = l.m_iMySign;

    l.m_iMySign = h.m_iMySign = POSITIVE;

    for (i=mt.m_iLengthInInts-1;i>=0;i--)
    {
        if (mt.m_aiMyInt[i])
            break;
    }
    mt.m_iLengthInInts = i+1;

    if (mt==0)
    {
        return;
    }

    mt.m_iMySign = POSITIVE;

    odiv=mt;
    odiv.m_iMySign = POSITIVE;
    flag=0;
    ui=odiv.m_aiMyInt[odiv.m_iLengthInInts-1];

    while (!(0x80000000 & (ui << flag)))
        flag++;
    odiv.BitShiftLeft(flag);

    len = l.m_iLengthInInts + h.m_iLengthInInts -odiv.m_iLengthInInts+1;
    if (len <= 0)
    {
        l.m_iMySign = h.m_iMySign = mflag;
        return;
    }

    if (h.m_iLengthInInts<MPI_LENGTH)
        h.m_aiMyInt[h.m_iLengthInInts]=0;

    ui = odiv.m_aiMyInt[odiv.m_iLengthInInts-1]+1;

    for (i = h.m_iLengthInInts-1, j = h.m_iLengthInInts + MPI_LENGTH - odiv.m_iLengthInInts; i>=0; i--, j--)
    {
        if ((i+1)>=MPI_LENGTH)
            t64 = 0;
        else
            t64 = h.m_aiMyInt[i+1];
        t64 <<=32 ;
        t64 += h.m_aiMyInt[i];
        if (ui)
            uj = (unsigned int)(t64/ui);
        else
            uj = (unsigned int)(t64>>32);
        temp = odiv;
        (temp.l) *= uj;
        if (temp.l.m_iCarry)
        {
            temp.h.m_iLengthInInts = 1;
            temp.h.m_aiMyInt[0]=temp.l.m_iCarry;
        }
        else
        {
            temp.h.m_iLengthInInts = 0;
        }
        temp<<=j;
        tdiv = odiv;
        tdiv<<=j;
        operator -=(temp);

        while (!(h<<tdiv.h))
        {
            *this -= tdiv;
        }
    }
    if (l.m_iLengthInInts < MPI_LENGTH)
        l.m_aiMyInt[l.m_iLengthInInts]=0;

    ui=odiv.m_aiMyInt[odiv.m_iLengthInInts-1]+1;

    for (i=l.m_iLengthInInts-1, j=l.m_iLengthInInts-odiv.m_iLengthInInts; i>=odiv.m_iLengthInInts-1; i--, j--)
    {
        if (i == MPI_LENGTH-1)
        {
            if (h.m_iLengthInInts == 0)
                t64 = 0;
            else
                t64 = h.m_aiMyInt[0];
        }
        else
            t64=l.m_aiMyInt[i+1];
        t64<<=32;
        t64+=l.m_aiMyInt[i];

        if (ui)
            uj = (unsigned int)(t64/ui);
        else
            uj = (unsigned int)(t64>>32);
        temp = odiv;
        temp.l *= uj;
        if (temp.l.m_iCarry)
        {
            temp.h.m_iLengthInInts = 1;
            temp.h.m_aiMyInt[0]=temp.l.m_iCarry;
        }
        else
        {
            temp.h.m_iLengthInInts = 0;
        }
        temp <<= j;
        tdiv = odiv;
        tdiv <<= j;
        operator -=(temp);

        while ((!(l<<tdiv.l))||(h.m_aiMyInt[0] && h.m_iLengthInInts))
        {
            *this -= tdiv;
        }
    }

    while (!(l<<mt))
    {
        uj=l.m_aiMyInt[l.m_iLengthInInts-1]/(mt.m_aiMyInt[mt.m_iLengthInInts-1]+1);
        if (0==uj)
            uj=1;
        temp.l = mt;
        (temp.l) *= uj;
        l -= temp.l;
    }
    l.m_iMySign = h.m_iMySign = mflag;
    return;
}

CMpl & CMpl::operator +=(const CMpl &oMpl)
{
    CMpi o;
    int i;
//	if (l.m_iMySign == MPI_INFINITE)
//		return *this;
//	if (oMpl.l.m_iMySign == MPI_INFINITE)
//	{
//		h.m_iMySign = l.m_iMySign = MPI_INFINITE;
//		return *this;
//	}
    l += oMpl.l;
    h += oMpl.h;

    if (h == 0)
        h.m_iMySign = l.m_iMySign;

    if (l.m_iMySign == h.m_iMySign)
    {
        if (l.m_iCarry)
        {
            o = l.m_iCarry;
            o.m_iMySign = l.m_iMySign;
            h += o;
            l.m_iCarry = 0;
        }
    }
    else
    {
        for (i=0;i<MPI_LENGTH;i++)
            o.m_aiMyInt[i]=HEX32BITS;
        o.m_iLengthInInts = MPI_LENGTH;
        o.m_iMySign = h.m_iMySign;
        l += o;

        o.m_iLengthInInts = 1;
        o.m_aiMyInt[1] = 0;
        o.m_aiMyInt[0] = 1;
        o.m_iMySign = h.m_iMySign;
        l += o;

        h -= o;
    }
    if (l.m_iLengthInInts < MPI_LENGTH && h != 0)
        l.m_iLengthInInts = MPI_LENGTH;
    return *this;
}

CMpl & CMpl::operator -=(const CMpl &oMpl)
{
    CMpl temp;
//	if (l.m_iMySign == MPI_INFINITE)
//		return *this;
//	if (oMpl.l.m_iMySign == MPI_INFINITE)
//	{
//		h.m_iMySign = l.m_iMySign = MPI_INFINITE;
//		return *this;
//	}
    temp = oMpl;
    if (oMpl.l.m_iMySign == POSITIVE)
    {
        temp.l.m_iMySign = temp.h.m_iMySign = NEGTIVE;
    }
    else
    {
        temp.l.m_iMySign = temp.h.m_iMySign = POSITIVE;
    }
    return operator += (temp);
}

CMpl::CMpl(const CMpi &m)
{
    l = m;
    h.m_iMySign = m.m_iMySign;
    if (h.m_aiMyInt[0] = m.m_iCarry)
    {
        h.m_iLengthInInts = 1;
    }
    else
    {
        h.m_iLengthInInts = 0;
    }
}

CMpi & CMpi::operator >>=(const int n)
{
    CMpl temp(*this);
    temp>>=n;
    *this = temp;
    m_iCarry = 0;
    return *this;
}

CMpl & CMpl::operator >>=(const int n)
{
    int i,j;
    if (n<0)
        return (*this)<<=(-n);

    for (i=0;i<l.m_iLengthInInts;i++)
    {
        if ((i+n) < l.m_iLengthInInts)
        {
            l.m_aiMyInt[i] = l.m_aiMyInt[i+n];
        }
        else
        {
            if (l.m_iLengthInInts == MPI_LENGTH)
            {
                j = i+n-MPI_LENGTH;
                if (j<h.m_iLengthInInts)
                {
                    l.m_aiMyInt[i] = h.m_aiMyInt[j];
                    continue;
                }
                else
                {
                    l.m_aiMyInt[i] = 0;
                    l.m_iLengthInInts = i;
                    h.m_iLengthInInts = 0;
                    return *this;
                }
            }
            else
            {
                l.m_aiMyInt[i]=0;
                l.m_iLengthInInts = i;
                h.m_iLengthInInts = 0;
                return *this;
            }
        }
    }

    for (i=0;i<h.m_iLengthInInts;i++)
    {
        if ((i+n)<h.m_iLengthInInts)
        {
            h.m_aiMyInt[i] = h.m_aiMyInt[n+i];
        }
        else
        {
            h.m_aiMyInt[i]=0;
            h.m_iLengthInInts = i;
            return *this;
        }
    }
    return *this;
}

CMpl::CMpl()
{
    l.m_iMySign = h.m_iMySign = POSITIVE;
    l.m_iLengthInInts = h.m_iLengthInInts = 0;
}


CMpl & CMpl::operator <<=(const int n)
{
    int i,j,k,p;
    if (n<0)
        return (*this)>>=(-n);
    k = h.m_iLengthInInts + l.m_iLengthInInts;
    if (k==0)
        return *this;
    if (k==1 && l.m_aiMyInt[0]==0)
        return *this;

    k +=n;
    if (k >= MPI_LENGTH*2)
        k = MPI_LENGTH*2;
    j = k-MPI_LENGTH;

    for (i=j-1, p=i-n; i>=0; i--, p--)
    {
        if (p>=0)
        {
            h.m_aiMyInt[i] = h.m_aiMyInt[p];
        }
        else
        {
            if ((p+MPI_LENGTH)>=0)
            {
                h.m_aiMyInt[i] = l.m_aiMyInt[MPI_LENGTH+p];
                continue;
            }
            else
            {
                h.m_aiMyInt[i]=0;
                continue;
            }
        }
    }

    if (k>=MPI_LENGTH)
        j = MPI_LENGTH;
    else
        j = k;
    for (i=j-1, p=i-n;i>=0;i--, p--)
    {
        if (p>=0)
        {
            l.m_aiMyInt[i]=l.m_aiMyInt[p];
        }
        else
        {
            l.m_aiMyInt[i]=0;
        }
    }
    l.m_iLengthInInts = j;
    if (j>=MPI_LENGTH)
        h.m_iLengthInInts = k-MPI_LENGTH;
    else
        h.m_iLengthInInts = 0;
    return *this;
}

CMpi & CMpi::operator <<=(const int n)
{
    CMpl temp(*this);
    temp<<=n;
    *this = temp;
    m_iCarry = 0;
    return *this;
}

int CMpi::operator !=(const CMpi &m) const
{
    return !(operator ==(m));
}

CMpi & CMpl::operator %=(const CMpi &m)
{
    Reduction(m);
    return (*this).l;
}


CMpi & CMpi::BitShiftLeft(const int iShiftBits)
{
    int i,j,k;
    j = iShiftBits/BITS_OF_INT;
    if (j)
    {
        (*this)<<=(j);
    }

    j = iShiftBits%BITS_OF_INT;

    if (j==0)
        return (*this);

    k = m_iLengthInInts;
    if (k<MPI_LENGTH)
    {
        m_aiMyInt[k] = m_aiMyInt[k-1]>>(BITS_OF_INT-j);
        if (m_aiMyInt[k])
            m_iLengthInInts++;
    }
    else
        m_iCarry = m_aiMyInt[MPI_LENGTH-1]>>(BITS_OF_INT-j);

    for (i=k-1;i>0;i--)
    {
        m_aiMyInt[i]<<=j;
        m_aiMyInt[i] += m_aiMyInt[i-1]>>(BITS_OF_INT-j);
    }

    m_aiMyInt[0]<<=j;

    return (*this);
}

CMpi & CMpi::BitShiftRight(const int iShiftBits)
{
    int i,j;
    j = iShiftBits/BITS_OF_INT;
    if (j)
    {
        (*this)>>=(j);
    }

    j = iShiftBits%BITS_OF_INT;

    if (j==0)
        return (*this);

    for (i=0; i<m_iLengthInInts-1;i++)
    {
        m_aiMyInt[i] >>= j;
        m_aiMyInt[i] += (m_aiMyInt[i+1]<<(BITS_OF_INT-j));
    }

    m_aiMyInt[m_iLengthInInts-1] >>= j;

    if (m_aiMyInt[m_iLengthInInts-1]==0)
        m_iLengthInInts--;

    return (*this);
}


CMpl & CMpl::BitShiftLeft(const int iShiftBits)
{
    int i,j,k;
    j = iShiftBits/BITS_OF_INT;
    if (j)
    {
        (*this)<<=(j);
    }
    j = iShiftBits%BITS_OF_INT;

    if (j==0)
        return (*this);

    k = h.m_iLengthInInts ;
    if (k>0)
    {
        if (k<MPI_LENGTH)
        {
            h.m_aiMyInt[k] = h.m_aiMyInt[k-1]>>(BITS_OF_INT-j);
            if (h.m_aiMyInt[k])
                h.m_iLengthInInts ++;
        }
        for (i = k-1; i>0;i--)
        {
            h.m_aiMyInt[i] <<= j;
            h.m_aiMyInt[i] += h.m_aiMyInt[i-1]>>(BITS_OF_INT-j);
        }
        h.m_aiMyInt[0] <<= j;
        h.m_aiMyInt[0] += l.m_aiMyInt[MPI_LENGTH-1]>>(BITS_OF_INT-j);
    }
    else
    {
        if (l.m_iLengthInInts==MPI_LENGTH)
        {
            h.m_aiMyInt[0] = l.m_aiMyInt[MPI_LENGTH-1]>>(BITS_OF_INT-j);
            if (h.m_aiMyInt[0])
                h.m_iLengthInInts = 1;
        }
    }

    k = l.m_iLengthInInts;
    if (k<MPI_LENGTH)
    {
        l.m_aiMyInt[k] = l.m_aiMyInt[k-1]>>(BITS_OF_INT-j);
        if (l.m_aiMyInt[k])
            l.m_iLengthInInts ++;
    }
    for (i=k-1;i>0;i--)
    {
        l.m_aiMyInt[i]<<=j;
        l.m_aiMyInt[i] += l.m_aiMyInt[i-1]>>(BITS_OF_INT-j);
    }
    l.m_aiMyInt[0]<<=j;

    return (*this);
}


CMpl CMpi::FastSquare() const
{
    CMpl temp;
    unsigned int c[MPI_LENGTH*2] = {
            0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
    };
    int k;
    int len = m_iLengthInInts*2;

//	for (k=0; k<len; k++)
//		c[k]=0;

    int i, j;
    DOUBLE_INT uv, sum;
    unsigned int R0 = 0, R1 = 0, R2 = 0;
    int imax;
    for (k = 0; k <= len-2; k++)
    {


//		imax = __min(k, m_iLengthInInts-1);
//		imax = __min(k/2, imax);
        imax = __min(k/2, m_iLengthInInts-1);
        for (i = imax, j = k-i; i >= 0; i--, j++)
        {
            if (j >= m_iLengthInInts)
                break;

            uv = m_aiMyInt[i];
            uv *= m_aiMyInt[j];
            if (i < j)
            {
                if (0x8000000000000000ull & uv)
                    R2++;
                uv <<= 1;
            }
            sum = R0;
            sum += (unsigned int)uv;
            R0 = (unsigned int)sum;
            sum >>= BITS_OF_INT;

            sum += R1;
            sum += (uv >> BITS_OF_INT);
            R1 = (unsigned int)sum;
            sum >>= BITS_OF_INT;

            R2 += (unsigned int)sum;
        }
        c[k] = R0;
        R0 = R1;
        R1 = R2;
        R2 = 0;
    }

    c[len-1] = R0;

    if (len>MPI_LENGTH)
    {
        temp.l.m_iLengthInInts = MPI_LENGTH;
        temp.h.m_iLengthInInts = len - MPI_LENGTH;

        for (i=0;i<temp.h.m_iLengthInInts;i++)
            temp.h.m_aiMyInt[i]=c[i+MPI_LENGTH];
    }
    else
    {
        temp.l.m_iLengthInInts = len;
        temp.h.m_iLengthInInts = 0;
    }

    for (i=0;i<temp.l.m_iLengthInInts;i++)
        temp.l.m_aiMyInt[i]=c[i];

    return temp;
}


CMpl & CMpl::BitShiftRight(const int iShiftBits)
{
    int i,j,k;
    j = iShiftBits/(BITS_OF_INT);
    if (j)
    {
        (*this)>>=(j);
    }
    j = iShiftBits%(BITS_OF_INT);

    if (j==0)
        return (*this);

    k = l.m_iLengthInInts;

    for (i=0; i<l.m_iLengthInInts-1;i++)
    {
        l.m_aiMyInt[i]>>=j;
        l.m_aiMyInt[i] += l.m_aiMyInt[i+1]<<(BITS_OF_INT-j);
    }
    if (k<MPI_LENGTH)
    {
        l.m_aiMyInt[l.m_iLengthInInts-1]>>=j;
        if (l.m_aiMyInt[l.m_iLengthInInts-1]==0)
            l.m_iLengthInInts --;
    }
    else
    {
        l.m_aiMyInt[l.m_iLengthInInts-1]>>=j;
        if (h.m_iLengthInInts>0)
            l.m_aiMyInt[l.m_iLengthInInts-1]+= h.m_aiMyInt[0]<<(BITS_OF_INT-j);
    }

    k = h.m_iLengthInInts ;
    if (k>0)
    {
        for (i =0;i< k-1; i++)
        {
            h.m_aiMyInt[i] >>= j;
            h.m_aiMyInt[i] += h.m_aiMyInt[i+1]<<(BITS_OF_INT-j);
        }

        h.m_aiMyInt[k-1] >>= j;
        if (h.m_aiMyInt[k-1]==0)
            h.m_iLengthInInts --;
    }
    return (*this);
}



CModulus::CModulus()
{
}




//#include "../GPU/Sm.h"
//void qiuni(unsigned long long* u, unsigned long long*v ,unsigned long long *r);
//void mpiqiuni(CMpi ca, CMpi cb,CMpi& cr)
//{
//	unsigned char cachar[100];
//	unsigned char cbchar[100];
//	unsigned char crchar[100];
//	ca.Export(cachar,32);
//	cb.Export(cbchar,32);
//	sm.swap(cachar,32);
//	sm.swap(cbchar,32);
//	qiuni((unsigned long long*)cachar, (unsigned long long*)cbchar , (unsigned long long*)crchar );
//	sm.swap(crchar,32);
//	cr.Import(crchar,32);
//
//}





//void CModulus::SimultaneousBinaryInverse(CMpi *pOut, const CMpi *pIn, int cnt)
//{
//	cnt = __min(cnt, SIMUL_BINARY_CNT);
//	CMpi c[SIMUL_BINARY_CNT];
//	CMpl temp;
//	int i;
//
//	c[0] = pIn[0];
//	for (i = 1; i < cnt; i++)
//	{
//		temp = c[i-1]*pIn[i];
//		c[i] = (temp %= m_oModulus);
//	}
//
//	//pOut[0] = BinaryInverse(c[cnt-1]);
//	mpiqiuni(c[cnt-1], m_oModulus , pOut[0]);
//	for (i = cnt-1; i > 0; i--)
//	{
//		temp = pOut[0]*c[i-1];
//		pOut[i] = (temp %= m_oModulus);
//		temp = pOut[0]*pIn[i];
//		pOut[0] = (temp %= m_oModulus);
//	}
//}
CMpi CModulus::BinaryInverse(const CMpi &oMpi)
{
    CMpi u = oMpi;
    CMpi v = m_oModulus;
    CMpl x1(1), x2(0);

    while ((u != 1) && (v != 1))
    {
        while (!(u.m_aiMyInt[0] & 0x01))
        {
            u.BitShiftRight(1);
            if (!(x1.l.m_aiMyInt[0] & 0x01))
                x1.BitShiftRight(1);
            else
            {
                x1 += m_oModulus;
                x1.BitShiftRight(1);
            }
        }

        while (!(v.m_aiMyInt[0] & 0x01))
        {
            v.BitShiftRight(1);
            if (!(x2.l.m_aiMyInt[0] & 0x01))
                x2.BitShiftRight(1);
            else
            {
                x2 += m_oModulus;
                x2.BitShiftRight(1);
            }
        }

        if (u < v)
        {
            v -= u;
            x2 -= x1;
        }
        else
        {
            u -= v;
            x1 -= x2;
        }
    }

    if (u == 1)
    {
        x1 %= m_oModulus;
        if (x1.l.IsNegative())
            x1 += m_oModulus;
        return x1.l;
    }
    else
    {
        x2 %= m_oModulus;
        if (x2.l.IsNegative())
            x2 += m_oModulus;
        return x2.l;
    }
}


void CMpi::Regularize()
{
    int i;

    for (i=m_iLengthInInts-1;i>=0;i--)
    {
        if (m_aiMyInt[i])
            break;
    }
    m_iLengthInInts = i+1;

    return;
}



CModulus::CModulus(const CMpi &oMpi)
{
//	if (oMpi.m_iMySign==MPI_INFINITE)
//	{
//		m_oModulus = (unsigned int) 0;
//	}
    m_oModulus = oMpi;
    m_oModulus.Regularize();

}

int CMpl::operator ==(const CMpl &oMpl) const
{
    if ((l==oMpl.l) && (h==oMpl.h))
        return 1;
    return 0;
}

int CMpi::operator > (const CMpi &m) const
{
    if (m_iMySign!=NEGTIVE)
    {
        if (m.m_iMySign==NEGTIVE)
            return 1;
        if (m_iMySign==POSITIVE)
        {
            if (m.m_iMySign == POSITIVE)
            {
                if ( *this >> m)
                    return 1;
                else
                    return 0;
            }
            else
            {
                return 0;
            }
        }
        else
            return 0;
    }
    if (m_iMySign==NEGTIVE)
    {
        if (m.m_iMySign!=NEGTIVE)
            return 0;
        else
        {
            if ( *this << m)
                return 1;
            else
                return 0;
        }
    }
    return 0;
}

int CMpi::operator < (const CMpi &m) const
{
    return (m>(*this));
}


int CMpi::GetLengthInBytes()
{
    int i;
    unsigned int j,k;
    Regularize();
    if (m_iLengthInInts==0)
        return 0;
    j = m_aiMyInt[m_iLengthInInts-1];
    k = 0xff;
    for (i=sizeof(unsigned int)-1;i>=0;i--)
    {
        if (j&(k<<(i*8)))
            break;
    }
    return i+1+(m_iLengthInInts-1)*sizeof(unsigned int);
}

int CModulus::GetLengthInBytes()
{
    return m_oModulus.GetLengthInBytes();
}



int CMpi::Import(const BYTE *abContent, int iLength)
{
    int i,j;
    m_iCarry = 0;
    m_iLengthInInts = 0;
    m_iMySign = POSITIVE;

    if (iLength>MPI_LENGTH*sizeof(unsigned int))
    {
        return 0;
    }

    j = 0;
    m_aiMyInt[m_iLengthInInts] = 0;
    for (i = iLength-1; i>=0 ; i--)
    {
        m_aiMyInt[m_iLengthInInts] += abContent[i]<<(8*j);
        j++;
        if (j>=sizeof(unsigned int))
        {
            j=0;
            m_iLengthInInts++;
            if (m_iLengthInInts!=MPI_LENGTH)
                m_aiMyInt[m_iLengthInInts] = 0;
        }
    }
    if (j)
        m_iLengthInInts++;
    return m_iLengthInInts;
}

int CMpi::Export(BYTE *abOutBytes, int iMinLength) const
{
    int j,k;
    int iLengthOfExport;
    unsigned int u;
    iLengthOfExport = 0;
    j = m_iLengthInInts-1;
    if (j<0)
        return 0;

    u =  m_aiMyInt[j];
    while (u==0)
    {
        j--;
        if (j < 0)
            return 0;
        u =  m_aiMyInt[j];
    }

    k = sizeof(unsigned int)-1;
    while (0==(u>>(k*8)))
        k--;

    int iOut = j*sizeof(unsigned int) + k + 1;
    while (iOut < iMinLength)
    {
        abOutBytes[iLengthOfExport++] = 0x00;
        iMinLength--;
    }

    while (k>=0)
    {
        abOutBytes[iLengthOfExport] = (BYTE )(u>>(k*8));
        iLengthOfExport++;
        k--;
    }

    j--;
    u =  m_aiMyInt[j];
    while (j>=0)
    {
        u = m_aiMyInt[j];
        for (k=sizeof(unsigned int)-1;k>=0;k--)
        {
            abOutBytes[iLengthOfExport] = (BYTE )(u>>(k*8));
            iLengthOfExport++;
        }
        j--;
    }

    return iLengthOfExport;
}



int CMpi::GetLengthInBits() const
{
    int i;
    unsigned int k;
    int iLength;
    for (i=m_iLengthInInts-1;i>=0;i--)
    {
        if (m_aiMyInt[i])
            break;
    }
    iLength = (i+1)*8*sizeof(unsigned int);
    k = m_aiMyInt[i];
    for (i=0;i<8*sizeof(unsigned int);i++)
    {
        if ( UNSIGNEDLEFTBIT & (k<<i))
            break;
    }
    return iLength - i;
}

int CMpi::IsNegative() const
{
    return m_iMySign == NEGTIVE;
}


void CMpi::ChangeSign()
{
    m_iMySign *= -1;
}



