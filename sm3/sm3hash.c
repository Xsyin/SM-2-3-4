//
// Created by lxb on 3/8/16.
//

#include "sm3hash.h"

void Sm3HashCF(unsigned int *pH, const unsigned char *pMsg);	// 迭代函数
void Sm3MS(unsigned int *pW, const unsigned int *pMsg);

//ROTL redifinition
#define ROTL(x,y)	(((x)<<(y&(32-1))) | ((x)>>(32-(y&(32-1)))))

unsigned int Sm3KDF(unsigned char *pKeyOut, unsigned int iLenOfOut /* in bytes */, const unsigned char *pSecret, unsigned int iLenOfSecret /* in bytes */, unsigned int ct)
{
    unsigned int tmp;
    unsigned int i, iRound = iLenOfOut/SM3_HASH_256;
    SM3_HASH_STATE state;
    for (i = 0; i < iRound; i++)
    {
        Sm3HashInit(&state, pSecret, iLenOfSecret);
        tmp = (ct << 24) | ((ct&0x0000ff00) << 8) | ((ct&0x00ff0000) >> 8) | (ct >> 24);
        Sm3HashPending(&state, (unsigned char *)&tmp, sizeof(tmp));
        if (!Sm3HashFinal(pKeyOut + i*SM3_HASH_256, &state))
            return 0;	// error
        ct++;
    }

    unsigned char acHashResult[SM3_HASH_256];
    if (0 != iLenOfOut % SM3_HASH_256)
    {
        Sm3HashInit(&state, pSecret, iLenOfSecret);
        tmp = (ct << 24) | ((ct&0x0000ff00) << 8) | ((ct&0x00ff0000) >> 8) | (ct >> 24);
        Sm3HashPending(&state, (unsigned char *)&tmp, sizeof(tmp));
        if (!Sm3HashFinal(acHashResult, &state))
            return 0;	// error

        for (i = 0; i < iLenOfOut % SM3_HASH_256; i++)
            pKeyOut[iLenOfOut - (iLenOfOut % SM3_HASH_256) + i] = acHashResult[i];
        ct++;
    }

    return iLenOfOut;
}



bool Sm3Hash(unsigned char *pOut, const unsigned char *pIn, unsigned int iInLen)
{
    unsigned int H[8] = // 迭代状态寄存器
            {
                    0x7380166F,
                    0x4914B2B9,
                    0x172442D7,
                    0xDA8A0600,
                    0xA96F30BC,
                    0x163138AA,
                    0xE38DEE4D,
                    0xB0FB0E4E
            };

    unsigned int i;
    // 每次处理64byte=512bits
    for (i = 0; i < iInLen/64; i++)
    {
        Sm3HashCF(H, pIn+i*64);
    }

    unsigned char BB2[128];	//最后的块,1块或2块
    for (i = 0; i < sizeof(BB2); i++)
        BB2[i] = 0x00;

    for (i = 0; i < (iInLen & 63); i++)
    {
        BB2[i] = pIn[(iInLen&0xffffffc0)+i];
    }

    // in bytes ==> in bits
    unsigned int low = 0, high = 0;
    high = iInLen >> 29;
    high = (high >> 24)
           | ((high&0x00ff0000) >> 8)
           | ((high&0x0000ff00) << 8)
           | (high << 24);
    low = iInLen << 3;
    low = (low >> 24)
          | ((low&0x00ff0000) >> 8)
          | ((low&0x0000ff00) << 8)
          | (low << 24);

    if ((iInLen & 63) < 56)
    {
        // 1 block
        BB2[i] = 0x80;

        // BB[56 .. 63]
        *(unsigned int *)(BB2+56) = high;
        *(unsigned int *)(BB2+60) = low;

        Sm3HashCF(H, BB2);
    }
    else
    {
        // 2 block
        BB2[i] = 0x80;
        Sm3HashCF(H, BB2);

        // BB[120 .. 127]
        *(unsigned int *)(BB2+120) = high;
        *(unsigned int *)(BB2+124) = low;

        Sm3HashCF(H, BB2+64);
    }

    for (i = 0; i < 8; i++)
    {
        pOut[i*4] = (unsigned char)(H[i] >> 24);
        pOut[i*4+1] = (unsigned char)(H[i] >> 16);
        pOut[i*4+2] = (unsigned char)(H[i] >> 8);
        pOut[i*4+3] = (unsigned char)H[i];
    }

    return true;
}

void Sm3HashCF(unsigned int *pH, const unsigned char *pMsg)
{
    unsigned int A = pH[0],
            B = pH[1],
            C = pH[2],
            D = pH[3],
            E = pH[4],
            F = pH[5],
            G = pH[6],
            H = pH[7];
    unsigned int w[68+64];
    // w[0..67] for W
    // w[68+0 .. 68+63] for W'

    int j;
    // unsigned char --> unsigned int
    unsigned int BB[16];
    for (j = 0; j < 16; j++)
        BB[j] = (pMsg[4*j] << 24)
                | (pMsg[4*j+1] << 16)
                | (pMsg[4*j+2] << 8)
                | pMsg[4*j+3];

    Sm3MS(w, BB);	//消息扩展

    unsigned int SS1, SS2, TT1, TT2;
    unsigned int T = 0x79CC4519;
    for (j = 0; j < 16; j++)
    {
        SS1 = ROTL(A, 12) + E + ROTL(T, j);
        SS1 = ROTL(SS1, 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = ((A^B^C) + D + SS2) + w[j+68];
        TT2 = ((E^F^G) + H + SS1) + w[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = TT2 ^ ROTL(TT2, 9) ^ ROTL(TT2, 17);
    }

    T = 0x7A879D8A;
    for (; j < 64; j++)
    {
        SS1 = ROTL(A, 12) + E + ROTL(T, j);
        SS1 = ROTL(SS1, 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = (((A&B) | (A&C) | (B&C)) + D + SS2) + w[j+68];
        TT2 = (((E&F) | ((~E)&G)) + H + SS1) + w[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = TT2 ^ ROTL(TT2, 9) ^ ROTL(TT2, 17);
    }

    pH[0] ^= A;
    pH[1] ^= B;
    pH[2] ^= C;
    pH[3] ^= D;
    pH[4] ^= E;
    pH[5] ^= F;
    pH[6] ^= G;
    pH[7] ^= H;
}

void Sm3MS(unsigned int *pW, const unsigned int *pMsg)
{
    // pW[i] for Wi
    // pW[68+i] for Wi'
    int j;
    for (j = 0; j < 16; j++)
        pW[j] = pMsg[j];

    for (; j < 68; j++)
    {
        pW[j] = pW[j-16] ^ pW[j-9] ^ ROTL(pW[j-3], 15);
        pW[j] ^= (ROTL(pW[j], 15) ^ ROTL(pW[j], 23));
        pW[j] ^= ((ROTL(pW[j-13], 7) ^ pW[j-6]));
    }

    for (j = 0; j < 64; j++)
        pW[68+j] = pW[j] ^ pW[j+4];
}


void Sm3HashInit(SM3_HASH_STATE *pState, const unsigned char *pIn, unsigned int iInLen)	// 第一次调用
{
    //状态寄存器
    pState->H[0] = 0x7380166F;
    pState->H[1] = 0x4914B2B9;
    pState->H[2] = 0x172442D7;
    pState->H[3] = 0xDA8A0600;
    pState->H[4] = 0xA96F30BC;
    pState->H[5] = 0x163138AA;
    pState->H[6] = 0xE38DEE4D;
    pState->H[7] = 0xB0FB0E4E;

    pState->u64Length = iInLen;

    unsigned int i;
    //每次处理64 bytes=512 bits
    for (i = 0; i < iInLen/64; i++)
    {
        Sm3HashCF(pState->H, pIn+i*64);
    }

    // 最后的一块
    for (i = 0; i < (iInLen & 63); i++)
        pState->BB[i] = pIn[(iInLen&0xffffffc0)+i];
}

void Sm3HashPending(SM3_HASH_STATE *pState, const unsigned char *pIn, unsigned int iInLen)		// 任意多次调用
{
    unsigned int iCurPos = (unsigned int)(pState->u64Length % 64);
    unsigned int i;
    unsigned int iMin = (64-iCurPos < iInLen) ? (64-iCurPos) : (iInLen);

    for (i = 0; i < iMin; i++)
        pState->BB[i+iCurPos] = pIn[i];

    pState->u64Length += iInLen;

    if (iInLen >= 64-iCurPos)
    {
        Sm3HashCF(pState->H, pState->BB);

        iInLen -= (64-iCurPos);
        pIn += (64-iCurPos);
        for (i = 0; i < iInLen/64; i++)
        {
            Sm3HashCF(pState->H, pIn+i*64);
        }

        for (i = 0; i < (iInLen & 63); i++)
            pState->BB[i] = pIn[(iInLen&0xffffffc0)+i];
    }
}

bool Sm3HashFinal(unsigned char *pOut, SM3_HASH_STATE *pState)	//最后一次调用
{
    
    unsigned int i;
    unsigned char BB2[128];	// 最后的块,1或2
    for (i = 0; i < sizeof(BB2); i++)
        BB2[i] = 0x00;

    for (i = 0; i < (pState->u64Length & 63); i++)
    {
        BB2[i] = pState->BB[i];
    }

    // in bytes ==> in bits
    unsigned int low = 0, high = 0;
    high = (unsigned int)(pState->u64Length >> 29);
    high = (high >> 24)
           | ((high&0x00ff0000) >> 8)
           | ((high&0x0000ff00) << 8)
           | (high << 24);
    low = (unsigned int)(pState->u64Length << 3);
    low = (low >> 24)
          | ((low&0x00ff0000) >> 8)
          | ((low&0x0000ff00) << 8)
          | (low << 24);

    if ((pState->u64Length & 63) < 56)
    {
        // 1 block
        BB2[i] = 0x80;

        // BB[56 .. 63]
        *(unsigned int *)(BB2+56) = high;
        *(unsigned int *)(BB2+60) = low;

        Sm3HashCF(pState->H, BB2);
    }
    else
    {
        // 2 block
        BB2[i] = 0x80;
        Sm3HashCF(pState->H, BB2);

        // BB[120 .. 127]
        *(unsigned int *)(BB2+120) = high;
        *(unsigned int *)(BB2+124) = low;

        Sm3HashCF(pState->H, BB2+64);
    }

    for (i = 0; i < 8; i++)
    {
        pOut[i*4] = (unsigned char)(pState->H[i] >> 24);
        pOut[i*4+1] = (unsigned char)(pState->H[i] >> 16);
        pOut[i*4+2] = (unsigned char)(pState->H[i] >> 8);
        pOut[i*4+3] = (unsigned char)(pState->H[i]);
    }

    return true;
}

// B=64
// ipad = the byte 0x36 repeated B times
// opad = the byte 0x5C repeated B times
// H(K XOR opad, H(K XOR ipad, text))
bool Sm3Hmac(unsigned char *pOut, const unsigned char *pMsg, unsigned int iLenOfMsg, const unsigned char *pSecret, int iLenOfSecret)
{
    unsigned char keyPadded[HMAC_B_LENGTH];
    int i = 0;
    do {
        keyPadded[i++] = 0;
    } while (i < HMAC_B_LENGTH);

    if (iLenOfSecret > HMAC_B_LENGTH)
        Sm3Hash(keyPadded, pSecret, iLenOfSecret);
    else
    {
        i = 0;
        while (i < iLenOfSecret)
        {
            keyPadded[i++] = pSecret[i];
        }
    }

    for (i = 0; i < HMAC_B_LENGTH; i++)
        keyPadded[i] ^= HMAC_IPAD;

    SM3_HASH_STATE state;
    Sm3HashInit(&state, keyPadded, HMAC_B_LENGTH);
    Sm3HashPending(&state, pMsg, iLenOfMsg);
    Sm3HashFinal(pOut, &state);

    for (i = 0; i < HMAC_B_LENGTH; i++)
        keyPadded[i] ^= (HMAC_IPAD^HMAC_OPAD);

    Sm3HashInit(&state, keyPadded, HMAC_B_LENGTH);
    Sm3HashPending(&state, pOut, SM3_HASH_256);
    Sm3HashFinal(pOut, &state);

    return true;
}

void Sm3HmacInit(SM3_HMAC_STATE *pState, const unsigned char *pSecret, int iLenOfSecret)
{
    int i = 0;
    do {
        pState->padding[i++] = 0;
    } while (i < HMAC_B_LENGTH);

    if (iLenOfSecret > HMAC_B_LENGTH)
        Sm3Hash(pState->padding, pSecret, iLenOfSecret);
    else
    {
        i = 0;
        while (i < iLenOfSecret)
        {
            pState->padding[i++] = pSecret[i];
        }
    }

    for (i = 0; i < HMAC_B_LENGTH; i++)
        pState->padding[i] ^= HMAC_IPAD;

    Sm3HashInit(&pState->hashState, pState->padding, HMAC_B_LENGTH);
}

void Sm3HmacPending(SM3_HMAC_STATE *pState, const unsigned char *pIn, unsigned int iInLen)
{
    Sm3HashPending(&pState->hashState, pIn, iInLen);
}

bool Sm3HmacFinal(unsigned char *pOut, SM3_HMAC_STATE *pState)
{
    Sm3HashFinal(pOut, &pState->hashState);

    int i;
    for (i = 0; i < HMAC_B_LENGTH; i++)
        pState->padding[i] ^= (HMAC_IPAD^HMAC_OPAD);

    Sm3HashInit(&pState->hashState, pState->padding, HMAC_B_LENGTH);
    Sm3HashPending(&pState->hashState, pOut, SM3_HASH_256);
    return Sm3HashFinal(pOut, &pState->hashState);
}


//杂凑第二版本
#include <string.h>
#include <stdio.h>
/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned int) (b)[(i)    ] << 24 )        \
        | ( (unsigned int) (b)[(i) + 1] << 16 )        \
        | ( (unsigned int) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned int) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif
/*
 * SM3 context setup
 */
void sm3_starts( sm3_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;

}
static void sm3_process( sm3_context *ctx, unsigned char *data )
{
    unsigned int SS1, SS2, TT1, TT2, W[68],W1[64];
    unsigned int A, B, C, D, E, F, G, H;
    unsigned int T[64];
    unsigned int Temp1,Temp2,Temp3,Temp4,Temp5;
    int j;
#ifdef _DEBUG
    int i;
#endif

// 	for(j=0; j < 68; j++)
// 		W[j] = 0;
// 	for(j=0; j < 64; j++)
// 		W1[j] = 0;

    for(j = 0; j < 16; j++)
        T[j] = 0x79CC4519;
    for(j =16; j < 64; j++)
        T[j] = 0x7A879D8A;

    GET_ULONG_BE( W[ 0], data,  0 );
    GET_ULONG_BE( W[ 1], data,  4 );
    GET_ULONG_BE( W[ 2], data,  8 );
    GET_ULONG_BE( W[ 3], data, 12 );
    GET_ULONG_BE( W[ 4], data, 16 );
    GET_ULONG_BE( W[ 5], data, 20 );
    GET_ULONG_BE( W[ 6], data, 24 );
    GET_ULONG_BE( W[ 7], data, 28 );
    GET_ULONG_BE( W[ 8], data, 32 );
    GET_ULONG_BE( W[ 9], data, 36 );
    GET_ULONG_BE( W[10], data, 40 );
    GET_ULONG_BE( W[11], data, 44 );
    GET_ULONG_BE( W[12], data, 48 );
    GET_ULONG_BE( W[13], data, 52 );
    GET_ULONG_BE( W[14], data, 56 );
    GET_ULONG_BE( W[15], data, 60 );

#ifdef _DEBUG
    printf("Message with padding:\n");
    for(i=0; i< 8; i++)
        printf("%08x ",W[i]);
    printf("\n");
    for(i=8; i< 16; i++)
        printf("%08x ",W[i]);
    printf("\n");
#endif



    for(j = 16; j < 68; j++ )
    {
        //W[j] = P1( W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j - 13],7 ) ^ W[j-6];
        //Why thd release's result is different with the debug's ?
        //Below is okay. Interesting, Perhaps VC6 has a bug of Optimizaiton.

        Temp1 = W[j-16] ^ W[j-9];
        Temp2 = ROTL(W[j-3],15);
        Temp3 = Temp1 ^ Temp2;
        Temp4 = P1(Temp3);
        Temp5 =  ROTL(W[j - 13],7 ) ^ W[j-6];
        W[j] = Temp4 ^ Temp5;
    }

#ifdef _DEBUG
    printf("Expanding message W0-67:\n");
    for(i=0; i<68; i++)
    {
        printf("%08x ",W[i]);
        if(((i+1) % 8) == 0) printf("\n");
    }
    printf("\n");
#endif

    for(j =  0; j < 64; j++)
    {
        W1[j] = W[j] ^ W[j+4];
    }

#ifdef _DEBUG
    printf("Expanding message W'0-63:\n");
    for(i=0; i<64; i++)
    {
        printf("%08x ",W1[i]);
        if(((i+1) % 8) == 0) printf("\n");
    }
    printf("\n");
#endif

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];
#ifdef _DEBUG
    printf("j     A       B        C         D         E        F        G       H\n");
    printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",A,B,C,D,E,F,G,H);
#endif

    for(j =0; j < 16; j++)
    {
        SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7);
        SS2 = SS1 ^ ROTL(A,12);
        TT1 = FF0(A,B,C) + D + SS2 + W1[j];
        TT2 = GG0(E,F,G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F,19);
        F = E;
        E = P0(TT2);
#ifdef _DEBUG
        printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif
    }

    for(j =16; j < 64; j++)
    {
        SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7);
        SS2 = SS1 ^ ROTL(A,12);
        TT1 = FF1(A,B,C) + D + SS2 + W1[j];
        TT2 = GG1(E,F,G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F,19);
        F = E;
        E = P0(TT2);
#ifdef _DEBUG
        printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif
    }

    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
#ifdef _DEBUG
    printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",ctx->state[0],ctx->state[1],ctx->state[2],
                               ctx->state[3],ctx->state[4],ctx->state[5],ctx->state[6],ctx->state[7]);
#endif
}
/*
 * SM3 process buffer
 */
void sm3_update( sm3_context *ctx, unsigned char *input, int ilen )
{
    int fill;
    unsigned int left;

    if( ilen <= 0 )
        return;

    //计算上次剩余数据的长度
    left = ctx->total[0] & 0x3F;
    fill =(int)(64 - left);

    ctx->total[0] += ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (unsigned int) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, fill );
        sm3_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        sm3_process( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, ilen );
    }
}

static const unsigned char sm3_padding[64] =
        {
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

/*
 * SM3 final digest
 */
void sm3_finish( sm3_context *ctx, unsigned char output[32] )
{
    unsigned int last, padn;
    unsigned int high, low;
    unsigned char msglen[8];

    high = ( ctx->total[0] >> 29 )
           | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_ULONG_BE( high, msglen, 0 );
    PUT_ULONG_BE( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sm3_update( ctx, (unsigned char *) sm3_padding, (int)padn );
    sm3_update( ctx, msglen, 8 );

    PUT_ULONG_BE( ctx->state[0], output,  0 );
    PUT_ULONG_BE( ctx->state[1], output,  4 );
    PUT_ULONG_BE( ctx->state[2], output,  8 );
    PUT_ULONG_BE( ctx->state[3], output, 12 );
    PUT_ULONG_BE( ctx->state[4], output, 16 );
    PUT_ULONG_BE( ctx->state[5], output, 20 );
    PUT_ULONG_BE( ctx->state[6], output, 24 );
    PUT_ULONG_BE( ctx->state[7], output, 28 );
}


