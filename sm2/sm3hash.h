//
// Created by lxb on 3/8/16.
//

#ifndef TESTNDK_SM3HASH_H
#define TESTNDK_SM3HASH_H

#endif //TESTNDK_SM3HASH_H
// SM3 Hash计算

#ifndef DCS_ECC_HEADER_DF0AJRW_DF90Y834TERN90_F98AH4____F98AH4___F9A8HTR9______5784__
#define DCS_ECC_HEADER_DF0AJRW_DF90Y834TERN90_F98AH4____F98AH4___F9A8HTR9______5784__

#define SM3_HASH_256				32	// length = 256 bits = 32 bytes

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif


/* 一次性完成
*  pOut: 消息hash结果输出
*  pIn: 消息输入
*  iInLen: 消息长度, 以字节计算
*/
bool Sm3Hash(unsigned char *pOut, const unsigned char *pIn, unsigned int iInLen /* in bytes */);


//多次调用
typedef struct _SM3_HASH_STATE
{
    unsigned int H[8];		//状态寄存器
    unsigned char BB[64];	//未处理的数据,有效长度是(u64Length%64)

#ifdef WIN32
    unsigned __int64 u64Length;
#else	// ARM ads, linux
    unsigned long int u64Length; // unsigned long long int u64Length; //
#endif
} SM3_HASH_STATE;

typedef struct
{
    unsigned int total[2];     /*!< number of bytes processed  */
    unsigned int state[8];     /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */

    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */

}sm3_context;

/*  消息未填充时的哈希结果
*  pIn: 消息输入, 
*  iInLen: 消息字节数
*  pState: H 为消息前64字节分组后的哈希结果, BB[]为 最后消息不足64字节部分
*/
void Sm3HashInit(SM3_HASH_STATE *pState, const unsigned char *pIn, unsigned int iInLen);
/*  原有消息拼接
*   pState状态下,在原有消息后拼接长度为iInLen字节的消息pIn
*   输出: 更新后的pState
*/	
void Sm3HashPending(SM3_HASH_STATE *pState, const unsigned char *pIn, unsigned int iInLen);	
/* 
*  pState状态下,对不足64字节分组消息进行填充并哈希, 得到最终哈希结果pOut
*
*/	
bool Sm3HashFinal(unsigned char *pOut, SM3_HASH_STATE *pState);	// 


// KDF用在SM2的加解密中
unsigned int Sm3KDF(unsigned char *pKeyOut, unsigned int iLenOfOut /* in bytes */, const unsigned char *pSecret, unsigned int iLenOfSecret /* in bytes */, unsigned int ct);




// ----------------------------------------------------------------------
// SM3 HMAC
#define HMAC_B_LENGTH		64
#define HMAC_IPAD			0x36
#define HMAC_OPAD			0x5c

bool Sm3Hmac(unsigned char *pOut, const unsigned char *pMsg, unsigned int iLenOfMsg, const unsigned char *pSecret, int iLenOfSecret);

typedef struct _SM3_HMAC_STATE
{
    unsigned char padding [HMAC_B_LENGTH];
    SM3_HASH_STATE hashState;
} SM3_HMAC_STATE;

// H(K XOR opad, H(K XOR ipad, text))
void Sm3HmacInit(SM3_HMAC_STATE *pState, const unsigned char *pSecret, int iLenOfSecret);	//第一次调用
void Sm3HmacPending(SM3_HMAC_STATE *pState, const unsigned char *pIn, unsigned int iInLen);		//任意多次调用
bool Sm3HmacFinal(unsigned char *pOut, SM3_HMAC_STATE *pState);	//




//第二版hash
#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17))
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23))

void sm3_starts( sm3_context *ctx );
/**
 * \brief          SM3 process buffer
 *
 * \param ctx      SM3 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sm3_update( sm3_context *ctx, unsigned char *input, int ilen );
/**
 * \brief          SM3 final digest
 *
 * \param ctx      SM3 context
 */
void sm3_finish( sm3_context *ctx, unsigned char *output );

#ifdef __cplusplus
}
#endif

#endif // DCS_ECC_HEADER_DF0AJRW_DF90Y834TERN90_F98AH4____F98AH4___F9A8HTR9______5784__
