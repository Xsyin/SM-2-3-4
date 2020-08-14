//
// Created by lxb on 3/8/16.
//
//SMS4对称加密算法
#include <stdint.h>

#ifndef TESTNDK_SMS4_H
#define TESTNDK_SMS4_H

#endif //TESTNDK_SMS4_H
#ifndef SMS4_HEADER_FDA90FJA09H___FDA98SFHA____FD98ASFH__
#define SMS4_HEADER_FDA90FJA09H___FDA98SFHA____FD98ASFH__







#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifndef SM4_PARAM
#define SM4_PARAM

#define SMS4_KEY_LENGTH				(128/8)
#define SMS4_BLOCK_LENGTH			(128/8)
#define SMS4_ROUND					32

    enum sm4_mode{
        SM4_ECB             = 0x00000000,
        SM4_CBC             = 0x00000001,

        SM4_ENCRYPT         = 0x00000002,
        SM4_DECRYPT         = 0x00000003,

    };
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    uint32_t sk[32];       /*!<  SM4 subkeys       */
} sm4_context;
#endif

/* 密钥扩展函数
 * subkey: 输出, 加解密时32轮使用的轮密钥
 * key: 输入, 加解密密钥
*/
void Sms4ExtendKey(unsigned int *subkey, const unsigned char *key);
/* sm4 加密
*  输入: plain 128bit明文  
        subkey   32轮密钥
*  输出: cipher 128bit密文
*/
void Sms4Encrypt(unsigned char *cipher, const unsigned char *plain, const unsigned int *subkey);
/* sm4 解密
*  输入: cipher 128bit密文  
        subkey   32轮密钥
*  输出: plain 128bit明文
*/
void Sms4Decrypt(unsigned char *plain, const unsigned char *cipher, const unsigned int *subkey);

/* sm4 加解密 CBC 模式
*  ctx: 模式与轮密钥
*  mode: 1. sm4_mode::SM4_ENCRYPT  则 input 明文, output 密文
         2. sm4_mode::SM4_DECRYPT  则 input 密文, output 明文
   iv: 初始向量
*/
void sm4_crypt_cbc( sm4_context *ctx,
                    int mode,
                    int length,
                    unsigned char *iv,
                    unsigned char *input,
                    unsigned char *output );

/*  加解密时的T变换:s盒与循环移位
*   return: 某一轮加解密的结果
*    w0 ^ T(w1 ^ w2 ^ w3 ^ rkey)
*/
unsigned int Sms4F(unsigned int w0, unsigned int w1, unsigned int w2, unsigned int w3, unsigned int rkey);

/* 密钥扩展时的T'变换: s盒与循环移位
*  return: w0 ⊕ T ′ ( w1⊕w2⊕w3 ⊕ck)  某一轮的轮密钥
*/
unsigned int Sms4FinExtendedKey(unsigned int w0, unsigned int w1, unsigned int w2, unsigned int w3, unsigned int ck);

#ifdef __cplusplus
}

#endif // __cplusplus


#endif // SMS4_HEADER_FDA90FJA09H___FDA98SFHA____FD98ASFH__
