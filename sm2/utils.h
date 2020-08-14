#include <stdio.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif

void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen) ;
void Hex2Str(const char *sSrc, char *sDest, int nSrcLen);
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen);
static int hex_decode (char hex);


#ifdef __cplusplus
}
#endif