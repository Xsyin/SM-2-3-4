#include <ctype.h>
#include "utils.h"

void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen) {
	short i;
	unsigned char highByte, lowByte;

	for (i = 0; i < sourceLen; i++) {
		highByte = source[i] >> 4;
		lowByte = source[i] & 0x0f;

		highByte += 0x30;

		if (highByte > 0x39)
			dest[i * 2] = highByte + 0x07;
		else
			dest[i * 2] = highByte;

		lowByte += 0x30;
		if (lowByte > 0x39)
			dest[i * 2 + 1] = lowByte + 0x07;
		else
			dest[i * 2 + 1] = lowByte;
	}
	return;
}

//字节流转换为十六进制字符串的另一种实现方式
void Hex2Str(const char *sSrc, char *sDest, int nSrcLen) {
	int i;
	char szTmp[3];

	for (i = 0; i < nSrcLen; i++) {
		sprintf(szTmp, "%02X", (unsigned char) sSrc[i]);
		memcpy(&sDest[i * 2], szTmp, 2);
	}
	return;
}

//十六进制字符串转换为字节流
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen) {
	short i;
	unsigned char highByte, lowByte;

	for (i = 0; i < sourceLen; i += 2) {
		highByte = toupper(source[i]);
		lowByte = toupper(source[i + 1]);

		if (highByte > 0x39)
			highByte -= 0x37;
		else
			highByte -= 0x30;

		if (lowByte > 0x39)
			lowByte -= 0x37;
		else
			lowByte -= 0x30;

		dest[i / 2] = (highByte << 4) | lowByte;
	}
	return;
}

static int hex_decode (char hex)
{
  switch (hex)
    {
    case '0':
      return 0;
    case '1':
      return 1;
    case '2':
      return 2;
    case '3':
      return 3;
    case '4':
      return 4;
    case '5':
      return 5;
    case '6':
      return 6;
    case '7':
      return 7;
    case '8':
      return 8;
    case '9':
      return 9;
    case 'A':
    case 'a':
      return 0x0A;
    case 'B':
    case 'b':
      return 0x0B;
    case 'C':
    case 'c':
      return 0x0C;
    case 'D':
    case 'd':
      return 0x0D;
    case 'E':
    case 'e':
      return 0x0E;
    case 'F':
    case 'f':
      return 0x0F;

    default:
      return -1;
    }

  return -1;
}

