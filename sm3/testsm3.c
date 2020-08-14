/*
 * testsm3.c
 *
 *  Created on: 2020-8-13
 *      Author: xsyin
 */
//Testing data from SM3 Standards
//http://www.oscca.gov.cn/News/201012/News_1199.htm
// Sample 1
// Input:"abc"
// Output:66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

// Sample 2
// Input:"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
// Outpuf:debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732

#include <stdio.h>
#include <string.h>
#include "sm3hash.h"

void printHexStr(unsigned char* data_addr, int len) {
	int i = 0;
	printf("len = %d\n", len);
	for (i = 0; i < len; i++) {
		printf("0x%02x ", *(data_addr + i));
	}
	printf("\n");
}
int main() {
	unsigned char out[512];
	char array[16] = {0xa, 0xb, 0xc, 0xd, 0xe,0xa, 0xb, 0xc, 0xd, 0xe,0xa, 0xb, 0xc, 0xd, 0xe,0xf};

	char key[16] =    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5,  0x6, 0x7 , 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
	
	// memset(out, 0x00, 512);
	// bool is = Sm3Hmac(out, array, 16, key, 16);
	// printf("%d\n", is);
	// printHexStr(out, strlen((char*)out));
	
	unsigned char *str = "abc";
	char *str1 = "abcd";
	unsigned char hashOut[32] = {0};
	printf("Message: %s\n", str);
	Sm3Hash(hashOut, str, 3);
	
	printf("hash result: ");
	printHexStr(hashOut, 32);

	printf("Message 1: ");
	for (size_t i = 0; i < 16; i++)
	{
		printf(" %s", str1);
	}
	SM3_HASH_STATE state1;
	Sm3HashInit(&state1, str1, 4);
	for (size_t i = 0; i < 15; i++)
	{
		Sm3HashPending(&state1, str1, 4);
	}
	Sm3HashFinal(hashOut, &state1);
	printf("\n");
	printHexStr(hashOut, 32);

	printf("Message: %s\n", str);
	sm3_context sm3Cnt;
	sm3_starts(&sm3Cnt);
	sm3_update(&sm3Cnt, str, 3);
	sm3_finish(&sm3Cnt, hashOut);
	printHexStr(hashOut, 32);

	return 0;
}

