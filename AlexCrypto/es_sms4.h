#ifndef SMS4_H_
#define SMS4_H_

#define SMS4_LONG unsigned long

#define SMS4_BLOCK_SIZE 16 
#define SMS4_KEY_SIZE 16

#define SMS4_ENCRYPT 1
#define SMS4_DECRYPT 0

/**
密钥匙一个分组长度 ,一个分组长度为16bit,2个字节
enc ：
false-> 解密 
true->加密
*/
int SMS4_docipher( unsigned char m[16], unsigned char c[16], const unsigned char k[16], int enc);
/**
新增扩展方法，原文长度小于分组长度16
*/
int SMS4_docipher_ex(const unsigned char m[], unsigned char c[],int length, const unsigned char k[16], int enc);
#endif
