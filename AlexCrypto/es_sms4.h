#ifndef SMS4_H_
#define SMS4_H_

#define SMS4_LONG unsigned long

#define SMS4_BLOCK_SIZE 16 
#define SMS4_KEY_SIZE 16

#define SMS4_ENCRYPT 1
#define SMS4_DECRYPT 0

/**
��Կ��һ�����鳤�� ,һ�����鳤��Ϊ16bit,2���ֽ�
enc ��
false-> ���� 
true->����
*/
int SMS4_docipher( unsigned char m[16], unsigned char c[16], const unsigned char k[16], int enc);
/**
������չ������ԭ�ĳ���С�ڷ��鳤��16
*/
int SMS4_docipher_ex(const unsigned char m[], unsigned char c[],int length, const unsigned char k[16], int enc);
#endif
