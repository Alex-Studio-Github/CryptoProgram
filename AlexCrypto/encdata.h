#ifndef _ENCDATA_
#define _ENCDATA_   

#define ENC_DATA		0xEE			//密文标志位
//自定义密文结构,最小40个字节,对齐
typedef struct CIPHERBLOB{
	unsigned char	flag[1];	 //密文标识位 1个字节，使用0xEE
	unsigned int	datalen;	  //密文长度  4
	unsigned char	*data;     //密文		 CipherLen	
	unsigned char	HASH[32];    //摘要sm3的摘要 32
}*pCipherblob;

int binToEncBin(const unsigned char* data,int len, unsigned char* encdata,int *enclen);
int encBinToBin(const unsigned char* encdata,int encLen, unsigned char* outdata,int *len);

#endif