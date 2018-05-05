#include "stdafx.h"
#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encdata.h"
#include "sm3.h"


bool isEqu(const unsigned char* src,const unsigned char* dec ,int len)
{
	int  i = 0 ;
	for(;i< len ; i++)
	{
		if(src[i] != dec[i])
		{
			return false;
		}
	}
	return true;
}
/*
typedef struct CIPHERBLOB{
unsigned char	flag[1];	 //密文标识位 1个字节，使用0xEE
unsigned int	datalen;	  //密文长度  4
unsigned char	*data;     //密文		 datalen	
unsigned char	HASH[32];    //摘要sm3的摘要 32
}*pCipherblob;
**/
//二进制数据转cipherblob结构，加密使用
//return -1 错误，0成功
int binToEncBin(const unsigned char* data,int len, unsigned char* encdata,int *enclen)
{
	CIPHERBLOB blob;
	unsigned char digest[32];
	int digestlen = 32;
	if(len < 16 || (data == NULL)  )
		return -1;
	
	blob.datalen = len;
	blob.flag[0] = ENC_DATA;
	blob.data  = (unsigned char *)malloc(len); memset(blob.data,0,len);
	memcpy(blob.data,data,len);

	memset(digest,0,digestlen);
	sm3(data,len,digest);

	memcpy(blob.HASH,digest,digestlen);
	//设置blob
	
	if( encdata == NULL)
	{
		*enclen = 1 + 4 + blob.datalen + 32;
		free(blob.data);
		return 0 ;
	}
	*enclen = 1 + 4 + blob.datalen + 32;
	//拼接encdata
	encdata[0] = blob.flag[0]; //标志位
	//设置长度blob.datalen
	encdata[1] = (blob.datalen) >> 24;
	encdata[2] = (blob.datalen) >> 16;
	encdata[3] = (blob.datalen) >> 8;
	encdata[4] = (blob.datalen);

	memcpy(encdata+5,blob.data,blob.datalen);
	memcpy(encdata + 5 + blob.datalen,blob.HASH,digestlen);

	free(blob.data);
	return 0;
}
//解密使用，密文数据转换成密文结构
//return -1 错误，0成功
int encBinToBin(const unsigned char* encdata,int encLen, unsigned char* outdata,int *len)
{
	CIPHERBLOB blob;
	unsigned char digest[32];
	int digestlen = 32;
	int dlen = 32;
	try
	{
		if(encLen < 53) //密文结构长度至少 1 + 4 + blob.datalen + 32 >= 53
		{
			return -1;		//密文格式错误
		}
		blob.flag[0] = encdata[0]; //取标志位判断
		if(blob.flag[0] != ENC_DATA)
		{
			return -1;			//密文格式错误
		}
		blob.datalen = encdata[1] << 24 |   //取密文长度
			           encdata[2] << 16 |
					   encdata[3] << 8 |
					   encdata[4];
 		
		if( encLen  != (1 + 4 + blob.datalen + 32) )
		{
			return -1;			//密文格式错误
		}
		if(blob.datalen < 16)
		{
			return -1;			//密文格式错误
		}
		blob.data = (unsigned char*)malloc(blob.datalen);
		memcpy(blob.data, encdata+5 ,blob.datalen);	//提取密文
		memcpy(blob.HASH ,encdata+5+blob.datalen , 32);//提取密文的摘要值
		//计算摘要
		sm3(blob.data,blob.datalen,digest);
		if(!isEqu((const unsigned char*)blob.HASH, (const unsigned char*)digest, digestlen))
		{
			return -1;		//格式错误
		}
		if(outdata == NULL)
		{
			*len = blob.datalen; 
			return 0 ;
		}
		memcpy(outdata,blob.data,blob.datalen);
		free(blob.data);
		blob.data = NULL;
	}
	catch (...)
	{
		return -1;
	}
	return 0;
}
