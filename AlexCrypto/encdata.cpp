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
unsigned char	flag[1];	 //���ı�ʶλ 1���ֽڣ�ʹ��0xEE
unsigned int	datalen;	  //���ĳ���  4
unsigned char	*data;     //����		 datalen	
unsigned char	HASH[32];    //ժҪsm3��ժҪ 32
}*pCipherblob;
**/
//����������תcipherblob�ṹ������ʹ��
//return -1 ����0�ɹ�
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
	//����blob
	
	if( encdata == NULL)
	{
		*enclen = 1 + 4 + blob.datalen + 32;
		free(blob.data);
		return 0 ;
	}
	*enclen = 1 + 4 + blob.datalen + 32;
	//ƴ��encdata
	encdata[0] = blob.flag[0]; //��־λ
	//���ó���blob.datalen
	encdata[1] = (blob.datalen) >> 24;
	encdata[2] = (blob.datalen) >> 16;
	encdata[3] = (blob.datalen) >> 8;
	encdata[4] = (blob.datalen);

	memcpy(encdata+5,blob.data,blob.datalen);
	memcpy(encdata + 5 + blob.datalen,blob.HASH,digestlen);

	free(blob.data);
	return 0;
}
//����ʹ�ã���������ת�������Ľṹ
//return -1 ����0�ɹ�
int encBinToBin(const unsigned char* encdata,int encLen, unsigned char* outdata,int *len)
{
	CIPHERBLOB blob;
	unsigned char digest[32];
	int digestlen = 32;
	int dlen = 32;
	try
	{
		if(encLen < 53) //���Ľṹ�������� 1 + 4 + blob.datalen + 32 >= 53
		{
			return -1;		//���ĸ�ʽ����
		}
		blob.flag[0] = encdata[0]; //ȡ��־λ�ж�
		if(blob.flag[0] != ENC_DATA)
		{
			return -1;			//���ĸ�ʽ����
		}
		blob.datalen = encdata[1] << 24 |   //ȡ���ĳ���
			           encdata[2] << 16 |
					   encdata[3] << 8 |
					   encdata[4];
 		
		if( encLen  != (1 + 4 + blob.datalen + 32) )
		{
			return -1;			//���ĸ�ʽ����
		}
		if(blob.datalen < 16)
		{
			return -1;			//���ĸ�ʽ����
		}
		blob.data = (unsigned char*)malloc(blob.datalen);
		memcpy(blob.data, encdata+5 ,blob.datalen);	//��ȡ����
		memcpy(blob.HASH ,encdata+5+blob.datalen , 32);//��ȡ���ĵ�ժҪֵ
		//����ժҪ
		sm3(blob.data,blob.datalen,digest);
		if(!isEqu((const unsigned char*)blob.HASH, (const unsigned char*)digest, digestlen))
		{
			return -1;		//��ʽ����
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
