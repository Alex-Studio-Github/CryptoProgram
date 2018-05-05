#include "stdafx.h"
#include "exportInterface.h"
#include "es_sms4_mode.h"
#include "sm3.h"

#include "stdio.h"
#include  "stdlib.h"
#include "conio.h"
#include "encdata.h"

//异或替代码
#ifndef   UNUSUAL_SYMMETRY  
#define   UNUSUAL_SYMMETRY  0X5B
#endif

void XorToBit( char*t,int length)
{
	int index = 0;
	while(index < length)
	{
		t[index] = (t[index]) ^ UNUSUAL_SYMMETRY;
		index++;
	}
}

static void* Malloc_Space(int length)
{
	void* out = (void*)malloc(length);
	memset(out,0,length);
	return out;
}
static void Free_Space(void* fr)
{
	if(fr)
		free(fr);
	fr = NULL;
}

/**
填充方法 pkcs#5
填充 需要填充的值 ，方便去填充 
*/
static void PaddingData(unsigned char* data,int datalength,
					unsigned char* paddingData,int *paddingLength)
{
	//取模值
	int mol = datalength  %  16;
	if(paddingData == NULL)
	{
		*paddingLength = datalength + 16 - mol;
		return;
	}
	//取填充值 
	int pad = 16 - mol;
	unsigned char* tmp = (unsigned char*)Malloc_Space(datalength+ pad);
		
	memcpy(tmp,data,datalength);
	int index = 0;
	while(index < pad)
	{
		tmp[datalength  + index] = pad;
		index++;
	}
	memcpy(paddingData,tmp,datalength + pad);
	Free_Space(tmp);
	tmp = NULL;
	return;
}
/**
去填充方法
*/
static void UnPaddingData(unsigned char* paddingData,int paddingLength,
						  unsigned char* data,int *datalength)
{
	if(paddingData == NULL || paddingLength == 0)
		return;
	int padd = paddingData[paddingLength - 1] ;
	*datalength = paddingLength - padd;
	if(data == NULL)
	{	
		return ;
	}
	memcpy(data , paddingData , *datalength );
	return ;
}


//取系统信息，生成对称密钥 ，生成摘要使用 sm3算法
CRYPTO_API int __stdcall GetSystemKey(unsigned char* outkey,int *keylength)
{
	if(!outkey) // 必须上层分配
	{
		return -1;
	}

#ifdef _WIN32

	char diskSeal[128] = {0};
	char mainBoard[128] = {0};
	char total[128*2] = {0};
	int totalLength = 0;
	bool rv = 0 ;
	totalLength = 65;
	GetComputerInfo((unsigned char*)total,&totalLength);
/*
	if(GetHDSerial(diskSeal) == 1)
	{
		strcpy_s(total, diskSeal);
		totalLength = strlen(total);
		//strcat_s(total,totalLength,"peng");
	}
	else
	{
		char cmd[]= "wmic BaseBoard get SerialNumber";
		rv = GetBaseBoardByCmd(cmd, mainBoard);
		if(rv == 1)
		{
			strcpy_s(total, mainBoard);
			totalLength = strlen(total);
		}

		if(strlen(total)<2)
		{
			char cmd[]= "wmic DiskDrive get SerialNumber";
			memset(total,0x00,sizeof(total));
			GetBaseBoardByCmd(cmd, total);
		}
		printf("mainBoard %s\n",total);
		totalLength = strlen(total);

		if(totalLength < 2)
		{
			strcpy(total,"STDST12345");
			totalLength = strlen(total);
		}
	}

*/	
	printf("key %s , length %d\n", total,totalLength);
	XorToBit(total,totalLength);//作异或运算
	//生成key
	unsigned char key[65] = {0};
	//unsigned char *sm3(const unsigned char *d, unsigned int n, unsigned char *md);
	sm3((const unsigned char *) total, totalLength,key);
	*keylength = 16;
	key[*keylength] = '\0';
	memcpy(outkey,key,*keylength);
	//取前面16位
#else  
	//linux

#endif	
	return 0;
}

//获取系统信息
CRYPTO_API int __stdcall  GetComputerInfo(unsigned char* systeminfo,int *systemLength)
{

#ifdef _WIN32_no_define

	char diskSeal[128] = {0};
	char mainBoard[128] = {0};
	char total[128*2] = {0};
	int totalLength = 0;
	int rv =  0;
	char tmp[] = {"STDST12345"};
#if 1  //临时处理

	if(systeminfo == NULL)
	{
		 *systemLength = strlen(tmp) + 1;
		 return 0;
	}
	  *systemLength = strlen(tmp) ;
	 memcpy(systeminfo,(const char*)(tmp),*systemLength);
	 return 0;

#endif 


	if(GetHDSerial(diskSeal) == 1)
	{
		strcpy_s(total, diskSeal);
		totalLength = strlen(total);
		printf("diskSeal： %s\n",diskSeal);
	}
	else
	{
		char cmd[]= "wmic BaseBoard get SerialNumber";
		rv = GetBaseBoardByCmd(cmd, mainBoard);
		if(rv == 1)
		{
			strcpy_s(total, mainBoard);
			totalLength = strlen(total);
		}
		
		if(strlen(total)<2)
		{
			char cmd[]= "wmic DiskDrive get SerialNumber";
			memset(total,0x00,sizeof(total));
			GetBaseBoardByCmd(cmd, total);
		}
		printf("mainBoard %s\n",total);
		totalLength = strlen(total);
		
		if(totalLength < 2)
		{
			strcpy(total,"STDST12345");
			totalLength = strlen(total);
		}

	}

	//unsigned char* out = (unsigned char*) malloc(sizeof(unsigned char)*totalLength); memset(out,0,totalLength);
	*systemLength = totalLength;
	if(systeminfo != NULL)
	{
		memcpy(systeminfo,total,*systemLength );
	}
	
#endif
	 return 0;
}
//根据系统信息生成key
CRYPTO_API int __stdcall  GetKeyFromSystemInfo(unsigned char* systeminfo,int systemLength,
	unsigned char*outKey,int *keylength)
{
	unsigned char* tmp = new unsigned char[systemLength];
	memcpy(tmp,systeminfo,systemLength);
	XorToBit((char*)tmp,systemLength);//作异或运算
	//生成key
	unsigned char thiskey[65] = {0};
	//unsigned char *sm3(const unsigned char *d, unsigned int n, unsigned char *md);
	sm3((const unsigned char *) tmp, systemLength,thiskey);
	*keylength = 16;
	thiskey[*keylength] = '\0';
	if(outKey != NULL)
		memcpy(outKey,thiskey,*keylength);
	delete [] tmp;
	return 0;
}


/**
//加密方法 sm4  ecb电码本模式
*/
CRYPTO_API int __stdcall EnDoCrypto(unsigned char*key,int keylength, 
	    unsigned char* proData/*明文*/,int prolength,
		unsigned char*secData,int *seclength)
{
	unsigned char* paddata = NULL;
	int  padlength = 0 ;
	//加密前，明文做填充
	PaddingData(proData,prolength,paddata,&padlength);
	

	paddata =(unsigned char*) Malloc_Space(padlength);
	PaddingData(proData,prolength,paddata,&padlength);

	unsigned char* tSec = (unsigned char*) Malloc_Space(padlength);
	unsigned char *tt = tSec;
	/*加密*/
	SMS4_ecb_encrypt(paddata,tt,padlength,key,1);
	//加密后密文转换tSec,padlength
	//返长度
	if(secData == NULL || *seclength < 1)
	{ 
		if(binToEncBin((const unsigned char*)tSec,padlength, NULL ,seclength) !=0 )
		{
			return -1;
		}
		return 0;
	}
	if(binToEncBin((const unsigned char*)tSec,padlength,secData,seclength) !=0 )
	{
		return -1;
	}
	Free_Space(tSec);   
	tSec = NULL;
	Free_Space(paddata);  
	paddata = NULL;
	return 0;
}
/**
//解密
***/
CRYPTO_API int __stdcall DeDoCrypto(unsigned char*key,int keylength, 
	unsigned char* secData/*密文*/,int seclength,
	unsigned char* decData/*明文*/,int* declength)
{
	unsigned char* enc = NULL;		//从入参中提取的密文
	int enclen = 0;					//enc 对应的长度

	unsigned char* unPaddata = NULL;
	int unPadLen = 0;
	int rv = 0 ;
	//取出实际密文
	/**密文判断*/
	rv = encBinToBin(secData,seclength,NULL,&enclen);
	if(rv != 0)
	{
		return rv;
	}
	enc	= (unsigned char*)Malloc_Space(enclen);
	rv = encBinToBin(secData,seclength,enc,&enclen);
	if(rv != 0)
	{
		return rv;
	}
	//解密,形成unPand的解密文
	unPadLen = enclen;
	unPaddata = (unsigned char*)Malloc_Space(unPadLen);
	SMS4_ecb_encrypt(enc,unPaddata,unPadLen,key,0);

	//去填充
	printf("解密后带填充的长度:%d\n",unPadLen);
	if(decData == NULL )
	{
		UnPaddingData(unPaddata,unPadLen,NULL,declength);
		Free_Space(enc);
		Free_Space(unPaddata); 
		return 0;
	}
	UnPaddingData(unPaddata,unPadLen,decData,declength);
	Free_Space(enc);
	Free_Space(unPaddata);    
	unPaddata = NULL;
	
	return 0;
}


void  test_main()
{
	unsigned char pk[16] = {0};
	int  keylength = 16 ;
	int rv = -1;
	//GetSystemKey(pk,&keylength);

	unsigned char computer[128] = {0};
	int sysLength = 128;
	GetComputerInfo(computer,&sysLength);
	printf("系统信息为： %s,length =%d\n",computer,sysLength);
	
	return ;


	int mykeyLenght = 16;
	unsigned char outKey[16] = {0};
	//派生公钥
	GetKeyFromSystemInfo(computer,sysLength,outKey,&mykeyLenght);
	int j = -1;
	do
	{
		j++;
		if( outKey[j] == pk[j])
			continue;
		printf("key is error\n");
		
	}while(j<16);
	printf("key right\n");
	//return ;
	unsigned char mingdata[] = {0x3b,0xcb,0x6b,0xcb,0x6e,0x6e,0x7e};

	unsigned char secdata[116] = {0}; 
	int seclen = 116;
	//加密,对加密的密文做特殊处理，区分明文和密文
	rv = EnDoCrypto(pk,keylength,(unsigned char *)mingdata,sizeof(mingdata) ,(unsigned char*)secdata,&seclen);
	
	//解密，解密过程中提取密文，如果密文格式不正确返回错误
	int declen = 0;
	rv = DeDoCrypto(pk,keylength,(unsigned char *)secdata,seclen,NULL,&declen);
	unsigned char *dec = (unsigned char*)malloc(declen);
	rv = DeDoCrypto(pk,keylength,(unsigned char *)secdata,seclen,(unsigned char*)dec,&declen);
	free(dec);
	return;
}