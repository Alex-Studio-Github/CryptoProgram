
#ifndef _EXPORTINTERFACE_H_
#define _EXPORTINTERFACE_H_


#ifdef _WIN32 

/* 导出库必须定义 API_CRYPTO_EXPORT */
#ifdef _WIN32
#define CRYPTO_API  __declspec(dllexport)
#else
#define CRYPTO_API  __declspec(dllimport)
#endif

#else  //linux
#ifndef CRYPTO_API 
#define CRYPTO_API  
#endif
#endif


#ifdef __cplusplus
extern "C" {
#endif

	/**
	*生成系统信息
	**/
	CRYPTO_API int __stdcall  GetComputerInfo(unsigned char* systeminfo,int *systemLength);
	//根据系统信息生成key
	CRYPTO_API int __stdcall  GetKeyFromSystemInfo(unsigned char* systeminfo,int systemLength,
								unsigned char*key,int *length);
	/************************************************************************/
	/*根据系统硬件信息生成唯一密钥                                          */
	/************************************************************************/
	CRYPTO_API int __stdcall  GetSystemKey(unsigned char* key,int *keylength);

	CRYPTO_API int __stdcall EnDoCrypto(unsigned char*key,int keylength, 
					unsigned char* proData/*明文*/,int prolength,
					unsigned char*secData,int *seclength);

	CRYPTO_API int __stdcall DeDoCrypto(unsigned char*key,int keylength, 
					unsigned char* secData/*密文*/,int seclength,
					unsigned char* decData/*明文*/,int* declength);

#ifdef	__cplusplus
}
#endif

#endif