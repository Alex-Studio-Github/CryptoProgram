
#ifndef _EXPORTINTERFACE_H_
#define _EXPORTINTERFACE_H_


#ifdef _WIN32 

/* ��������붨�� API_CRYPTO_EXPORT */
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
	*����ϵͳ��Ϣ
	**/
	CRYPTO_API int __stdcall  GetComputerInfo(unsigned char* systeminfo,int *systemLength);
	//����ϵͳ��Ϣ����key
	CRYPTO_API int __stdcall  GetKeyFromSystemInfo(unsigned char* systeminfo,int systemLength,
								unsigned char*key,int *length);
	/************************************************************************/
	/*����ϵͳӲ����Ϣ����Ψһ��Կ                                          */
	/************************************************************************/
	CRYPTO_API int __stdcall  GetSystemKey(unsigned char* key,int *keylength);

	CRYPTO_API int __stdcall EnDoCrypto(unsigned char*key,int keylength, 
					unsigned char* proData/*����*/,int prolength,
					unsigned char*secData,int *seclength);

	CRYPTO_API int __stdcall DeDoCrypto(unsigned char*key,int keylength, 
					unsigned char* secData/*����*/,int seclength,
					unsigned char* decData/*����*/,int* declength);

#ifdef	__cplusplus
}
#endif

#endif