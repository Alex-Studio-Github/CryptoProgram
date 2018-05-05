#ifndef _ENCDATA_
#define _ENCDATA_   

#define ENC_DATA		0xEE			//���ı�־λ
//�Զ������Ľṹ,��С40���ֽ�,����
typedef struct CIPHERBLOB{
	unsigned char	flag[1];	 //���ı�ʶλ 1���ֽڣ�ʹ��0xEE
	unsigned int	datalen;	  //���ĳ���  4
	unsigned char	*data;     //����		 CipherLen	
	unsigned char	HASH[32];    //ժҪsm3��ժҪ 32
}*pCipherblob;

int binToEncBin(const unsigned char* data,int len, unsigned char* encdata,int *enclen);
int encBinToBin(const unsigned char* encdata,int encLen, unsigned char* outdata,int *len);

#endif