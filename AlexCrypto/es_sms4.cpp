#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "es_sms4.h"

static void hex_print( unsigned char *data, int len )
{
        int i;
        for(i=0;i<len;i++)
        {
                if( i && i%4==0) printf(" ");
                if( i && i%32==0) printf("\n");
                printf("%02x", data[i]);
        }
        printf("\n");
}



#ifndef ROTATE
#define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#endif


unsigned char S[256]={0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
	0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
	0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
	0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
	0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
	0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
	0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
	0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
	0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
	0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
	0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
	0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
	0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
	0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
	0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
	0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48};

#ifdef WIN32
static __inline SMS4_LONG Tao( SMS4_LONG a )
#else
static inline SMS4_LONG Tao( SMS4_LONG a )
#endif
{
	unsigned char a1,a2,a3,a4;
	//unsigned char b1,b2,b3,b4;
	SMS4_LONG b1,b2,b3,b4;
	SMS4_LONG b;

	a1 = (unsigned char)(((a)    )&0xff);
	a2 = (unsigned char)(((a)>> 8)&0xff);
	a3 = (unsigned char)(((a)>>16)&0xff);
	a4 = (unsigned char)(((a)>>24)&0xff);

	b1 = S[a1];b2=S[a2];b3=S[a3];b4=S[a4];

	b  = b4<<24;
	b |= b3<<16;
	b |= b2<< 8;
	b |= b1;

	return b;
}

#define L(x) ((x) ^ ROTATE((x),2) ^ ROTATE((x),10) ^ ROTATE((x),18) ^ ROTATE((x),24))

#ifdef WIN32
static __inline SMS4_LONG T( SMS4_LONG x )
#else
static inline SMS4_LONG T( SMS4_LONG x )
#endif
{
	SMS4_LONG a;
	a = Tao( x );
	return L(a); 
}

#define Lk(x) ((x) ^ ROTATE((x),13) ^ ROTATE((x),23))

#ifdef WIN32
static __inline SMS4_LONG Tk( SMS4_LONG x )
#else
static inline SMS4_LONG Tk( SMS4_LONG x )
#endif
{
	SMS4_LONG a;
	a = Tao( x );
	return Lk(a); 
}

SMS4_LONG FK[4]={0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC};

SMS4_LONG CK[32]={0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279};

#ifndef HOST_c2l
#define HOST_c2l_xxx(c,l)       (l =(((unsigned long)(*((c)++)))    ),          \
                         l|=(((unsigned long)(*((c)++)))<< 8),          \
                         l|=(((unsigned long)(*((c)++)))<<16),          \
                         l|=(((unsigned long)(*((c)++)))<<24),          \
                         l)

#define HOST_c2l(c,l)   (l =(((unsigned long)(*((c)++)))<<24),          \
                         l|=(((unsigned long)(*((c)++)))<<16),          \
                         l|=(((unsigned long)(*((c)++)))<< 8),          \
                         l|=(((unsigned long)(*((c)++)))    ),          \
                         l)
#endif

#ifdef WIN32
static __inline void R( SMS4_LONG a[4], int len )
#else
static inline void R( SMS4_LONG a[4], int len )
#endif
{
	int i;
	int hlen = len/2;
	SMS4_LONG tmp;

	for(i=0;i<hlen;i++){
		tmp = a[i];
		a[i]=a[len-i-1];
		a[len-i-1]=tmp;
	}
}
#ifdef WIN32
static __inline void keyExpand( SMS4_LONG *pmk, SMS4_LONG *prk )
#else
static inline void keyExpand( SMS4_LONG *pmk, SMS4_LONG *prk )
#endif
{
	int i;
	SMS4_LONG K[36];
	
	for(i=0;i<4;i++){
		K[i] = pmk[i]^FK[i];
	}
	//printf("fk:\n");hex_print( (unsigned char *)FK, sizeof(SMS4_LONG)*4);
	//printf("k:\n");hex_print( (unsigned char *)K, sizeof(SMS4_LONG)*4);

	for(i=0;i<32;i++){
		prk[i]=K[i+4]=K[i]^Tk(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]);
	}
}

/**
加解密扩展方法
对长度小于一个分组(16个字节)的原文补0，再加密
增加原文长度参数length
*/
int SMS4_docipher_ex(const unsigned char m[], unsigned char c[],int length, const unsigned char k[16], int enc)
{
	SMS4_LONG rk[32];
	SMS4_LONG x[36];
	SMS4_LONG y[4];
	SMS4_LONG mk[4];
    unsigned char *ptmp = NULL;
	int j = 0;	
//	unsigned char *in = (unsigned char*)malloc(16); //末尾补0
//	memcpy(in,m,16);//对输入参数m赋值 length 必定小于16

	ptmp = (unsigned char *)k;
	for(j=0;j<4;j++){
		HOST_c2l(ptmp, mk[j]);
	}
	//ptmp = in;
	ptmp = (unsigned char*)m ;
	for(j=0;j<4;j++){
		HOST_c2l(ptmp, x[j]);
	}

	keyExpand( mk, rk );

	if( !enc ) R(rk, sizeof(rk)/sizeof(SMS4_LONG));

	for(j=0;j<32;j++){
		x[j+4] = x[j]^T(x[j+1]^x[j+2]^x[j+3]^rk[j]);
	}	

	//printf("rk:\n");hex_print( (unsigned char *)rk, sizeof(SMS4_LONG)*32);
	//printf("x:\n");hex_print( (unsigned char *)x, sizeof(SMS4_LONG)*36);

	y[0]=x[35];y[1]=x[34];y[2]=x[33];y[3]=x[32];
	
	/**修改部分**/
	unsigned char cOut[16] = {0};
	ptmp = cOut;
	/*******/
	//ptmp = c;//注释 by 彭
	for(j=0;j<4;j++){
		SMS4_LONG t = y[j];
		*(ptmp++) = (unsigned char)(t>>24);
		*(ptmp++) = (unsigned char)(t>>16);
		*(ptmp++) = (unsigned char)(t>> 8);
		*(ptmp++) = (unsigned char)(t);
	}
	//输出
	memcpy(c,cOut,length);
	return 0;
}


/*
分组加密，一次加密16个字节
*/
int SMS4_docipher( unsigned char m[16], unsigned char c[16], const unsigned char k[16], int enc)
{
	SMS4_LONG rk[32];
	SMS4_LONG x[36];
	SMS4_LONG y[4];
	SMS4_LONG mk[4];
	unsigned char *ptmp;
	int j = 0;	

	ptmp = (unsigned char *)k;
	for(j=0;j<4;j++){
                HOST_c2l(ptmp, mk[j]);
	}
	ptmp = m;
	for(j=0;j<4;j++){
                HOST_c2l(ptmp, x[j]);
	}

	keyExpand( mk, rk );

	if( !enc ) R(rk, sizeof(rk)/sizeof(SMS4_LONG));

	for(j=0;j<32;j++){
		x[j+4] = x[j]^T(x[j+1]^x[j+2]^x[j+3]^rk[j]);
	}	

	//printf("rk:\n");hex_print( (unsigned char *)rk, sizeof(SMS4_LONG)*32);
	//printf("x:\n");hex_print( (unsigned char *)x, sizeof(SMS4_LONG)*36);

	y[0]=x[35];y[1]=x[34];y[2]=x[33];y[3]=x[32];
	//输出
	ptmp = c;
	for(j=0;j<4;j++){
		SMS4_LONG t = y[j];
		*(ptmp++) = (unsigned char)(t>>24);
		*(ptmp++) = (unsigned char)(t>>16);
		*(ptmp++) = (unsigned char)(t>> 8);
		*(ptmp++) = (unsigned char)(t);
	}
	return 0;
}



