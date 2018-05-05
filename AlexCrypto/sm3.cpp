#include "stdafx.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "sm3.h"

#define nl2c(l,c)	(*((c)++) = (unsigned char)(((l) >> 24) & 0xff), \
					 *((c)++) = (unsigned char)(((l) >> 16) & 0xff), \
					 *((c)++) = (unsigned char)(((l) >> 8)  & 0xff), \
					 *((c)++) = (unsigned char)(((l)    )   & 0xff))

#define c_2_nl(c)	((*(c) << 24) | (*(c+1) << 16) | (*(c+2) << 8) | *(c+3))
#define ROTATE(X, C) (((X) << (C)) | ((X) >> (32 - (C))))

#define TH 0x79cc4519
#define TL 0x7a879d8a
#define FFH(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FFL(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GGH(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GGL(X, Y, Z) (((X) & (Y)) | ((~X) & (Z)))
#define P0(X)  ((X) ^ (((X) << 9) | ((X) >> 23)) ^ (((X) << 17) | ((X) >> 15)))
#define P1(X)  ((X) ^ (((X) << 15) | ((X) >> 17)) ^ (((X) << 23) | ((X) >> 9)))

#define DEBUG_SM3 0

#if DEBUG_SM3
void PrintBuf(unsigned char *buf, int	buflen)
{
  int i;
  printf("\n");
  printf("len = %d\n", buflen);
  for(i=0; i<buflen; i++) {
    if (i % 32 != 31)
      printf("%02x", buf[i]);
    else
      printf("%02x\n", buf[i]);
  }
  printf("\n");
  return;
}
#endif

unsigned char sm2_par_dig[128] = {
  0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
  0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
  0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,
  0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
  0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,
  0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
  0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0,
};

void sm3_block(SM3_CTX *ctx)
{
  register int j, k;
  register ulong t;
  register ulong ss1, ss2, tt1, tt2;
  register ulong a, b, c, d, e, f, g, h;
  ulong w[132];


  for(j = 0; j < 16; j++)
    w[j] = ctx->data[j];

  for(j = 16; j < 68; j++) {
    t = w[j-16] ^ w[j-9] ^ ROTATE(w[j-3], 15);
    w[j] = P1(t) ^ ROTATE(w[j-13], 7) ^ w[j-6];
  }


  for(j = 0, k = 68; j < 64; j++, k++) {
    w[k] = w[j] ^ w[j+4];
  }


  a = ctx->h[0];
  b = ctx->h[1];
  c = ctx->h[2];
  d = ctx->h[3];
  e = ctx->h[4];
  f = ctx->h[5];
  g = ctx->h[6];
  h = ctx->h[7];

  for(j = 0; j < 16; j++) {
    ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TH, j), 7);
    ss2 = ss1 ^ ROTATE(a, 12);
    tt1 = FFH(a, b, c) + d + ss2 + w[68 + j];
    tt2 = GGH(e, f, g) + h + ss1 + w[j];

    d = c;
    c = ROTATE(b, 9);
    b = a;
    a = tt1;

    h = g;
    g = ROTATE(f, 19);
    f = e;
    e = P0(tt2);
  }


  for(j = 16; j < 33; j++) {
    ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TL, j), 7);
    ss2 = ss1 ^ ROTATE(a, 12);
    tt1 = FFL(a, b, c) + d + ss2 + w[68 + j];
    tt2 = GGL(e, f, g) + h + ss1 + w[j];

    d = c;
    c = ROTATE(b, 9);
    b = a;
    a = tt1;

    h = g;
    g = ROTATE(f, 19);
    f = e;
    e = P0(tt2);
  }


  for(j = 33; j < 64; j++) {
    ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TL, (j-32)), 7);
    ss2 = ss1 ^ ROTATE(a, 12);
    tt1 = FFL(a, b, c) + d + ss2 + w[68 + j];
    tt2 = GGL(e, f, g) + h + ss1 + w[j];

    d = c;
    c = ROTATE(b, 9);
    b = a;
    a = tt1;

    h = g;
    g = ROTATE(f, 19);
    f = e;
    e = P0(tt2);
  }


  ctx->h[0]  ^=  a ;
  ctx->h[1]  ^=  b ;
  ctx->h[2]  ^=  c ;
  ctx->h[3]  ^=  d ;
  ctx->h[4]  ^=  e ;
  ctx->h[5]  ^=  f ;
  ctx->h[6]  ^=  g ;
  ctx->h[7]  ^=  h ;

}


void SM3_Init (SM3_CTX *ctx)
{
  ctx->h[0] = 0x7380166fUL;
  ctx->h[1] = 0x4914b2b9UL;
  ctx->h[2] = 0x172442d7UL;
  ctx->h[3] = 0xda8a0600UL;
  ctx->h[4] = 0xa96f30bcUL;
  ctx->h[5] = 0x163138aaUL;
  ctx->h[6] = 0xe38dee4dUL;
  ctx->h[7] = 0xb0fb0e4eUL;
  ctx->Nl   = 0;
  ctx->Nh   = 0;
  ctx->num  = 0;
}

void SM3_Update(SM3_CTX *ctx, const void *data, unsigned int len)
{
  unsigned char *d;
  ulong l;
  int i, sw, sc;


  if (len == 0)
    return;

  l = (ctx->Nl + (len << 3)) & 0xffffffffL;
  if (l < ctx->Nl) /* overflow */
    ctx->Nh++;
  ctx->Nh += (len >> 29);
  ctx->Nl = l;


  d = (unsigned char *)data;

  while (len >= SM3_CBLOCK) {
    ctx->data[0] = c_2_nl(d);
    d += 4;
    ctx->data[1] = c_2_nl(d);
    d += 4;
    ctx->data[2] = c_2_nl(d);
    d += 4;
    ctx->data[3] = c_2_nl(d);
    d += 4;
    ctx->data[4] = c_2_nl(d);
    d += 4;
    ctx->data[5] = c_2_nl(d);
    d += 4;
    ctx->data[6] = c_2_nl(d);
    d += 4;
    ctx->data[7] = c_2_nl(d);
    d += 4;
    ctx->data[8] = c_2_nl(d);
    d += 4;
    ctx->data[9] = c_2_nl(d);
    d += 4;
    ctx->data[10] = c_2_nl(d);
    d += 4;
    ctx->data[11] = c_2_nl(d);
    d += 4;
    ctx->data[12] = c_2_nl(d);
    d += 4;
    ctx->data[13] = c_2_nl(d);
    d += 4;
    ctx->data[14] = c_2_nl(d);
    d += 4;
    ctx->data[15] = c_2_nl(d);
    d += 4;

    sm3_block(ctx);
    len -= SM3_CBLOCK;
  }

  if(len > 0) {
    memset(ctx->data, 0, 64);
    ctx->num = len + 1;
    sw = len >> 2;
    sc = len & 0x3;

    for(i = 0; i < sw; i++) {
      ctx->data[i] = c_2_nl(d);
      d += 4;
    }

    switch(sc) {
    case 0:
      ctx->data[i] = 0x80000000;
      break;
    case 1:
      ctx->data[i] = (d[0] << 24) | 0x800000;
      break;
    case 2:
      ctx->data[i] = (d[0] << 24) | (d[1] << 16) | 0x8000;
      break;
    case 3:
      ctx->data[i] = (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | 0x80;
      break;
    }
  }
}

void SM3_Final(unsigned char *md, SM3_CTX *ctx)
{

  if(ctx->num == 0) {
    memset(ctx->data, 0, 64);
    ctx->data[0] = 0x80000000;
    ctx->data[14] = ctx->Nh;
    ctx->data[15] = ctx->Nl;
  } else {
    if(ctx->num <= SM3_LAST_BLOCK) {
      ctx->data[14] = ctx->Nh;
      ctx->data[15] = ctx->Nl;
    } else {
      sm3_block(ctx);
      memset(ctx->data, 0, 56);
      ctx->data[14] = ctx->Nh;
      ctx->data[15] = ctx->Nl;
    }
  }

  sm3_block(ctx);

  nl2c(ctx->h[0], md);
  nl2c(ctx->h[1], md);
  nl2c(ctx->h[2], md);
  nl2c(ctx->h[3], md);
  nl2c(ctx->h[4], md);
  nl2c(ctx->h[5], md);
  nl2c(ctx->h[6], md);
  nl2c(ctx->h[7], md);
}

unsigned char *sm3(const unsigned char *d, unsigned int n, unsigned char *md)
{
  SM3_CTX ctx;

  SM3_Init(&ctx);
  SM3_Update(&ctx, d, n);
  SM3_Final(md, &ctx);
  memset(&ctx, 0, sizeof(ctx));

  return(md);
}

int sm3_z(unsigned char *userid, int userid_len, unsigned char *xa, int xa_len, unsigned char *ya, int ya_len, unsigned char *z)
{
  /*
  功能：根据用户ID及公钥，求Z值
  [输入] userid： 用户ID
  [输入] userid_len： userid的字节数
  [输入] xa： 公钥的X坐标
  [输入] xa_len: xa的字节数
  [输入] ya： 公钥的Y坐标
  [输入] ya_len: ya的字节数
  [输出] z：32字节

  返回值：
  		－1：内存不足
  		  0：成功
  */
  unsigned char *buf;
  int userid_bitlen;

  if((xa_len > 32) || (ya_len > 32))
    return -1;

  buf = (unsigned char *)malloc(2+userid_len+128+32+32);
  if(buf == NULL)
    return -1;

  userid_bitlen = userid_len << 3;
  buf[0] = (userid_bitlen >> 8) & 0xFF;
  buf[1] = userid_bitlen & 0xFF;

  memcpy(buf+2, userid, userid_len);
  memcpy(buf+2+userid_len, sm2_par_dig, 128);

  memset(buf+2+userid_len+128, 0, 64);
  memcpy(buf+2+userid_len+128+32-xa_len, xa, 32);
  memcpy(buf+2+userid_len+128+32+32-ya_len, ya, 32);

  sm3(buf, 2+userid_len+128+32+32, z);
  free(buf);

#if DEBUG
  printf("sm3_z: ");
  PrintBuf(z, 32);
#endif

  return 0;

}


