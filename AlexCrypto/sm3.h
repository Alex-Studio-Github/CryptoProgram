
#ifndef __SM3_HEADER__
#define __SM3_HEADER__


#define  SM3_LBLOCK         16
#define  SM3_CBLOCK         64
#define  SM3_DIGEST_LENGTH  32
#define  SM3_LAST_BLOCK     56

#ifdef WIN32
#define  ulong				unsigned long
#else
#define	 ulong				unsigned int
#endif

  typedef struct SM3state_st {
    ulong h[8];
    ulong Nl,Nh;
    ulong data[SM3_LBLOCK];
    unsigned int  num;
  } SM3_CTX;

  unsigned char *sm3(const unsigned char *d, unsigned int n, unsigned char *md);
  /*
  d:  data
  n:  byte length
  md: 32 bytes digest
  */
  void SM3_Init (SM3_CTX *ctx);
  void SM3_Update(SM3_CTX *ctx, const void *data, unsigned int len);
  void SM3_Final(unsigned char *md, SM3_CTX *ctx);
  int sm3_z(unsigned char *userid, int userid_len, unsigned char *xa, int xa_len, unsigned char *ya, int ya_len, unsigned char *e);


#endif/* __SM3_H__ */
