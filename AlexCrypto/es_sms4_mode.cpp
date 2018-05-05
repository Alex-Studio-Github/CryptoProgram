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

//iv 就是一个分组长度
void SMS4_cbc_encrypt(const unsigned char *in, unsigned char *out,
        const unsigned long length, const unsigned char *key,
        unsigned char *ivec, const int enc)
{
	SMS4_LONG n;
	SMS4_LONG len = length;
	unsigned char tmp[SMS4_BLOCK_SIZE];
	const unsigned char *iv = ivec;

	if( enc == SMS4_ENCRYPT ) {
		while (len >= SMS4_BLOCK_SIZE) {
			for(n=0; n < SMS4_BLOCK_SIZE; ++n)
				out[n] = in[n] ^ iv[n];
			SMS4_docipher(out, out, key, enc);
			iv = out;
			len -= SMS4_BLOCK_SIZE;
			in += SMS4_BLOCK_SIZE;
			out += SMS4_BLOCK_SIZE;
		}
		if (len) {
			for(n=0; n < len; ++n)
				out[n] = in[n] ^ iv[n];
			for(n=len; n < SMS4_BLOCK_SIZE; ++n)
				out[n] = iv[n];
			SMS4_docipher(out, out, key, enc);
			iv = out;
		}
		memcpy(ivec,iv,SMS4_BLOCK_SIZE);
	} else if (in != out) {
		while (len >= SMS4_BLOCK_SIZE) {
			SMS4_docipher((unsigned char *)in, out, key, enc);
			for(n=0; n < SMS4_BLOCK_SIZE; ++n)
				out[n] ^= iv[n];
			iv = in;
			len -= SMS4_BLOCK_SIZE;
			in  += SMS4_BLOCK_SIZE;
			out += SMS4_BLOCK_SIZE;
		}
		if (len) {
			SMS4_docipher((unsigned char *)in,tmp,key, enc);
			for(n=0; n < len; ++n)
				out[n] = tmp[n] ^ iv[n];
			iv = in;
		}
		memcpy(ivec,iv,SMS4_BLOCK_SIZE);
	} else {
		while (len >= SMS4_BLOCK_SIZE) {
			memcpy(tmp, in, SMS4_BLOCK_SIZE);
			SMS4_docipher((unsigned char *)in, out, key, enc);
			for(n=0; n < SMS4_BLOCK_SIZE; ++n)
				out[n] ^= ivec[n];
			memcpy(ivec, tmp, SMS4_BLOCK_SIZE);
			len -= SMS4_BLOCK_SIZE;
			in += SMS4_BLOCK_SIZE;
			out += SMS4_BLOCK_SIZE;
		}
		if (len) {
			memcpy(tmp, in, SMS4_BLOCK_SIZE);
			SMS4_docipher(tmp, out, key, enc);
			for(n=0; n < len; ++n)
				out[n] ^= ivec[n];
			for(n=len; n < SMS4_BLOCK_SIZE; ++n)
				out[n] = tmp[n];
			memcpy(ivec, tmp, SMS4_BLOCK_SIZE);
		}
	}

}

void SMS4_ecb_encrypt(const unsigned char *in, unsigned char *out,
        int length, const unsigned char *key, const int enc)
{
	SMS4_LONG len = length;

	while (len >= SMS4_BLOCK_SIZE) {
		SMS4_docipher((unsigned char *)in, out, key, enc);
		len -= SMS4_BLOCK_SIZE;
		in += SMS4_BLOCK_SIZE;
		out += SMS4_BLOCK_SIZE;
	}
	//pkcs5 , 7
	if (len) {
	    SMS4_docipher((unsigned char *)in, out, key, enc);
	}
	
}

