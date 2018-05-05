#ifndef _SMS4_MODE_H
#define _SMS4_MODE_H

void SMS4_cbc_encrypt(const unsigned char *in, unsigned char *out,
	const unsigned long length, const unsigned char *key,
	unsigned char *ivec, const int enc);
void SMS4_ecb_encrypt(const unsigned char *in, unsigned char *out,
	int length, const unsigned char *key, const int enc);

#endif