#ifndef DORCA30_API
#define DORCA30_API
#include <stdint.h>
typedef unsigned int size_t; 
typedef enum
{
	MODE_ECB = 0,
	MODE_CBC,
	MODE_OFB,
	MODE_CTR,
	MODE_CFB
}RG_AES_OPMODE;
	
typedef enum
{
	RG_256 = 0,
	RG_128
}RG_MODE;
typedef enum
{
	RG_ARIA = 0,
	RG_AES
}RG_ALGO;
typedef enum
{
	RG_ENC = 0,
	RG_DEC
}RG_ENCDEC;


typedef enum{
	MODE256 = 1,
	MODE128 = 0
}KEY_SAVE_MODE;

typedef struct _point
{
uint8_t x[32];
uint8_t y[32];
}point;
int dorca3_cipher_decipher(int mode, int arg_type, unsigned char* Key, int key_length, unsigned char *iv, unsigned char *out, unsigned char *in, size_t len, int type,int last );
int ecdh_gen_pub_key(uint8_t* sk,point *p1);
int ecdh_gen_session_key(uint8_t* sk,point *p1, uint8_t *key,size_t* key_length);
int sha_256_perform(unsigned char *txdata, unsigned char *rxdata, long long ByteNo);
int ecdsa_verify_signature(point *public_key, uint8_t *r,uint8_t *s,uint8_t *h  );
int ecdsa_gen_public_key(unsigned char *private_key, point *public_key);
int ecdsa_gen_signature(uint8_t *d, uint8_t *k, uint8_t *h, uint8_t *r, uint8_t *s);
#endif //DORCA30_API