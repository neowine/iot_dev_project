#include "dorca30_api.h"
#include "dorca30_api_inside.h"
#include <stdlib.h>


int dorca3_cipher_decipher(int mode, int arg_type, unsigned char* Key, int key_length, unsigned char *iv, unsigned char *out, unsigned char *in, size_t len, int type ,int last)
{
	int dorca3_opmode = 0;
	int dorca3_enc_dec = 0;
	int dorca3_keylength = 0;
	int dorca3_aes_aria = 0;


	dorca3_opmode = type;
	dorca3_enc_dec = mode;
	if( 1 == arg_type)
		dorca3_aes_aria = RG_AES;
	else
		dorca3_aes_aria = RG_ARIA;
	if(32 == key_length)
		dorca3_keylength = RG_256;
	else
		dorca3_keylength = RG_128;
	
	if(NULL != Key) {
			if(MODE_ECB == type) {	
				AES_ARIA_INIT(dorca3_keylength,dorca3_aes_aria,Key);
			} 
			else{
				if(NULL != iv)
					SET_IV(iv,dorca3_opmode,dorca3_keylength,dorca3_aes_aria,Key);
			}		
	}
	
	if( RG_ENC == dorca3_enc_dec)
		AES_ARIA_Encrypt(in,out);
	else
		AES_ARIA_Decrypt(in,out);	

	if(last)
		AES_ARIA_CLOSE();

}
int ecdh_gen_pub_key(uint8_t* sk,point *p1)
{
	_ecdh_gen_pub_key(sk,p1);
}

int ecdh_gen_session_key(uint8_t* sk,point *p1, uint8_t *key,size_t* key_length)
{
	_ecdh_gen_session_key(sk,p1,key,key_length);
}

int sha_256_perform(unsigned char *txdata, unsigned char *rxdata, long long ByteNo)
{
  STANDARD_SHA_MODE(txdata, rxdata,ByteNo);
}

int  ecdsa_verify_signature(point *public_key, uint8_t *r,uint8_t *s,uint8_t *h  )
{
	 return _ecdsa_verify_signature(public_key, r, s, h);
}

int  ecdsa_gen_public_key(unsigned char *private_key, point *public_key)
{
	_ecdsa_gen_public_key(private_key, public_key);
}

int ecdsa_gen_signature(uint8_t *d, uint8_t *k, uint8_t *h, uint8_t *r, uint8_t *s)
{
	_ecdsa_gen_signature(d,k,h,r,s);
}