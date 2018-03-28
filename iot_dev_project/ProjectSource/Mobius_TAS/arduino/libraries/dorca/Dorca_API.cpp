#include "dorca30_api.h"
#include "dorca30_api_inside.h"
#include <stdlib.h>


int dorca3_cipher_decipher(int mode, int arg_type, unsigned char* Key, int key_length, unsigned char *iv, unsigned char *out, unsigned char *in, size_t len, int type,int last)
{
	int dorca3_opmode = 0;
	int dorca3_enc_dec = 0;
	int dorca3_keylength = 0;
	int dorca3_aes_aria = 0;
	int dorca3_two_frame = 0;
	if(32 == len)
	  dorca3_two_frame = 1;
	  
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
	
	#ifdef DEBUG_API
		printf("\r\n mode %d",mode);
		printf("\r\n arg_type %d",arg_type);
		if(NULL != Key) {
			printf("\r\n Key");
			printbyte(Key,key_length);
		}
		if(NULL != iv){
			printf("\r\n iv");
			printbyte(iv,16);
		}
		printf("\r\n in");
		printbyte(in,16);
		printf("\r\n len %d", len);
		printf("\r\n type %d", type);
		printf("\r\n last %d", last);
		
		
	#endif
	if(NULL != Key) {
			if(MODE_ECB == type) {	
				AES_ARIA_INIT(dorca3_keylength,dorca3_aes_aria,Key,dorca3_two_frame);
			} 
			else{
				if(NULL != iv)
					SET_IV(iv,dorca3_opmode,dorca3_keylength,dorca3_aes_aria,Key,dorca3_two_frame);
			}		
	}
	
	if(16 == len) {
		if( RG_ENC == dorca3_enc_dec)
			AES_ARIA_Encrypt(in,out);
		else
			AES_ARIA_Decrypt(in,out);	
	}
	
	else {
		if( RG_ENC == dorca3_enc_dec)
			AES_ARIA_Encrypt32(in,out);
		else
			AES_ARIA_Decrypt32(in,out);	

	}

	
	if(last){

		AES_ARIA_CLOSE();
		
		if(32 == len){
			Reset();

		}
	}

}



int wake_up()
{
	Dorca3_SPI_Init(1000*1000);
	SetZero_RG_SLEEP_TIMER();
	Dorca3_Close();
	return 0;
}
int check_sleep()
{
	return is_sleep();
}
#if 1
int ecdh_gen_pub_key(uint8_t* sk,point *p1)
{
	_ecdh_gen_pub_key(sk,p1);
	return 0;
}

int ecdh_gen_session_key(uint8_t* sk,point *p1, uint8_t *key,size_t* key_length)
{
	_ecdh_gen_session_key(sk,p1,key,key_length);
	return 0;	
}

int sha_256_perform(unsigned char *txdata, unsigned char *rxdata, long long ByteNo)
{
  STANDARD_SHA_MODE(txdata, rxdata,ByteNo);
	return 0;  
}

int  ecdsa_verify_signature(point *public_key, uint8_t *r,uint8_t *s,uint8_t *h  )
{
	 return _ecdsa_verify_signature(public_key, r, s, h);

}

int  ecdsa_gen_public_key(unsigned char *private_key, point *public_key)
{

	_ecdsa_gen_public_key(private_key, public_key);
	return 0;  	
}

int ecdsa_gen_signature(uint8_t *d, uint8_t *k, uint8_t *h, uint8_t *r, uint8_t *s)
{
	_ecdsa_gen_signature(d,k,h,r,s);
	return 0;  	
}


int rsa_pub_enc_2048(unsigned char * pub_key_n,unsigned char * pub_key_e,unsigned char * out, unsigned char *in, size_t len,int padding)
{
	_rsa_pub_enc_2048(pub_key_n,pub_key_e,out,in,len,padding);
}
int rsa_pub_dec_2048(unsigned char * priv_key,unsigned char * pub_key_n,unsigned char * out, unsigned char *in, size_t len,int padding)
{
	_rsa_pub_dec_2048(priv_key,pub_key_n,out,in,len,padding);
}

#endif
