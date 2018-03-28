#ifndef DORCA30_INSIDE_API
#define DORCA30_INSIDE_API



void SetZero_RG_SLEEP_TIMER();
int is_sleep();	
void Reset();
void SET_IV(unsigned char *IV,int AES_OPMODE,int RG_128_256,int AES_ARIA,unsigned char *AES_ARIA_KEY,int TWO_FRAME);
int AES_ARIA_INIT(int RG_128_256,int AES_ARIA,unsigned char *AES_ARIA_KEY,int TWO_FRAME);
void AES_ARIA_CLOSE();
void AES_ARIA_Decrypt(unsigned char *pInput, unsigned char *pOutput);
void AES_ARIA_Encrypt(unsigned char *pInput, unsigned char *pOutput);

void AES_ARIA_Decrypt32(unsigned char *pInput, unsigned char *pOutput);
void AES_ARIA_Encrypt32(unsigned char *pInput, unsigned char *pOutput);
unsigned char STANDARD_SHA_MODE(unsigned char *txdata, unsigned char *rxdata, long long ByteNo);

void AES_ARIA_ECB_TEST_ETRI_MAIN();
void SHA_TEST_MAIN();
int _ecdh_gen_pub_key(uint8_t* sk,point *p1);
int _ecdh_gen_session_key(uint8_t* sk,point *p1, uint8_t *key,size_t* key_length);
void _ecdsa_gen_signature(uint8_t *d, uint8_t *k, uint8_t *h, uint8_t *r, uint8_t *s);
int _ecdsa_verify_signature(point *public_key, uint8_t *r,uint8_t *s,uint8_t *h );
void _ecdsa_gen_public_key(unsigned char *private_key, point *public_key);
int ecdh_gen_session_key(uint8_t* sk,point *p1, uint8_t *key,size_t* key_length);
int ecdh_gen_pub_key(uint8_t* sk,point *p1);
int  ecdsa_gen_public_key(unsigned char *private_key, point *public_key);
int ecdsa_gen_signature(uint8_t *d, uint8_t *k, uint8_t *h, uint8_t *r, uint8_t *s);
int  ecdsa_verify_signature(point *public_key, uint8_t *r,uint8_t *s,uint8_t *h  );
int sha_256_perform(unsigned char *txdata, unsigned char *rxdata, long long ByteNo);
int _rsa_pub_enc_2048(unsigned char * pub_key_n,unsigned char * pub_key_e,unsigned char * out, unsigned char *in, size_t len,int padding);
int _rsa_pub_dec_2048(unsigned char * priv_key,unsigned char * pub_key_n,unsigned char * out, unsigned char *in, size_t len,int padding);



#endif //DORCA30_INSIDE_API
