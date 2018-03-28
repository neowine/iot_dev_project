#ifndef DORCA30_API
#define DORCA30_API
#if 0


#if defined(ARDUINO) && ARDUINO >= 100

  #include "Arduino.h"

#else
  #include "WProgram.h"
#endif




#endif
#include <Arduino.h>

#include <SPI.h>


typedef unsigned char uint8_t;
//#include <stdint.h>
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
int wake_up();
void INT0();

int dorca3_cipher_decipher(int mode, int arg_type, unsigned char* Key, int key_length, unsigned char *iv, unsigned char *out, unsigned char *in, size_t len, int type,int last );
int check_sleep();
int ecdh_gen_pub_key(uint8_t* sk,point *p1);
int ecdh_gen_session_key(uint8_t* sk,point *p1, uint8_t *key,size_t* key_length);
int sha_256_perform(unsigned char *txdata, unsigned char *rxdata, long long ByteNo);
int ecdsa_verify_signature(point *public_key, uint8_t *r,uint8_t *s,uint8_t *h);
int ecdsa_gen_public_key(unsigned char *private_key, point *public_key);
int ecdsa_gen_signature(uint8_t *d, uint8_t *k, uint8_t *h, uint8_t *r, uint8_t *s);
int rsa_pub_enc_2048(unsigned char * pub_key_n,unsigned char * pub_key_e,unsigned char * out, unsigned char *in, size_t len,int padding);
int rsa_pub_dec_2048(unsigned char * priv_key,unsigned char * pub_key_n,unsigned char * out, unsigned char *in, size_t len,int padding);

void Dorca3_SPI_Init( int com_speed );
void Dorca3_Close();
void API_TEST_MAIN();
void TEST_AES();
unsigned char EE_WR_TEST_Main();


//void SetSerial(Serial *pSerial);
 #define LAST 1
 #define CS0 19
 #define CS1 18
// #define INT_0 5
#define INT_0 5
#define INT_1 10


 #define POWER 15

#endif //DORCA30_API
