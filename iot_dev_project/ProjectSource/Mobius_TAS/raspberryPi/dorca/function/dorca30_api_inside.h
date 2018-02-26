#ifndef DORCA30_INSIDE_API
#define DORCA30_INSIDE_API



	
void SET_IV(unsigned char *IV,int AES_OPMODE,int RG_128_256,int AES_ARIA,unsigned char *AES_ARIA_KEY);
int AES_ARIA_INIT(int RG_128_256,int AES_ARIA,unsigned char *AES_ARIA_KEY);
void AES_ARIA_CLOSE();
void AES_ARIA_Decrypt(unsigned char *pInput, unsigned char *pOutput);
void AES_ARIA_Encrypt(unsigned char *pInput, unsigned char *pOutput);

unsigned char STANDARD_SHA_MODE(unsigned char *txdata, unsigned char *rxdata, long long ByteNo);

void AES_ARIA_ECB_TEST_ETRI_MAIN();
void SHA_TEST_MAIN();

#endif //DORCA30_INSIDE_API