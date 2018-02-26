#ifndef __DORCA
#define __DORCA

#include "stdafx.h"
#include "base64.h"

#define LAST -1
#define MAX_BUFF 256
#define CIPHER_BUFF_SIZE 32
#define DORCA_MAX_BUFF 16

class Dorca {
public:
	static Dorca * getInstance();

	void setEncryptType(int type, int keySize = 0);

	void setKey(std::string key); //TODO

	std::string encrypt(std::string msg);
	std::string decrypt(std::string msg);
	
private:
	static Dorca * Instance;
	pthread_mutex_t dorcaMutex; //write를 할 때 사용되는 Mutex

	unsigned char key[32];
	int cipher_type;
	int keySize;

	Dorca();
	~Dorca();
	void dorca_init();
};

#endif // !__DORCA