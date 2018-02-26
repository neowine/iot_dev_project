#include "DorcaClass.h"


using namespace std;

Dorca * Dorca::getInstance() {
	if (Instance == NULL)
		Instance = new Dorca;
	return Instance;
}

void Dorca::dorca_init() {
	RaspberryDorcaInit();
}

void Dorca::setEncryptType(int type, int keySize) {
	this->cipher_type = type;
	this->keySize = keySize;
}

void Dorca::setKey(string key) {
	int i, n;
	char tmp[3] = "00";

	n = key.size() / 2;
	for (i = 0; i < n; i++) {
		memcpy(tmp, &key[i * 2], 2);
		this->key[i] = (uint8_t)strtoul(tmp, NULL, 16);
	}
}

string Dorca::encrypt(string msg) {
	int length = 0;
	char enc[MAX_BUFF];
	memset(enc, 0, MAX_BUFF);

	for (int i = 0; i * DORCA_MAX_BUFF < msg.length(); i++) {
		unsigned char cstr[CIPHER_BUFF_SIZE];
		memset(cstr, '\0', CIPHER_BUFF_SIZE);
		strncpy((char*)cstr, msg.substr(i * DORCA_MAX_BUFF, DORCA_MAX_BUFF).c_str(), DORCA_MAX_BUFF);

		unsigned char buff_encrypt[CIPHER_BUFF_SIZE];
		memset(buff_encrypt, '\0', CIPHER_BUFF_SIZE);

		pthread_mutex_lock(&this->dorcaMutex);
		dorca3_cipher_decipher(RG_ENC, this->cipher_type, this->key, this->keySize, NULL, buff_encrypt, cstr, (size_t)DORCA_MAX_BUFF, MODE_ECB, LAST);
		pthread_mutex_unlock(&this->dorcaMutex);

		for (int j = i * DORCA_MAX_BUFF, k = 0; j < i * DORCA_MAX_BUFF + 16; j++, k++)
			enc[j] = buff_encrypt[k];

		length += DORCA_MAX_BUFF;
	}

	char _base64[MAX_BUFF];
	Base64::Encode(enc, length, _base64, MAX_BUFF);

	return _base64;
}

string Dorca::decrypt(string msg) {
	char dec[MAX_BUFF];
	Base64::Decode(msg.c_str(), msg.length(), dec, MAX_BUFF);

	string ret = "";
	int length = Base64::DecodedLength(msg);

	for (int i = 0; i * DORCA_MAX_BUFF < length; i++) {
		unsigned char buff_encrypt[CIPHER_BUFF_SIZE];
		memset(buff_encrypt, '\0', CIPHER_BUFF_SIZE);
		memcpy(buff_encrypt, &dec[i * DORCA_MAX_BUFF], DORCA_MAX_BUFF);

		unsigned char buff_decrypt[CIPHER_BUFF_SIZE];
		memset(buff_decrypt, '\0', CIPHER_BUFF_SIZE);
		
		pthread_mutex_lock(&this->dorcaMutex);
		dorca3_cipher_decipher(RG_DEC, this->cipher_type, this->key, this->keySize, NULL, buff_decrypt, buff_encrypt, (size_t)DORCA_MAX_BUFF, MODE_ECB, LAST);
		pthread_mutex_unlock(&this->dorcaMutex);

		ret.append((char*)buff_decrypt);
	}

	return ret;
}

Dorca::Dorca() {
	this->dorca_init();
	pthread_mutex_init(&this->dorcaMutex, NULL);
}

Dorca::~Dorca() {
	delete Instance;
}

Dorca* Dorca::Instance = NULL;