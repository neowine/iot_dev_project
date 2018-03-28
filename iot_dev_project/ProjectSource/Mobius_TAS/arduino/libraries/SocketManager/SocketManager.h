#ifndef __SOCKMNG
#define __SOCKMNG
#include <WiFi101.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>
#include <RTClib.h>

#define BUFF_SIZE 32
#define LAST -1
#define MAX_BUFF 256
#define CIPHER_BUFF_SIZE 32
#define DORCA_MAX_BUFF 16
class SocketManager {
public:
	String ret;
	
	SocketManager();

	void setInfo(int port, String ctname, String ssid, String pw = "");
	void setNetwork(String ssid, String pw = "");

	void get_nCubeInfo();
	void connect();
	void chkConnect();

	bool readMsg(String* msg, bool timeChk = true,int hello = 1);
	void sendMsg(String msg, bool needAck = false);

	
	String decrypt(char * msg);

	void initTimeStamp();
	unsigned char * b64_decode_ex(const char *src, size_t len, size_t *decsize);
	unsigned char *b64_decode(const char *src, size_t len){
	
	  return b64_decode_ex(src, len, NULL);
	}	
	
	unsigned char buffer[512];
	
	void* custom_malloc(size_t size){
		return buffer;
	}
	
	void* custom_realloc(void* ptr, size_t size){
		return buffer;
	}

private:
	WiFiClient client;
	String ssid;
	String pw;
	String ctname;

	IPAddress address;
	int port;
	long long timeStamp;
	DateTime curTime;
};

#endif
