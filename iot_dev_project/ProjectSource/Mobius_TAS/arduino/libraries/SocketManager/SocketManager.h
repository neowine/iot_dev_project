#ifndef __SOCKMNG
#define __SOCKMNG
#include <WiFi101.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>
#include <RTClib.h>

#define BUFF_SIZE 32

class SocketManager {
public:
	SocketManager();

	void setInfo(int port, String ctname, String ssid, String pw = "");
	void setNetwork(String ssid, String pw = "");

	void get_nCubeInfo();
	void connect();
	void chkConnect();

	bool readMsg(String* msg, bool timeChk = true);
	void sendMsg(String msg, bool needAck = false);

	void initTimeStamp();
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