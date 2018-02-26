#include "SocketManager.h"

long long stoll(String str);

SocketManager::SocketManager() {
	WiFi.setPins(8, 7, 4, 2);
	this->timeStamp = 0;
}

void SocketManager::setInfo(int port, String ctname, String ssid, String pw) {
	if (WiFi.status() == WL_NO_SHIELD) {
		Serial.println("WiFi shield no present");
		while (true);
	}

	this->ssid = ssid;
	this->pw = pw;
	this->ctname = ctname;
	this->port = port;
}

void SocketManager::setNetwork(String ssid, String pw) {
	this->ssid = ssid;
	this->pw = pw;
}

void SocketManager::get_nCubeInfo() {
	WiFiUDP udp;
	char buff[BUFF_SIZE];
	String recvData;

	Serial.println("Try get nCube IP addr...");
	udp.begin(this->port);
	while (true) {
		int packetSize = udp.parsePacket();
		if (!packetSize) {
			delay(2000);
			continue;
		}

		for (int i = 0; i < BUFF_SIZE; ++i)
			buff[i] = 0;
		udp.read(buff, BUFF_SIZE - 1);
		recvData = buff;
		
		if (!recvData.startsWith("nCube"))
			continue;

		this->address = udp.remoteIP();
		Serial.println("Get nCube IP success!!!");
		break;
	}
	
	udp.stop();
}

void SocketManager::connect() {
	while (WiFi.status() != WL_CONNECTED || !this->client.connected()) {
		if (WiFi.status() != WL_CONNECTED) {
			Serial.print("Attempting connect to Network... SSID: ");
			Serial.println(this->ssid);
			WiFi.begin(this->ssid, this->pw);
			delay(5000);
		}

		String msg = "";
		while (WiFi.status() == WL_CONNECTED && msg != "hello") {
			this->get_nCubeInfo();
			Serial.println("nCube Connecting...  ");
			if (this->client.connect(this->address, this->port) >= 0) {
				Serial.println("Send Hello Packet...");
				this->sendMsg("hello", true);
				delay(1000);
				readMsg(&msg, false);
			}
			else
				Serial.println("connect fail! retry...");
		}
	}	
	Serial.println("Connect WIFI success!");
}

void SocketManager::chkConnect() {
	while(!this->client.connected())
		this->connect();
}

bool SocketManager::readMsg(String* msg, bool timeChk) {
	*msg = this->client.readString();

	if (*msg == "")
		return false;

	StaticJsonBuffer<200> jsonBuffer;
	JsonObject& json = jsonBuffer.parseObject(*msg);

	if (!json.success() || json["ctname"] != this->ctname + "in") {
		Serial.println("Json Parse Failed(Read)");
		Serial.println(*msg);
		*msg = "";
		return false;
	}
	String temp = json["con"];

	if (timeChk) {
		long long recvTimeStamp = stoll(temp.substring(temp.indexOf(":"), temp.indexOf(";")));

		if (recvTimeStamp <= this->timeStamp) {
			Serial.println("timeStamp warning... packet block!!");
			Serial.print("recvTime(second): ");
			Serial.println((int)(recvTimeStamp/1000));
			*msg = "";
			return false;
		}
		this->timeStamp = recvTimeStamp;
	}

	*msg = temp;
	return true;
}

void SocketManager::sendMsg(String msg, bool needAck) {
	StaticJsonBuffer<200> jsonBuffer;
	JsonObject& json = jsonBuffer.createObject();
	if(needAck)
		json["ctname"] = this->ctname + "in";
	else {
		json["ctname"] = this->ctname + "out";
		msg += ":" + String(this->curTime.unixtime()) + "000;";
	}
	json["con"] = msg;

	msg = "";
	json.printTo(msg);
	this->client.write(msg.c_str(), msg.length());
}

void SocketManager::initTimeStamp() {
	String msg = "";
	long long time;

	while (true) {
		this->chkConnect();
		Serial.println("time request...");
		this->sendMsg("timeRequest", true);
		delay(1000);
		this->readMsg(&msg, false);
		time = stoll(msg);
		if (time <=0) {
			Serial.println("getTime fail");
			continue;
		}
		this->curTime = DateTime((int)(time/1000));
		break;
	}

	if (this->timeStamp == 0)
		this->timeStamp = curTime.unixtime();

	Serial.println("time set complete!");
	Serial.print("now time(second): ");
	Serial.println(this->curTime.unixtime());
}

long long stoll(String str) {
	long long temp = 0;
	for (int i = 0; i < str.length(); i++) {
		if (str.c_str()[i] < '0' || str.c_str()[i] > '9') {
			Serial.println("cannot parse to long long");
			return -1;
		}
		temp *= 10;
		temp += (str.c_str()[i] - '0');
	}
	return temp;
}