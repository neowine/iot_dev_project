#include "SocketManager.h"
#include "dorca30_api.h"
static const char b64_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};

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
		//Serial.println("Connect WIFI success!");
		//return;

		String msg = "";
		while (WiFi.status() == WL_CONNECTED && msg != "hello") {
			this->get_nCubeInfo();
			Serial.println("msg");			
			Serial.print(msg);					
			Serial.println("nCube Connecting...  ");
			if (this->client.connect(this->address, this->port) >= 0) {
				Serial.println("Send Hello Packet...");
				this->sendMsg("hello", true);
				delay(1000);
				readMsg(&msg, false,1);
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

bool SocketManager::readMsg(String* msg, bool timeChk,int hello) {
	char buffer[512];
	String decodedMsg;
	unsigned char *pDecodedBase64;
	*msg = this->client.readString();
	Serial.println("readNsg");
	if (*msg == "") {
	//	Serial.println("return false");
		return false;
	}
	
	
	StaticJsonBuffer<200> jsonBuffer;
	JsonObject& json = jsonBuffer.parseObject(*msg);

	if (!json.success() || json["ctname"] != this->ctname + "in") {
		Serial.println("Json Parse Failed(Read)");
		Serial.print(*msg);
		String kk = json["ctname"];
		Serial.print(kk);
		*msg = "";
		return false;
	}
	String temp = json["con"];
	temp.toCharArray(buffer, temp.length()+1);
	pDecodedBase64 =b64_decode(buffer,temp.length());
	String str((char *)pDecodedBase64);
	Serial.println("\r\n Decoded Str");
	Serial.print(str);
	decodedMsg = decrypt((char *)pDecodedBase64);
	Serial.println("\r\n Decoded Str FINAL");
	Serial.print(decodedMsg);
	if(0 == hello)
		*msg = decodedMsg;
	else
		*msg = temp;
	Serial.println("msg");
	Serial.print(*msg);	
	return true;
	
	

	if (timeChk) {
		long long recvTimeStamp = stoll(temp.substring(temp.indexOf(":"), temp.indexOf(";")));

#if 0		
		if (recvTimeStamp <= this->timeStamp) {
			Serial.println("timeStamp warning... packet block!!");
			Serial.print("recvTime(second): ");
			Serial.println((int)(recvTimeStamp/1000));
			*msg = "";
			return false;
		}
#endif		
		this->timeStamp = recvTimeStamp;
	}


	
    Serial.println("READ MESSAGE!");
	Serial.print(*msg);
	*msg = temp;
    Serial.println("Parsed String");
	Serial.print(temp);	
	return true;
}

unsigned char * SocketManager::b64_decode_ex(const char *src, size_t len, size_t *decsize) 
{
	  int i = 0;
	  int j = 0;
	  int l = 0;
	  size_t size = 0;
	  unsigned char *dec = NULL;
	  unsigned char buf[3];
	  unsigned char tmp[4];
	
	  // alloc
	  dec = (unsigned char *) custom_malloc(1);
	  if (NULL == dec) { return NULL; }
	
	  // parse until end of source
	  while (len--) {
		// break if char is `=' or not base64 char
		if ('=' == src[j]) { break; }
		if (!(isalnum(src[j]) || '+' == src[j] || '/' == src[j])) { break; }
	
		// read up to 4 bytes at a time into `tmp'
		tmp[i++] = src[j++];
	
		// if 4 bytes read then decode into `buf'
		if (4 == i) {
		  // translate values in `tmp' from table
		  for (i = 0; i < 4; ++i) {
			// find translation char in `b64_table'
			for (l = 0; l < 64; ++l) {
			  if (tmp[i] == b64_table[l]) {
				tmp[i] = l;
				break;
			  }
			}
		  }
	
		  // decode
		  buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
		  buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
		  buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];
	
		  // write decoded buffer to `dec'
		  dec = (unsigned char *) custom_realloc(dec, size + 3);
		  if (dec != NULL){
			for (i = 0; i < 3; ++i) {
			  dec[size++] = buf[i];
			}
		  } else {
			return NULL;
		  }
	
		  // reset
		  i = 0;
		}
	  }
	
	  // remainder
	  if (i > 0) {
		// fill `tmp' with `\0' at most 4 times
		for (j = i; j < 4; ++j) {
		  tmp[j] = '\0';
		}
	
		// translate remainder
		for (j = 0; j < 4; ++j) {
			// find translation char in `b64_table'
			for (l = 0; l < 64; ++l) {
			  if (tmp[j] == b64_table[l]) {
				tmp[j] = l;
				break;
			  }
			}
		}
	
		// decode remainder
		buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
		buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
		buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];
	
		// write remainer decoded buffer to `dec'
		dec = (unsigned char *) custom_realloc(dec, size + (i - 1));
		if (dec != NULL){
		  for (j = 0; (j < i - 1); ++j) {
			dec[size++] = buf[j];
		  }
		} else {
		  return NULL;
		}
	  }
	
	  // Make sure we have enough space to add '\0' character at end.
	  dec = (unsigned char *) custom_realloc(dec, size + 1);
	  if (dec != NULL){
		dec[size] = '\0';
	  } else {
		return NULL;
	  }
	
	  // Return back the size of decoded string if demanded.
	  if (decsize != NULL) {
		*decsize = size;
	  }
	
	  return dec;
}


String SocketManager::decrypt(char * msg) {
	unsigned char dec[MAX_BUFF];
	unsigned char key[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f}; 
	char *pDecrypt = NULL;
	unsigned char buff_encrypt[CIPHER_BUFF_SIZE];
	memset(buff_encrypt, 0, CIPHER_BUFF_SIZE);
	memcpy(buff_encrypt, msg, DORCA_MAX_BUFF);
	
	unsigned char buff_decrypt[CIPHER_BUFF_SIZE];
	memset(buff_decrypt, 0, CIPHER_BUFF_SIZE);

	//int length = Base64::DecodedLength(msg);

	//for (int i = 0; i * DORCA_MAX_BUFF < length; i++) {
	int i = 0;


		
	//pthread_mutex_lock(&this->dorcaMutex);
	Dorca3_SPI_Init(1000*1000);
	dorca3_cipher_decipher(RG_DEC, 1, key, 32, NULL, buff_decrypt, buff_encrypt, (size_t)DORCA_MAX_BUFF, MODE_ECB, LAST);
	Dorca3_Close();
	//pthread_mutex_unlock(&this->dorcaMutex);

		//ret.append((char*)buff_decrypt);
	pDecrypt = (char *)buff_decrypt;
	String temp(pDecrypt);
	ret = temp;
	Serial.println("DECRYPTED ");
	Serial.print(ret);
	return ret;

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
#if 0		
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
#endif		
		break;
	}

	if (this->timeStamp == 0)
		this->timeStamp = curTime.unixtime();

//	Serial.println("time set complete!");
//	Serial.print("now time(second): ");
//	Serial.println(this->curTime.unixtime());
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
