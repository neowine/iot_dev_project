/**
 * Copyright (c) 2017, OCEAN
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
    OneM2MClient.cpp - Library for oneM2M Client interacting to oneM2M server named Mobius
    Created by Ilyeup Ahn in KETI Korea, March 19, 2017.
    Released into the public domain.
*/

#include "OneM2MClient.h"

#include <FlashAsEEPROM.h>

/************************* WiFI Setup *****************************/
#define WINC_CS   8
#define WINC_IRQ  7
#define WINC_RST  4
#define WINC_EN   2

#define LEDPIN 13

#define BTNPIN A1


void (*_mqtt_resp_callback)(String topic, JsonObject& root);
void (*_mqtt_noti_callback)(String topic, JsonObject& root);


void mqttMessageHandler(char* topic_in, byte* payload, unsigned int length) {
	String topic = String(topic_in);

	if (topic.substring(8,12) == "resp") {
		Serial.println("Receive published data");

		char resp_message[length];
		memset((char*)resp_message, '\0', length);

		Serial.print("<----  ");
		Serial.println(length);
		for (unsigned int i = 0; i < length; i++) {
			resp_message[i] = (char)payload[i];
			Serial.print(resp_message[i]);
		}
		Serial.println("\n\r<----  ");

		//StaticJsonBuffer<MQTT_MAX_PACKET_SIZE> jsonBuffer;
		DynamicJsonBuffer jsonBuffer(MQTT_MAX_PACKET_SIZE);
		JsonObject& resp_root = jsonBuffer.parseObject(resp_message);

		if (!resp_root.success()) {
			Serial.println(F("parseObject() failed"));
			return;
		}

		if(_mqtt_resp_callback != NULL) {
			_mqtt_resp_callback(topic, resp_root);
		}
	}
	else if(topic.substring(8,11) == "req") {
		Serial.println("Notification");

		char req_message[length];
		memset((char*)req_message, '\0', length);

		Serial.print("<----  ");
		Serial.println(length);
		for (unsigned int i = 0; i < length; i++) {
			req_message[i] = (char)payload[i];
			Serial.print(req_message[i]);
		}
		Serial.println("\n\r<----  ");

		//StaticJsonBuffer<MQTT_MAX_PACKET_SIZE> jsonBuffer;
		DynamicJsonBuffer jsonBuffer(MQTT_MAX_PACKET_SIZE);

		JsonObject& req_root = jsonBuffer.parseObject(req_message);

		if (!req_root.success()) {
			Serial.println(F("parseObject() failed"));
			return;
		}

		if(_mqtt_noti_callback != NULL) {
			_mqtt_noti_callback(topic, req_root);
		}
	}
}



OneM2MClient::OneM2MClient(String broker, uint16_t port, String _aeid)
{
  AE_ID = _aeid;
  MOBIUS_MQTT_BROKER_IP = broker;
  MOBIUS_MQTT_PORT = port;

  _btnDownFlag = 0;
  _btnDownCount = 0;

  _mqtt_resp_callback = NULL;
  _mqtt_noti_callback = NULL;

  initTopic();
}

void OneM2MClient::createAE(String rqi, int index, String api)
{
  String body_str =
    "{"
      "\"op\":\"1\","
      "\"to\":\"" + resource[index].to + "?rcn=0\","
      "\"fr\":\"" + AE_ID + "\","
      "\"rqi\":\"" + rqi + "\","
      "\"ty\":\"" + resource[index].ty + "\","
      "\"pc\":{"
        "\"m2m:ae\":{"
         "\"rn\":\"" + resource[index].rn + "\","
         "\"api\":\"" + api + "\","
         "\"rr\":\"true\""
	    "}"
      "}"
    "}";

  request(body_str);
}

void OneM2MClient::createCnt(String rqi, int index)
{
  String body_str =
    "{"
      "\"op\":\"1\","
      "\"to\":\"" + resource[index].to + "?rcn=0\","
      "\"fr\":\"" + AE_ID + "\","
      "\"rqi\":\"" + rqi + "\","
      "\"ty\":\"" + resource[index].ty + "\","
      "\"pc\":{"
        "\"m2m:cnt\":{"
          "\"rn\":\"" + resource[index].rn + "\""
        "}"
      "}"
    "}";

  request(body_str);
}

void OneM2MClient::deleteSub(String rqi, int index)
{
  String body_str =
    "{"
      "\"op\":\"4\","
      "\"to\":\"" + resource[index].to + "/" + resource[index].rn + "\","
      "\"fr\":\"" + AE_ID + "\","
      "\"rqi\":\"" + rqi + "\","
      "\"pc\":{"
      "}"
    "}";

  request(body_str);
}

void OneM2MClient::createSub(String rqi, int index)
{
  String body_str =
    "{"
      "\"op\":\"1\","
      "\"to\":\"" + resource[index].to + "?rcn=0\","
      "\"fr\":\"" + AE_ID + "\","
      "\"rqi\":\"" + rqi + "\","
      "\"ty\":\"" + resource[index].ty + "\","
      "\"pc\":{"
        "\"m2m:sub\":{"
          "\"rn\":\"" + resource[index].rn + "\","
          "\"enc\":{"
            "\"net\":[3]},"
          "\"nu\":"
            "[\"mqtt://" + String(MOBIUS_MQTT_BROKER_IP)  + ":1883/" + AE_ID + "?ct=json&rcn=9\"],"
          "\"nct\":\"2\""
        "}"
      "}"
    "}";

  request(body_str);
}

void OneM2MClient::createCin(String rqi, String to, String value)
{
  String body_str =
    "{"
      "\"op\":\"1\","
      "\"to\":\"" + to + "\","
      "\"fr\":\"" + AE_ID + "\","
      "\"rqi\":\"" + rqi + "\","
      "\"ty\":\"4\","
      "\"pc\":{"
        "\"m2m:cin\":{"
          "\"con\":" + value + ""
        "}"
      "}"
    "}";

  request(body_str);
}

void OneM2MClient::request(String body_str)
{
  char req_topic[_topic.req.length() + 1];
  _topic.req.toCharArray(req_topic, _topic.req.length() + 1);

  char body_buff[MQTT_MAX_PACKET_SIZE];
  memset(body_buff, 0, MQTT_MAX_PACKET_SIZE);

  body_str.toCharArray(body_buff, body_str.length() + 1);
  Serial.println();
  Serial.println(body_buff);

  if (!mqtt.publish(req_topic, body_buff)) {
    Serial.println(F("REQUEST Failed"));
  } else {
    Serial.println(F("REQUEST OK!"));
  }
}

void OneM2MClient::response(char* body_buff)
{
  char noti_resp_topic[_topic.noti_resp.length() + 1];
  _topic.noti_resp.toCharArray(noti_resp_topic, _topic.noti_resp.length() + 1);

  Serial.println("");
  Serial.println(noti_resp_topic);

  if (!mqtt.publish(noti_resp_topic, body_buff)) {
    Serial.println(F("RESPONSE Failed"));
  } else {
    Serial.println(F("RESPONSE OK!"));
  }
}

void OneM2MClient::setCallback(void (*callback1)(String topic, JsonObject& root), void (*callback2)(String topic, JsonObject& root)) {
  _mqtt_resp_callback = callback1;
  _mqtt_noti_callback = callback2;
}


void OneM2MClient::initTopic() {
  _topic.req        = "/oneM2M/req/" + AE_ID + "/Mobius/json";
  _topic.resp       = "/oneM2M/resp/" + AE_ID + "/Mobius/json";

  _topic.noti       = "/oneM2M/req/Mobius/" + AE_ID + "/json";
  _topic.noti_resp  = "/oneM2M/resp/Mobius/" + AE_ID + "/json";
}

void OneM2MClient::printWiFiStatus() {
  // print the SSID of the network you're attached to:
  Serial.print("SSID: ");
  Serial.println(WiFi.SSID());
  //  Serial.print("PASSWORD: ");
  //  Serial.println(WiFi.PASSWORD());

  // If value of data first byte in the EEPROM is 1 it means that this device was provisioned
  if (EEPROM.read(0) == 0) { // when connect other AP after finish provisioning
    Serial.println("EEPROM is empty, writing some example data:");
    Serial.print("->");
    EEPROM.write(0, 1);
    Serial.print(" ");
    Serial.print(1);
    Serial.println();

    Serial.print("->");
    for (int i = 0; i < M2M_MAX_SSID_LEN; i++) {
      EEPROM.write(i + 1, WiFi._ssid[i]);
      Serial.print(" ");
      Serial.print(WiFi._ssid[i]);
    }
    Serial.println();

    Serial.print("->");
    for (int i = 0; i < M2M_MAX_SSID_LEN; i++) {
      EEPROM.write(M2M_MAX_SSID_LEN + i + 1, WiFi._password[i]);
      Serial.print(" ");
      Serial.print(WiFi._password[i]);
    }
    Serial.println();

    // commit() saves all the changes to EEPROM, it must be called
    // every time the content of virtual EEPROM is changed to make
    // the change permanent.
    // This operation burns Flash write cycles and should not be
    // done too often. See readme for details:
    // https://github.com/cmaglie/FlashStorage#limited-number-of-writes
    EEPROM.commit();
    Serial.println("Done!");

    Serial.print("After commit, calling isValid() returns ");
    Serial.println(EEPROM.isValid());
  }
  else {
    Serial.println("EEPROM has been written.");
    Serial.println("Here is the content of the first 20 bytes:");

    Serial.print("->");
    Serial.print(" ");
    Serial.print(EEPROM.read(0));
    Serial.println();

    Serial.print("->");
    for (int i = 0; i < M2M_MAX_SSID_LEN; i++) {
      Serial.print(" ");
      Serial.print(EEPROM.read(i + 1));
    }
    Serial.println();

    Serial.print("->");
    for (int i = 0; i < M2M_MAX_SSID_LEN; i++) {
      Serial.print(" ");
      Serial.print(EEPROM.read(M2M_MAX_SSID_LEN + i + 1));
    }
    Serial.println();
  }

  // print your WiFi shield's IP address:
  IPAddress ip = WiFi.localIP();
  Serial.print("IP Address: ");
  Serial.println(ip);

  // print the received signal strength:
  long rssi = WiFi.RSSI();
  Serial.print("signal strength (RSSI): ");
  Serial.print(rssi);
  Serial.println(" dBm");

  digitalWrite(LEDPIN, LOW);
}

void OneM2MClient::begin()
{
  pinMode(LEDPIN, OUTPUT);

  pinMode(BTNPIN, INPUT_PULLUP);

  // begin WiFi
  WiFi.setPins(WINC_CS, WINC_IRQ, WINC_RST, WINC_EN);

  // check for the presence of the shield:
  if (WiFi.status() == WL_NO_SHIELD) {
    Serial.println("WiFi shield not present");
    // don't continue:
    while (true);
  }

  Serial.println("WiFi shield present");

  // If value of data first byte in the EEPROM is 1 it means that this device was provisioned
  if (EEPROM.read(0) == 0) { // Enter provision mode
	// after connect to default AP
	WiFi.begin("gbsmfather", "qwertyuiop");
    delay(1000);
	if (WiFi.status() != WL_CONNECTED) {
		// Start in provisioning mode:
		//  1) This will try to connect to a previously associated access point.
		//  2) If this fails, an access point named "wifi101-XXXX" will be created, where XXXX
		//     is the last 4 digits of the boards MAC address. Once you are connected to the access point,
		//     you can configure an SSID and password by visiting http://wifi101/
		WiFi.beginProvision2();
		
		bool mdnsname_view_cnt = true;

		while (WiFi.status() != WL_CONNECTED) {
		  // wait while not connected

		  //Created access point name and Server domain name shows only once
		  if (mdnsname_view_cnt) {
			byte mac[6];
			WiFi.macAddress(mac);
			Serial.print("Accesse point named 'wifi101-");
			Serial.print(mac[1], HEX);
			Serial.print(mac[0], HEX);
			Serial.println("' is created");
			Serial.print("Server listening at 'http://");
			Serial.print("wifi101");
			Serial.println(".local/'");
			mdnsname_view_cnt = false;
		  }

		  // blink the led to show an unconnected status
		  digitalWrite(LEDPIN, HIGH);
		  delay(100);
		  digitalWrite(LEDPIN, LOW);
		  delay(100);
		}
    }
  }
  else { // already provisioned
    // just connect AP previous connected

    // get connecting info to AP from eeprom
    for (int i = 0; i < M2M_MAX_SSID_LEN; i++) {
      _ssid[i] = EEPROM.read(i + 1);
    }

    for (int i = 0; i < M2M_MAX_SSID_LEN; i++) {
      _password[i] = EEPROM.read(M2M_MAX_SSID_LEN + i + 1);
    }

    WiFi.begin(_ssid, _password);
    delay(500);
//	while (WiFi.status() != WL_CONNECTED) {
//   // blink the led to show an unconnected status
//      digitalWrite(LEDPIN, HIGH);
//      delay(1000);
//      digitalWrite(LEDPIN, LOW);
//      delay(1000);
//	  WiFi.begin();
//    }
  }

  Serial.println("WiFi Connected. It's Information is...");
  printWiFiStatus();

  // begin MQTT
  WiFiClient wifiClient;
  PubSubClient _mqtt(wifiClient);
  mqtt = _mqtt;

  char ip[16];
  MOBIUS_MQTT_BROKER_IP.toCharArray(ip, 16);
  mqtt.setServer(ip, MOBIUS_MQTT_PORT);
}

void OneM2MClient::chkInitProvision() {
  if (digitalRead(A1) == LOW) {
    _btnDownCount++;
	Serial.print(">");
    if (_btnDownCount > 65000) {
      _btnDownCount = 65000;
      _btnDownFlag = 2;

      digitalWrite(LEDPIN, HIGH);
    }
    else {
      _btnDownFlag = 1;
    }
  }
  else if ((digitalRead(A1) == HIGH) && (_btnDownFlag == 1)) {
    _btnDownFlag = 0;
    _btnDownCount = 0;

    Serial.println("EEPROM has been written.");
    Serial.println("Here is the content of the first 67 bytes:");

    Serial.print("->");
    Serial.print(" ");
    Serial.print(EEPROM.read(0));
    Serial.println();

    Serial.print("->");
    for (int i = 0; i < M2M_MAX_SSID_LEN; i++) {
      Serial.print(" ");
      Serial.print((char)EEPROM.read(i + 1));
    }
    Serial.println();

    Serial.print("->");
    for (int i = 0; i < M2M_MAX_SSID_LEN; i++) {
      Serial.print(" ");
      Serial.print((char)EEPROM.read(M2M_MAX_SSID_LEN + i + 1));
    }
    Serial.println();
  }
  else if ((digitalRead(A1) == HIGH) && (_btnDownFlag == 2)) {
    _btnDownFlag = 0;
    _btnDownCount = 0;

    EEPROM.write(0, 0);
    EEPROM.commit();

    Serial.println("Go to provisioning mode ... ");

    NVIC_SystemReset();      // processor software reset
  }
  else {
    _btnDownFlag = 0;
    _btnDownCount = 0;
  }
}

void OneM2MClient::chkInitProvision2() {
  if (digitalRead(A1) == LOW) {
    _btnDownCount++;
	Serial.print(">");
    if (_btnDownCount > 6) {
      _btnDownCount = 6;
      _btnDownFlag = 2;

      digitalWrite(LEDPIN, HIGH);
    }
    else {
      _btnDownFlag = 1;
    }
  }
  else if ((digitalRead(A1) == HIGH) && (_btnDownFlag == 1)) {
    _btnDownFlag = 0;
    _btnDownCount = 0;

    Serial.println("EEPROM has been written.");
    Serial.println("Here is the content of the first 67 bytes:");

    Serial.print("->");
    Serial.print(" ");
    Serial.print(EEPROM.read(0));
    Serial.println();

    Serial.print("->");
    for (int i = 0; i < M2M_MAX_SSID_LEN; i++) {
      Serial.print(" ");
      Serial.print((char)EEPROM.read(i + 1));
    }
    Serial.println();

    Serial.print("->");
    for (int i = 0; i < M2M_MAX_SSID_LEN; i++) {
      Serial.print(" ");
      Serial.print((char)EEPROM.read(M2M_MAX_SSID_LEN + i + 1));
    }
    Serial.println();
  }
  else if ((digitalRead(A1) == HIGH) && (_btnDownFlag == 2)) {
    _btnDownFlag = 0;
    _btnDownCount = 0;

    EEPROM.write(0, 0);
    EEPROM.commit();

    Serial.println("Go to provisioning mode ... ");

    NVIC_SystemReset();      // processor software reset
  }
  else {
    _btnDownFlag = 0;
    _btnDownCount = 0;
  }
}

String OneM2MClient::getAeid() {
  return AE_ID;
}

bool OneM2MClient::chkConnect() {
  if (WiFi.status() == WL_CONNECTED) {
    if (mqtt.connected()) { // Stop if already connected.
      mqtt.loop();
      return 1;
    }

    char resp_topic[_topic.resp.length()+1];
    char noti_topic[_topic.noti.length()+1];
    _topic.resp.toCharArray(resp_topic, _topic.resp.length()+1);
    _topic.noti.toCharArray(noti_topic, _topic.noti.length()+1);

    while (!mqtt.connected()) {
      Serial.println();
      Serial.print("Attempting MQTT connection...");
      // Attempt to connect
      if (mqtt.connect("")) {
        Serial.println("connected");

        mqtt.setCallback(mqttMessageHandler);

        if (mqtt.subscribe(resp_topic)) {
          Serial.println(_topic.resp + " Successfully subscribed");
        }

        if (mqtt.subscribe(noti_topic)) {
          Serial.println(_topic.noti + " Successfully subscribed");
        }
      }
      else {
        Serial.print("failed, rc=");
        Serial.print(mqtt.state());
        Serial.println(" try again in 5 seconds");

        // Wait 5 seconds before retrying
        delay(5000);
      }
    }

    return 1;
  }

  WiFi.begin();

//  Serial.println("WiFi Connected. It's Information is...");
//  printWiFiStatus();

  return 0;
}
