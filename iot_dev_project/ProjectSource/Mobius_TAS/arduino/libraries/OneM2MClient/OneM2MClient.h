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
    OneM2MClient.h - Library for oneM2M Client interacting to oneM2M server named Mobius
    Created by Ilyeup Ahn in KETI Korea, March 19, 2017.
    Released into the public domain.
*/

#ifndef ONEM2MCLIENT_H
#define ONEM2MCLIENT_H

#include "Arduino.h"

#include <WiFi101.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

const String CSE_ID = "Mobius";

typedef struct _resource_t { //리소스 구조체
  String ty;
  String to;
  String rn;
  int status;
} resource_t;

typedef struct _topic_t { //토픽 구조체
  String req;
  String resp;
  String noti;
  String noti_resp;
} topic_t;

class OneM2MClient
{
  public:
    OneM2MClient(String broker, uint16_t port, String _aeid); //broker IP, MQTT port, ae IE 설정
    void createAE(String rqi, int index, String api); //서버에 ae생성../rqi: request packet ID(rand) / index: resource's ae Index / api: app ID
    void createCnt(String rqi, int index); //서버에 container 생성
    void deleteSub(String rqi, int index); //서버에 subscribe 제거
    void createSub(String rqi, int index); //서버에 subscribe 생성
    void createCin(String rqi, String to, String value); //서버에 content instance 생성

    void response(char* body_buff);

    void setCallback(void (*callback1)(String topic, JsonObject& root), void (*callback2)(String topic, JsonObject& root)); //함수 포인터 전달

    void begin(); // 초기 wifi연결 프로세스

    void chkInitProvision();
	void chkInitProvision2();
    bool chkConnect(); //네트워크 연결여부 체크

	String getAeid();

    PubSubClient mqtt;
    resource_t resource[10];
	int resource_count;
    topic_t _topic;

  private:
    char _ssid[M2M_MAX_SSID_LEN];
    char _password[M2M_MAX_SSID_LEN];

    uint8_t _btnDownFlag;
    uint16_t _btnDownCount;
    uint8_t _provisoned;

    void printWiFiStatus();
    void buildResource();
    void initTopic();
    void request(String body_str);

	String AE_ID;
	String MOBIUS_MQTT_BROKER_IP;
	uint16_t MOBIUS_MQTT_PORT;
};

#endif // ONEM2MCLIENT_H
