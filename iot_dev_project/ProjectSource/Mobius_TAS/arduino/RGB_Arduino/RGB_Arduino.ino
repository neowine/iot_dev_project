/*
 Name:    RGB_Arduino.ino
 Created: 2018-02-09 오전 9:05:48
 Author:  toddlf95
*/
#include <RTClib.h>
#include <WiFi101.h>
#include <SocketManager.h>

///////////////////////////////////////////need Setting
#define LED_R 10
#define LED_G 9
#define LED_B 6

#define TAS_PORT 3105
#define CT_NAME "arduino-"

#define SSID "HSSon-Labtop"
#define PW "Documents"

#define SW_PIN 11
///////////////////////////////////////////////end

SocketManager sockMNG;
int oldTime; //ms
String msg;

void led(String msg);
void sw();

const int sendTimeInterval = 1000; //ms
// the setup function runs once when you press reset or power the board
void setup() {
  Serial.begin(115200);
  delay(3000);
  //while (!Serial); ////for TEST

  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);
  pinMode(SW_PIN, INPUT_PULLDOWN);

  digitalWrite(LED_R, LOW);
  digitalWrite(LED_G, LOW);
  digitalWrite(LED_B, LOW);

  //init setting
  Serial.println("WiFi Set...");
  sockMNG.setInfo(TAS_PORT, CT_NAME, SSID, PW);
  Serial.println("try connect");

  delay(3000);
  sockMNG.connect();
  oldTime = 0;

  Serial.println("connect complete!");
  //init end

  digitalWrite(LED_R, HIGH);
  digitalWrite(LED_G, HIGH);
  digitalWrite(LED_B, HIGH);
}

// the loop function runs over and over again until power down or reset
void loop() {
  sockMNG.chkConnect();
  sockMNG.initTimeStamp();

  if (millis() - oldTime > sendTimeInterval) {
    oldTime = millis();
    sw();
  }
  if (sockMNG.readMsg(&msg)) {
    int index = msg.indexOf('_');
    
    if (msg.substring(0, index) == "LED")
      led(msg.substring(index + 1));
    else
      Serial.println("Wrong Container: " + msg.substring(0, index));
  }
}

void led(String msg) {
  int index = msg.indexOf(' ');
  int curPIN;

  switch (msg[0]) {
  case 'R':
    curPIN = LED_R;
    Serial.println("LED_RED");
    break;
  case 'G':
    curPIN = LED_G;
    Serial.println("LED_GREEN");
    break;
  case 'B':
    curPIN = LED_B;
    Serial.println("LED_BLUE");
    break;
  default:
    Serial.println("Wrong Color: " + msg.substring(0, index - 1));
    return;
  }

  if (msg.substring(index + 1) == "ON") {
    digitalWrite(curPIN, LOW);
    Serial.println("ON");
  }

  else if (msg.substring(index + 1) == "OFF") {
    digitalWrite(curPIN, HIGH);
    Serial.println("OFF");
  }
  else
    Serial.println("Wrong Command: " + msg.substring(index + 1));
}

void sw() {
  String msg = "Sensor ";
  if (digitalRead(SW_PIN) == 1)
    msg += "ON";
  else
    msg += "OFF";

  sockMNG.sendMsg(msg);
}
