/*
 Name:    RGB_Arduino.ino
 Created: 2018-02-09 오전 9:05:48
 Author:  toddlf95
*/
#include <RTClib.h>
#include <WiFi101.h>
#include <SocketManager.h>
#include "dorca30_api.h"
///////////////////////////////////////////need Setting
#define LED_R 6
#define LED_G 9
#define LED_B 10

#define TAS_PORT 3105
#if 0
#define CT_NAME "arduino-"

//#define SSID "HUAWEI-4322-2.4G"
//#define PW "79726109"
#define SSID "HUAWEI-47DC-2.4G"
#define PW "98080753"

#else
#define CT_NAME "arduino-"

#define SSID "spshin"
#define PW "12345678"
#endif
int count = 0;
#define SW_PIN 11
///////////////////////////////////////////////end

SocketManager sockMNG;

void pinStr( uint32_t ulPin, unsigned strength) // works like pinMode(), but to set drive strength
{
  // Handle the case the pin isn't usable as PIO
  if ( g_APinDescription[ulPin].ulPinType == PIO_NOT_A_PIN )
  {
    return ;
  }
  if(strength) strength = 1;      // set drive strength to either 0 or 1 copied
  PORT->Group[g_APinDescription[ulPin].ulPort].PINCFG[g_APinDescription[ulPin].ulPin].bit.DRVSTR = strength ;
}
int oldTime; //ms
String msg;

void led(String msg);
void sw();

const int sendTimeInterval = 1000; //ms
// the setup function runs once when you press reset or power the board
void setup() {
  
 // Open serial communications and wait for port to open:
 pinMode (CS0, OUTPUT);
 pinMode (CS1, OUTPUT); 
 pinMode (INT_0, OUTPUT);  
 pinMode (INT_1, OUTPUT);  
 pinMode (16, OUTPUT);  
 pinMode (POWER, OUTPUT);
 pinStr(POWER, 1);
pinStr(16, 1); 
 
// digitalWrite (CS1, LOW);
// digitalWrite (CS1, LOW);
 
 digitalWrite (INT_1, LOW);  
 //digitalWrite (INT_1, HIGH);
 digitalWrite (POWER, LOW);
 digitalWrite (16,  LOW);
 delay(2000);

 digitalWrite (16, HIGH);
 digitalWrite (POWER, HIGH);
 digitalWrite (CS0, HIGH);
 digitalWrite (CS1, HIGH);
  Serial.begin(9600);
  delay(3000);
  //while (!Serial); ////for TEST

  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);
  pinMode(SW_PIN, INPUT_PULLDOWN);

  digitalWrite(LED_R, LOW);
  digitalWrite(LED_G, LOW);
  digitalWrite(LED_B, LOW);
  Serial.println("before...");
  wake_up();
  TEST_AES();
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
  /*
  if (millis() - oldTime > sendTimeInterval) {
    oldTime = millis();
    sw();
  }
  */
  Serial.println(count);
  //TEST_AES();
  if (sockMNG.readMsg(&msg,0,0)) {
    Serial.println("FINAL MESSAGE");
    Serial.print(msg);
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
    Serial.println("LOCAL _ LED_RED");
    break;
  case 'G':
    curPIN = LED_G;
    Serial.println("LOCAL _ LED_GREEN");
    break;
  case 'B':
    curPIN = LED_B;
    Serial.println("LOCAL _ LED_BLUE");
    break;
  default:
    Serial.println("LOCAL _ Wrong Color: " + msg.substring(0, index - 1));
    return;
  }
  Serial.println("COMMAND");
  Serial.print(msg.substring(index + 1, index + 3));
  if (msg.substring(index + 1, index + 3) == "ON") {
    digitalWrite(curPIN, LOW);
    
  }

  else if (msg.substring(index + 1, index + 3) == "OF") {
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
