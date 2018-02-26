/*
	Project name: RGB_PI (Mobius TAS) - test code
	language: C++
	Company: neowine
	Author: Hee_Seung Son
	Date: 02/07/2018

	for dorca encryption test which using Mobius
*/
#include "stdafx.h"
#include "Led.h"
#include "SwitchSensor.h"
#include "DorcaClass.h"

using namespace std;

pthread_t pthread[3];
typedef void* (*THREADFUNCPTR)(void*);

void* contRunThread (void* con);

int main() {
	wiringPiSetupGpio();	
	Module* con;

	//--------------------------------------------------------------------------------------------------//for test (test key)
	Dorca::getInstance()->setKey("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	Dorca::getInstance()->setEncryptType(RG_AES, 32);
	//--------------------------------------------------------------------------------------------------//

	while (true) {
		pthread_create(&pthread[0], NULL, (THREADFUNCPTR)(&SocketManager::socketRead), SocketManager::getInstance());

		con = new Led("LED");
		SocketManager::getInstance()->addModule(con);
		pthread_create(&pthread[1], NULL, contRunThread, con);
		
		con = new SwitchSensor("sw-sensor");
		SocketManager::getInstance()->addModule(con);
		pthread_create(&pthread[2], NULL, contRunThread, con);

		con = NULL;
		for (int i = 0; i < 3; i++)
			pthread_join(pthread[i], NULL);
		SocketManager::destructInstance();
	}

	return 0;
}

void * contRunThread(void * con) {
	Module* module = (Module*) con;
	module->run();

	delete module;
	return NULL;
}