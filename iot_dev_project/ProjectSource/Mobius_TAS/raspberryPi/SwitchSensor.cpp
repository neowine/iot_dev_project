#include "SwitchSensor.h"

using namespace std;

SwitchSensor::SwitchSensor(std::string mod_name) : Module(mod_name) {
	pinMode(LIGHT, INPUT);
	pullUpDnControl(LIGHT, PUD_DOWN);
}

void SwitchSensor::run() {
	string value;
	while (true) {
		if (this->resetFlag)
			return;

		int val = digitalRead(LIGHT);
		string str;
		switch (val) {
		case 0:
			str = "Sensor 1 OFF";
			break;
		case 1:
			str = "Sensor 1 ON";
			break;
		}

		SocketManager::getInstance()->socketWrite(str);
		cout << str << endl << endl;
		delay(1000);
	}
}