#include "Led.h"

using namespace std;

Led::Led(string mod_name) : Module(mod_name) {
	pinMode(LED_R, OUTPUT);
	pinMode(LED_G, OUTPUT);
	pinMode(LED_B, OUTPUT);

	digitalWrite(LED_R, 1);
	digitalWrite(LED_G, 1);
	digitalWrite(LED_B, 1);
}

void Led::run() {
	while (true) {
		string msg = this->getMsg();

		cout << "get massage: " << msg << endl;

		if (this->resetFlag)
			return;

		int pin_num = -1;
		switch (msg[0]) {
		case 'R':
			pin_num = LED_R;
			cout << "Module name - LED Red" << endl;
			break;
		case 'G':
			pin_num = LED_G;
			cout << "Module name - LED Green" << endl;
			break;
		case 'B':
			pin_num = LED_B;
			cout << "Module name - LED Blue" << endl;
			break;
		default:
			cout << "wrong Module" << endl;
			continue;
		}

		int index = msg.find(" ") + 1;
		msg = msg.substr(index, msg.find(" ", index) - index);

		if (msg == "OFF")
			digitalWrite(pin_num, 1);
		else if (msg == "ON")
			digitalWrite(pin_num, 0);
		else {
			cout << "wrong command: " << msg << endl << endl;
			continue;
		}

		cout << "command: " << msg << endl << endl;
	}
}