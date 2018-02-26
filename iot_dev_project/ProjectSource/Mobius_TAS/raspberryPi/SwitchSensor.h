#ifndef _SWITCHSENSOR
#define _SWITCHSENSOR

#include "Module.h"

#define LIGHT 12

class SwitchSensor :
	public Module {
public:
	SwitchSensor(std::string mod_name); //mod_name 세팅하는 생성자
private:
	void run(); //Module로부터 상속받은 run 함수
};

#endif