#ifndef _SWITCHSENSOR
#define _SWITCHSENSOR

#include "Module.h"

#define LIGHT 12

class SwitchSensor :
	public Module {
public:
	SwitchSensor(std::string mod_name); //mod_name �����ϴ� ������
private:
	void run(); //Module�κ��� ��ӹ��� run �Լ�
};

#endif