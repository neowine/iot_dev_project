#ifndef _LED
#define _LED

#include "stdafx.h"
#include "Module.h"

#define LED_R 16
#define LED_G 20
#define LED_B 21

class Led :
	public Module {
public:
	Led(std::string mod_name); //mod_name�� ����.
	void run(); //Module�κ��� ��ӹ޾� ����ϴ� run �Լ�
};

#endif