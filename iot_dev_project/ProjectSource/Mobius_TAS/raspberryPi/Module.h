#ifndef _Module
#define _Module

#include "stdafx.h"
#include "SocketManager.h"

class Module {
public:
	Module(std::string moduleName); //Module ������. Module name ���� (json ���� ct-name �κ�)
	virtual ~Module(); //Module �Ҹ���. semaphore ����
	void enqueueMsg(std::string msg); //�� �����̳ʺ� message queue. message queue�� SocketManagerŬ�������� �־��ش�. (���� �޽����� �з��Ͽ� �� �����̳ʺ��� �Ҵ�)
									  //�޽����� ���� ��� semaphore�� �ϳ� ������Ų��. 

	virtual void run() = 0; //���� run �Լ�
	void setResetFlag(); //resetFlag�� �ø��� ���� �Լ�. �ش� flag�� �ö��� ��� �� �����带 �����Ѵ�.

	std::string getMsg(); //message queue�κ��� �޽����� �޾ƿ´�. ���ο����� message queue ũ�Ⱑ 1 �̻��� �� ������ block ���·� ����Ѵ�.

	std::string getConName();  //Module name get �Լ�
protected:
	std::string moduleName;
	std::queue<std::string> msgQueue;
	sem_t queueSize; //semaphore
	bool resetFlag;
	int64_t timeStamp;
};

#endif