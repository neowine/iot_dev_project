#ifndef _Module
#define _Module

#include "stdafx.h"
#include "SocketManager.h"

class Module {
public:
	Module(std::string moduleName); //Module 생성자. Module name 세팅 (json 에서 ct-name 부분)
	virtual ~Module(); //Module 소멸자. semaphore 해제
	void enqueueMsg(std::string msg); //각 컨테이너별 message queue. message queue는 SocketManager클래스에서 넣어준다. (받은 메시지를 분류하여 각 컨테이너별로 할당)
									  //메시지가 들어온 경우 semaphore를 하나 증가시킨다. 

	virtual void run() = 0; //메인 run 함수
	void setResetFlag(); //resetFlag를 올리기 위한 함수. 해당 flag가 올라갔을 경우 각 스레드를 종료한다.

	std::string getMsg(); //message queue로부터 메시지를 받아온다. 내부에서는 message queue 크기가 1 이상이 될 떄까지 block 상태로 대기한다.

	std::string getConName();  //Module name get 함수
protected:
	std::string moduleName;
	std::queue<std::string> msgQueue;
	sem_t queueSize; //semaphore
	bool resetFlag;
	int64_t timeStamp;
};

#endif