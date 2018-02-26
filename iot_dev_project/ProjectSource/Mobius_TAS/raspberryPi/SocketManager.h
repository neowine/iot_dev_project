#ifndef _SOCKMANAGER
#define _SOCKMANAGER

#include "stdafx.h"
#include "Module.h"
#include "DorcaClass.h"

#define BUF_LEN 256
#define TAS_PORT 3105 //TAS 포트번호
#define CONT_NAME "raspberryPi-"

class Module;

class SocketManager {
public:
	static SocketManager * getInstance(); //싱글턴 패턴을 위한 getInstance 함수
	static void destructInstance(); //소멸을 위한 destruct 함수
	void initConnect(); //nCube와 초기 연결
	void* socketRead(void*); //소켓으로부터 Read 수행. 스레드 함수.
	void socketWrite(std::string content); //소켓으로부터 Write 수행.
	void addModule(Module* Module); //ModuleList, Map에 컨테이너 추가
	void deleteModule(std::string conName); //ModuleList, Map으로부터 해당 contName을 가진 컨테이너를 삭제

	void get_nCubeInfo();

private:
	int sock_fd;
	bool errFlag;
	std::string cont_name;
	in_addr_t nCube_addr;

	struct sockaddr_in sock_addr;
	static SocketManager* Instance;

	pthread_mutex_t sockWriteMutex; //write를 할 때 사용되는 Mutex
	std::vector<Module*> ModuleList; //Module * 저장.
	std::map<std::string, u_int> ModuleIndex; //map 자료구조를 사용하여 Module를 빠르게 찾음.

	SocketManager(); //생성자
	~SocketManager(); //소멸자
	std::string change_to_json(std::string Module_name, std::string content); //Module name 과 cotent를 받아 송신할 json파일로 변환
	std::string getContent(std::string json_c, std::string key); //json 문자열로부터 key값에 해당하는 필드의 데이터를 parse
	void sendHelloPacket();
};

#endif