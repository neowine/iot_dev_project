#ifndef _SOCKMANAGER
#define _SOCKMANAGER

#include "stdafx.h"
#include "Module.h"
#include "DorcaClass.h"

#define BUF_LEN 256
#define TAS_PORT 3105 //TAS ��Ʈ��ȣ
#define CONT_NAME "raspberryPi-"

class Module;

class SocketManager {
public:
	static SocketManager * getInstance(); //�̱��� ������ ���� getInstance �Լ�
	static void destructInstance(); //�Ҹ��� ���� destruct �Լ�
	void initConnect(); //nCube�� �ʱ� ����
	void* socketRead(void*); //�������κ��� Read ����. ������ �Լ�.
	void socketWrite(std::string content); //�������κ��� Write ����.
	void addModule(Module* Module); //ModuleList, Map�� �����̳� �߰�
	void deleteModule(std::string conName); //ModuleList, Map���κ��� �ش� contName�� ���� �����̳ʸ� ����

	void get_nCubeInfo();

private:
	int sock_fd;
	bool errFlag;
	std::string cont_name;
	in_addr_t nCube_addr;

	struct sockaddr_in sock_addr;
	static SocketManager* Instance;

	pthread_mutex_t sockWriteMutex; //write�� �� �� ���Ǵ� Mutex
	std::vector<Module*> ModuleList; //Module * ����.
	std::map<std::string, u_int> ModuleIndex; //map �ڷᱸ���� ����Ͽ� Module�� ������ ã��.

	SocketManager(); //������
	~SocketManager(); //�Ҹ���
	std::string change_to_json(std::string Module_name, std::string content); //Module name �� cotent�� �޾� �۽��� json���Ϸ� ��ȯ
	std::string getContent(std::string json_c, std::string key); //json ���ڿ��κ��� key���� �ش��ϴ� �ʵ��� �����͸� parse
	void sendHelloPacket();
};

#endif