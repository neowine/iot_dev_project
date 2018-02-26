#include "SocketManager.h"

using namespace std;

SocketManager* SocketManager::Instance = NULL;

SocketManager * SocketManager::getInstance() {
	if (Instance == NULL) {
		Instance = new SocketManager;
		return Instance;
	}
	else
		return Instance;
}

void SocketManager::destructInstance() {
	delete SocketManager::getInstance();
	SocketManager::Instance = NULL;
}

SocketManager::SocketManager() {
	pthread_mutex_init(&this->sockWriteMutex, NULL);

	this->get_nCubeInfo();
	while (true) {
		if ((this->sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			cout << "Can't open stream socket" << endl;
			continue;
		}
		break;
	}
	memset(&this->sock_addr, 0, sizeof(this->sock_addr));

	this->sock_addr.sin_family = AF_INET;
	this->sock_addr.sin_addr.s_addr = this->nCube_addr;
	this->sock_addr.sin_port = htons(TAS_PORT);
	this->errFlag = false;
	this->cont_name = CONT_NAME;
	
	int flag = 1;
	signal(SIGPIPE, SIG_IGN);

	this->initConnect();
	this->sendHelloPacket();
}

SocketManager::~SocketManager() {
	close(this->sock_fd);
}

void SocketManager::initConnect() {
	while (true) {
		if (connect(sock_fd, (struct sockaddr*)&sock_addr, sizeof(sock_addr))) {
			cout << "can't connect to nCube." << endl;
			cout << "try reconnect..." << endl;
			delay(1000);
			continue;
		}
		cout << "nCube connect success!!" << endl << endl;
		break;
	}
}

void * SocketManager::socketRead(void *) {
	char buff[BUF_LEN];
	while (true) {
		memset(buff, 0, BUF_LEN);
		if (this->errFlag || read(this->sock_fd, buff, BUF_LEN - 1) <= 0) {
			cout << "sockRead error!!!" << endl;
			for (Module* cont : this->ModuleList)
				cont->setResetFlag();
			this->errFlag = false;
			break;
		}
		try {
			string con = this->getContent(buff, "con");
			con = Dorca::getInstance()->decrypt(con);

			string mod_name = con.substr(0, con.find("_"));
			con = con.substr(con.find("_") + 1);

			int cont_index = this->ModuleIndex.find(mod_name)->second;
			if (cont_index < ModuleList.size()) {
				this->ModuleList[cont_index]->enqueueMsg(con);
				cout << "read buff complete" << endl;
			}
			else
				cout << "read buff failed. mod_name: " << mod_name << ", con: " << con << endl;
		}
		catch (exception e) {
			cout << "read fail... wrong data: " << buff << endl;
		}
	}
	return NULL;
}

void SocketManager::socketWrite(string content) {

	if (content != "hello") {
		struct timeval tv;
		gettimeofday(&tv, NULL);

		content += ":" + to_string((int64_t)(tv.tv_sec) * 1000 + (int64_t)(tv.tv_usec) / 1000) + ";"; // for timeStamp
		cout << "raw send: " << content << endl;
		content = Dorca::getInstance()->encrypt(content);
		cout << "enc send: " << content << endl;
	}

	string msg = this->change_to_json(this->cont_name + "out", content);

	pthread_mutex_lock(&this->sockWriteMutex);
	if (write(this->sock_fd, msg.c_str(), msg.size()) <= 0) {
		cout << "sockWrite error!!" << endl;
		this->errFlag = true;
	}
	else
		this->errFlag = false;
	delay(10);
	pthread_mutex_unlock(&this->sockWriteMutex);
}

void SocketManager::addModule(Module * Module) {
	this->ModuleList.push_back(Module); 
	this->ModuleIndex.insert(map<string, int>::value_type(Module->getConName(), ModuleList.size() - 1));
}

void SocketManager::deleteModule(string conName) {
	int index;
	map<string, u_int>::iterator iter = this->ModuleIndex.find(conName);

	if (iter != this->ModuleIndex.end()) 
		index = iter->second;
	else {
		cout << "\"" << conName << "\" Module is not exist." << endl;
		return;
	}

	delete this->ModuleList[index];
	this->ModuleList.erase(this->ModuleList.begin() + index);

	while(index++ < this->ModuleList.size()) 
		this->ModuleIndex.find(this->ModuleList[index]->getConName())->second--;
}

void SocketManager::get_nCubeInfo() {
	bool opt_val = true;
	int broadcastSock_fd;
	sockaddr_in addr_me, addr_nCube;
	while (true) {
		if ((broadcastSock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			cout << "get socket fail..." << endl;
			continue;
		}
		setsockopt(broadcastSock_fd, SOL_SOCKET, SO_BROADCAST, &opt_val, sizeof(opt_val));

		memset(&addr_me, 0, sizeof(addr_me));
		addr_me.sin_family = AF_INET;
		addr_me.sin_port = htons(TAS_PORT);
		addr_me.sin_addr.s_addr = INADDR_ANY;
		if (bind(broadcastSock_fd, (sockaddr*)&addr_me, sizeof(addr_me)) == -1) {
			cout << "bind broadcast socket fail..." << endl;
			continue;
		}
		break;
	}
	
	char buff[BUF_LEN];
	unsigned int addrLen = sizeof(addr_me);
	cout << endl << "Try get nCube IP addr..." << endl;
	while (true) {
		string buff_string;
		memset(buff, 0, sizeof(BUF_LEN));
		recvfrom(broadcastSock_fd, buff, BUF_LEN, 0, (sockaddr*)&addr_nCube, &addrLen);
		buff_string = buff;
		if (buff_string.find("nCube") != string::npos) {
			this->nCube_addr = addr_nCube.sin_addr.s_addr;
			cout << "get nCube IP success!!!" << endl << "\tIP addr: " << inet_ntoa(addr_nCube.sin_addr) << endl << endl;
			break;
		}
	}
	close(broadcastSock_fd);
}

void SocketManager::sendHelloPacket() {
	string helloPacket = this->change_to_json(this->cont_name + "in", "hello");
	string check = "";
	char buff[BUF_LEN];
	struct timeval tv;

	tv.tv_sec = 2;
	tv.tv_usec = 0;
	setsockopt(this->sock_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval*)&tv, sizeof(tv));
	while (check != "hello") { 
		memset(buff, 0, BUF_LEN);
		cout << "send hello packet..." << endl;
		write(this->sock_fd, helloPacket.c_str(), helloPacket.length());
		if (read(this->sock_fd, buff, BUF_LEN - 1) < 0) {
			cout << "retry..." << endl;
			continue;
		}
		try {
			check = this->getContent(buff, "con");
		}
		catch (exception e) {
			cout << "wrong data... please send to JSON format" << endl;
		}
	}
	tv.tv_sec = 0;
	setsockopt(this->sock_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval*)&tv, sizeof(tv));

	cout << this->cont_name << " get hello packet success!!" << endl << endl;
}

string SocketManager::change_to_json(string Module_name, string content) {
	string json;
	json = "{  \"ctname\":  \"" + Module_name + "\",  \"con\":  \"" + content + "\"  }";
	return json;
}

string SocketManager::getContent(string json_c, string key) {
	string jform_name = "\"" + key + "\":\"";

	int start = json_c.find(jform_name) + jform_name.length();   // find location of Module
	int end = json_c.find('"', start);         // end of content
	jform_name = json_c.substr(start, end - start);

	return jform_name;
}