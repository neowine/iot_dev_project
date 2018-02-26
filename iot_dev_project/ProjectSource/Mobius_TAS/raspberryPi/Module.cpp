#include "stdafx.h"
#include "Module.h"

using namespace std;

Module::Module(string moduleName) {
	struct timeval tv;
	gettimeofday(&tv, NULL);

	this->moduleName = moduleName;
	sem_init(&this->queueSize, 0, 0);
	this->resetFlag = false;
	this->timeStamp = (int64_t)(tv.tv_sec) * 1000 + (int64_t)(tv.tv_usec) / 1000;
}

Module::~Module() {
	sem_destroy(&this->queueSize);
}

void Module::enqueueMsg(string msg) {
	this->msgQueue.push(msg);
	if (sem_post(&this->queueSize) < 0) {
		cout << "msg Enqueue semaphore error!!!" << endl;
		while (this->msgQueue.size())
			this->msgQueue.pop();
	}
}

string Module::getMsg() {
	struct timespec time;
	while (true) {
		do {
			if (this->resetFlag)
				pthread_exit(NULL);
			while (clock_gettime(CLOCK_REALTIME, &time) == -1)
				cout << "clock gettime" << endl;
			time.tv_sec += 2;
		} while (sem_timedwait(&this->queueSize, &time) < 0);
		string msg = this->msgQueue.front(); // Red/Green/Blue + " " + ON/OFF
		this->msgQueue.pop();

		cout << "raw: " << msg << endl;

		int start = msg.find(":") + 1;
		int end = msg.find(";") - start;
		int64_t checkTime;
		try {
			checkTime = stoll(msg.substr(start, end));
		} 
		catch (exception e) {
			cout << "Wrong time stamp!" << endl;
		}

		if (this->timeStamp < checkTime) {
			this->timeStamp = checkTime;
			return msg.substr(0, msg.find(":"));
		}
		else {
			cout << "my: " << this->timeStamp << endl;
			cout << "recv: " << checkTime << endl;
			cout << "blocked unknown user" << endl;
		}
	}
}


void Module::setResetFlag() {
	this->resetFlag = true;
}

std::string Module::getConName() {
	return this->moduleName;
}