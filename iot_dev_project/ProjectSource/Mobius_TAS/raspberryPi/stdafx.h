#ifndef _STDAFX
#define _STDAFX

//해당 파일은 모든 파일에 쓰이는 헤더들을 기술한 파일입니다.

#include <iostream>
#include <queue>
#include <semaphore.h>
#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wiringPi.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <map>
#include <signal.h>
#include <ctime>
#include <sys/time.h>

extern "C" {
#include "dorca/function/dorca30_api.h"
#include "dorca/dorca_header_4_cpp.h"
}

#endif