CXX = g++
CC = gcc
CFLAGS = -c -Wall -w
CXXFLAGS = $(CFLAGS) -std=c++11
LDFLAGS = -lbcm2835 -lpthread -lwiringPi

CSRCS = \
	./dorca/aes.c \
	./dorca/aes_core.c \
	./dorca/aes_ecb.c \
	./dorca/aes_misc.c \
	./dorca/aria.c \
	./dorca/Entry.c \
	./dorca/mrshs256.c \
	./dorca/function/aes128_engine.c \
	./dorca/function/dorca.c \
	./dorca/function/dorca30_function.c \
	./dorca/function/Dorca_API.c
CXXSRCS = \
	./SocketManager.cpp \
	./SwitchSensor.cpp \
	./Led.cpp \
	./Module.cpp \
	./DorcaClass.cpp \
	./main.cpp
OBJS = $(CXXSRCS:.cpp=.o) $(CSRCS:.c=.o)


all: raspberryPi_TAS
RGB_PI:	$(OBJS)
	@echo [Link] $@ FROM: $^
	@$(CXX) -o $@ $^ $(LDFLAGS)

.PHONY: all clean

clean:
	rm -f ./raspberryPi_TAS ./*.o f ./dorca/*.o ./dorca/function/*.o

.c.o: 
	@echo [Compile C] $<
	@$(CC) -o $@ $< $(CFLAGS)
.cpp.o:
	@echo [Compile C++] $<
	@$(CXX) -o $@ $< $(CXXFLAGS)
