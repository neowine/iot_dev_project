

//<==
#define WHEREAMI() printf("%s %d\n",__FILE__,__LINE__)
#include "dorca.h"
#include "dorca30_api.h"


char* value;
unsigned char  buf[1024];
unsigned char  buf1[1024];
unsigned char  buf2[1024];
unsigned char* buff1[128];
unsigned char  Keybuffer[128] = {0,};
//Serial *pSerialLocal = 0;
extern Serial_ Serial;
int gSPIMode = 0;
/*
 *
Name
Spi_init ()Initialize sip_device for Neowine application
Synopsis
#include < dorca.h>
int spi_init();
Description
The spi_init () function used to initialize spi_device on AP's interface.
Return Value
The spi_init () function returns a OK or NotOK
 * */

 //char* filePath ="/mnt/sdcard/";
/*
int create_file()
{
	int open_flags = O_RDWR | O_CREAT | O_DIRECT | O_SYNC;
	//LOGI("filePath: %s\n", filePath);
	fd = open(filePath, open_flags, 0766);
	if(fd<0){
		LOGE("Create errno: %s\n", strerror(errno));
		return -1;
	}
	//LOGI("Neowine create OK , fd=%d \n", fd);
	return fd;

}
*/

//void SetSerial(Serial *pSerial)
//{
//	pSerialLocal = pSerial;
//}
#define WAITDELAY 6
void Dorca3_SPI_Init( int com_speed )
{	SPI.begin();
	delay(100);

	Serial.println("Dorca3_SPI_Init");
	if(1 == gSPIMode) {
	digitalWrite(INT_0, HIGH);			
	//delayMicroseconds(WAITDELAY);

	digitalWrite(INT_0, LOW);	
	delayMicroseconds(200*1000);
	gSPIMode = 0;
	Serial.println("SPI 1");	
	}

	SPI.beginTransaction(SPISettings(com_speed, MSBFIRST, SPI_MODE0));
}

void INT0()
{
	volatile int i = 0;
	//digitalWrite(INT_0, LOW);	
	//Serial.println("INT0");
	//Serial.println(INT_0);
	
	Serial.println("INT0_HIGH_LOW");	
	return;
	
	//for( i = 0; i < 3000; i++);
	for( i = 0; i < 3; i++);
	//for( i = 0; i < 30; i++);	
	//for( i = 0; i < 30; i++);
	//for( i = 0; i < 30; i++);
	//for( i = 0; i < 30; i++);	
	digitalWrite(INT_0, HIGH);			
	digitalWrite(INT_0, LOW);	

}


void Dorca3_CM0_Close()
{

	SPI.endTransaction();
	SPI.end();
	Serial.println("Dorca3_CM0_Close");	

}
void Dorca3_Close()
{
	Serial.println("Dorca3_Close");

   SPI.endTransaction();
   SPI.end();
}

char*  Dorca3_CM0_SPI_Init( int com_speed )
{
	Serial.println("Dorca3_CM0_SPI_Init");
	delay(100);

	SPI.begin();
	if(0 == gSPIMode){
#if 0	
	digitalWrite(INT_1, HIGH);			
	digitalWrite(INT_1, LOW);	
#else
	digitalWrite(INT_0, HIGH);	
	//delayMicroseconds(WAITDELAY);

	digitalWrite(INT_0, LOW);	
#endif
	delayMicroseconds(200*1000);
	gSPIMode = 1;
	Serial.println("SPI 1");	
	}

	SPI.beginTransaction(SPISettings(com_speed, MSBFIRST, SPI_MODE1));

}

void send_data_arm7(unsigned char *buffer,int size)
{
	int status, i;
	memset(buf, 0, sizeof buf);
	memset(buf2, 0, sizeof buf2);
	

	for (i=0; i< size ; i++)
	   buf[i] = buffer[i];

	digitalWrite(CS1, LOW);	
	
	for(i = 0; i < size; i++)
		SPI.transfer(buf[i]);
	
	digitalWrite(CS1, HIGH);	



//--- Stop

}

void read_data_arm7(unsigned char *tx_buffer,unsigned char *rx_buffer, int size)
{
	int status, i;

	digitalWrite(CS1, LOW);	
	for(i = 0; i < 5; i++)
		SPI.transfer(tx_buffer[i]);

	digitalWrite(CS1, HIGH);	
	delayMicroseconds(100*1000);
	digitalWrite(CS1, LOW);	
	for(i = 0; i < size; i++)
		rx_buffer[i] = SPI.transfer(0);
	
	digitalWrite(CS1, HIGH);	

	
//--- Stop

}

void spi_read (int fd,int inst, int addr, int nbytes, unsigned char *rx_data)
{
	int status, i;

	memset(buf, 0, sizeof buf);
	memset(buf2, 0, sizeof buf2);

	buf[0] = (char)inst;
	buf[1] = (addr>>8) & 0xFF;
	buf[2] = addr & 0xFF;
	buf[3] = 0xFF;
	//Serial.println("spi_read size");
	//Serial.println(nbytes);	
	
	digitalWrite(CS0, LOW);	
	for(i = 0; i < 4; i++)
		SPI.transfer(buf[i]);
	
	for(i = 0; i < nbytes; i++)
		rx_data[i] = SPI.transfer(0);
	
	digitalWrite(CS0, HIGH);	
    // 1 instruction
	// 2 addr MSB
	// 3 addr LSB
	// 4 dummy


}


void spi_write(int fd,int inst, int addr, int nbytes, unsigned char *value)
{

	int status, i;

	memset(buf, 0, sizeof buf);
	memset(buf2, 0, sizeof buf2);
	buf[0] = (char)inst;
	buf[1] = (addr>>8) & 0xFF;
	buf[2] = addr & 0xFF;
	buf[3] = 0xFF;
	
    // 1 instruction
	// 2 addr MSB
	// 3 addr LSB
	// 4 dummy
	// 5 ~ N byte payload
	// 6 dummy
	for (i=0; i< nbytes ; i++)
	   buf[i + 4] = value[i];

	buf[nbytes+4] = 0xFF;
	//Serial.println("spi_write size");
	//Serial.println(nbytes);
	digitalWrite(CS0, LOW);
	for( i= 0; i < nbytes+4+1; i++)
		SPI.transfer(buf[i]);
	digitalWrite(CS0, HIGH);


}


