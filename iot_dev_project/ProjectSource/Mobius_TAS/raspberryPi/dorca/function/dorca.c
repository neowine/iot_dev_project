#include <bcm2835.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include <string.h>


#define LOG_TAG1		"JNI_SPI_NEOWINE"
#define LOGI(...)	printf(__VA_ARGS__)
#define LOGE(...)	printf(__VA_ARGS__)
//<==
#define WHEREAMI() printf("%s %d\n",__FILE__,__LINE__)
#include "dorca.h"



struct spi_ioc_transfer xfer[2];
struct spi_ioc_transfer xferCM0[2];

char* value;
unsigned char  buf[1024];
unsigned char  buf1[1024];
unsigned char  buf2[1024];
unsigned char* buff1[128];
unsigned char  Keybuffer[128] = {0,};

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
extern int fd0;
extern int fd1;
char*  Dorca3_SPI_Init( int com_speed )
{
	if (!bcm2835_init())
	 {
	   printf("bcm2835_init failed. Are you running as root??\n");
	   return 1;
	 }
	 if (!bcm2835_spi_begin())
	 {
	   printf("bcm2835_spi_begin failed. Are you running as root??\n");
	   return 1;
	 }
	 printf("\r\n Dorca3_SPI_Init");	 
	 bcm2835_spi_setBitOrder(BCM2835_SPI_BIT_ORDER_MSBFIRST);	   // The default
	 bcm2835_spi_setDataMode(BCM2835_SPI_MODE0);				   // The default
	 bcm2835_spi_setClockDivider(BCM2835_SPI_CLOCK_DIVIDER_32); // The default
	 bcm2835_spi_chipSelect(BCM2835_SPI_CS0);					   // The default
	 bcm2835_spi_setChipSelectPolarity(BCM2835_SPI_CS0, LOW);	   // the default


}

void Dorca3_CM0_Close()
{
    bcm2835_spi_end();
    bcm2835_close();


}
void Dorca3_Close()
{
    bcm2835_spi_end();
    bcm2835_close();

}

char*  Dorca3_CM0_SPI_Init( int com_speed )
{
	if (!bcm2835_init())
	 {
	   printf("bcm2835_init failed. Are you running as root??\n");
	   return 1;
	 }
	 if (!bcm2835_spi_begin())
	 {
	   printf("bcm2835_spi_begin failed. Are you running as root??\n");
	   return 1;
	 }
	 printf("\r\n Dorca3_CM0_SPI_Init");
	 bcm2835_spi_setBitOrder(BCM2835_SPI_BIT_ORDER_MSBFIRST);	   // The default
	 bcm2835_spi_setDataMode(BCM2835_SPI_MODE1);				   // The default
	 bcm2835_spi_setClockDivider(BCM2835_SPI_CLOCK_DIVIDER_512  ); // The default
	 bcm2835_spi_chipSelect(BCM2835_SPI_CS1);					   // The default
	 bcm2835_spi_setChipSelectPolarity(BCM2835_SPI_CS0, LOW);	   // the default


}

void send_data_arm7(unsigned char *buffer,int size)
{
	int status, i;
	memset(buf, 0, sizeof buf);
	memset(buf2, 0, sizeof buf2);
	

	for (i=0; i< size ; i++)
	   buf[i] = buffer[i];


	bcm2835_spi_transfern(&buf[0], size);


//--- Stop

}

void read_data_arm7(unsigned char *tx_buffer,unsigned char *rx_buffer, int size)
{
	int status, i;
	memset(buf, 0, sizeof buf);
	memset(buf2, 0, sizeof buf2);
	
	for (i=0; i< 5 ; i++)
	   buf[i] = tx_buffer[i];

	bcm2835_spi_transfern(&buf[0], 5);
	usleep(50);
	bcm2835_spi_transfern(&rx_buffer[0], size);

	
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
	
    // 1 instruction
	// 2 addr MSB
	// 3 addr LSB
	// 4 dummy

	bcm2835_spi_transfern(&buf[0], nbytes+4);			//data_buffer used for tx and rx    printf("Sent to SPI: 0x%02X. Read back from SPI: 0x%02X.\n", send_data, read_data);
	memcpy(rx_data,&buf[4],nbytes);
	if (status < 0)
	{
		LOGE("SPI_IOC_MESSAGE spi_read");
		return;
	}
}


void spi_write(int fd,int inst, int addr, int nbytes, char *value)
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

	bcm2835_spi_transfern(&buf[0], nbytes+5);


}


