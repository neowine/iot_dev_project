//#define ETRY_CODE
#ifndef ETRY_CODE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#endif
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>

#define NETBUF_SIZE 161
#define ENCBUF_SIZE 160
#define WHEREAMI() printf("%s %d\n",__FILE__,__LINE__)

#define GPIO_OUTPUT 0
#define GPIO_INPUT 1
#define GPIO_HIGH  1
#define GPIO_LOW  0
 
#define GPIO_NONE  "none"
#define GPIO_FALLING "falling"
#define GPIO_RISING "rising"
#define GPIO_BOTH  "both"
#define MAX_BUF 512
#define SYSFS_GPIO_DIR "/sys/class/gpio"


#define PA01	    ((unsigned int)1 << 1)

#define VPP_OUT     
#define VPP_OFF	    
//#define VPP_LOW		AT91F_PIO_ClearOutput(AT91C_BASE_PIOA,PA01)//	PORTC &= 0xFb
//#define VPP_HIGH  	AT91F_PIO_SetOutput(AT91C_BASE_PIOA, PA01)

#define VPP_LOW		
#define VPP_HIGH  	
//void ChangeSerial(unsigned long serial_no);


//#define PA22	    ((unsigned int) 1 << 22)
#define VPP_PA22_OUT      
#define VPP_PA22_ON	      
#include <stdio.h>
#define VPP_PA22_OFF	


//#define PA23	    ((unsigned int) 1 << 23)
#define VPP_PA23_OUT      
#define VPP_PA23_ON	       
#define VPP_PA23_OFF	
int fd_19;

#ifndef ETRY_CODE
void export(int gpio)
{
   char buf[MAX_BUF]; 
   int fd;
//   printf("export %d\n",gpio); 
   fd = open("/sys/class/gpio/export", O_WRONLY);
   sprintf(buf, "%d", gpio); 
   write(fd, buf, strlen(buf));
   close(fd);
}

void unexport(int gpio)
{
   char buf[MAX_BUF]; 
   int fd;
	
//	printf("unexport %d\n",gpio);
	fd = open("/sys/class/gpio/unexport", O_WRONLY);
   sprintf(buf, "%d", gpio);
   write(fd, buf, strlen(buf));
   close(fd);
}

 void direction(int gpio, int dir)
{
   char buf[MAX_BUF]; 
   int fd;

//	printf("direction %d dir %d\n",gpio,dir);
   sprintf(buf, "/sys/class/gpio/gpio%d/direction", gpio);

   fd = open(buf, O_WRONLY);

   // Set out direction
   if(dir == 1)
	   write(fd, "out", 3); 
   else// Set in direction
	   write(fd, "in", 2); 
	   
   close(fd);
}

void read_val(int gpio)
{
   char buf[MAX_BUF]; 
   int fd;

   char value;

 //  printf("read_val %d \n",gpio);
   sprintf(buf, "/sys/class/gpio/gpio%d/value", gpio);

   fd = open(buf, O_RDONLY);

   read(fd, &value, 1);

   if(value == '0')
   { 
		// Current GPIO status low
   }
   else
   {
		// Current GPIO status high
   }

   close(fd);
}

void write_val(int gpio, int val)
{
   char buf[MAX_BUF]; 
   int fd;

//   printf("write_val  gpio %d val %d \n",gpio,val); 
   sprintf(buf, "/sys/class/gpio/gpio%d/value", gpio);
   fd = open(buf, O_WRONLY);
   // Set GPIO high status
   if(val == 1)
	   write(fd, "1", 1); 
   // Set GPIO low status 
   else
	   write(fd, "0", 1); 

   close(fd);
}


void PortOpen()
{
	char buf[MAX_BUF];
	//	 printf("write_val	gpio %d val %d \n",gpio,val); 
	   sprintf(buf, "/sys/class/gpio/gpio%d/value", 19);
	   fd_19 = open(buf, O_WRONLY);
	   // Set GPIO high status
 
	


}
#endif

void PrintCntEx(int HitCnt, int MissCnt,int IgnoreCnt, int TotalCnt)
{
	printf("\r\n---------------------------------------------");
	printf("\r\nHIT Cnt : %d   MISS Cnt : %d   IgnoreCnt : %d  TOTAL Cnt : %d",HitCnt,MissCnt,IgnoreCnt,TotalCnt);
//	gTESTAllCnt++;
	if(MissCnt == 0)
		printf("\r\n PASS");
	else
		{
			printf("\r\n FAIL");
//			gTESTAllErrorCnt++;
		}
	printf("\r\n---------------------------------------------");
}

extern unsigned int cs;
 int gPrintMode;
extern int Aes256;
extern int Aes128;
extern int Aria256;
extern int Aria128;
extern int AesIsFirst;
unsigned int NumOfIterMain = 1;

#define LOGI(...)	printf(__VA_ARGS__)
#define LOGE(...)	printf(__VA_ARGS__)
#define SPI0_SPEED 1000*1000
#define SPI1_SPEED 500*1000
#define POWER 12
void PowerOn()
{
#ifndef ETRY_CODE

	export(POWER);
	export(19); 		
	export(8);
	export(7);			
	
	printf("export");
	direction(POWER,1);
	direction(19,1);			
	direction(8,1); 			
	direction(7,1); 
	printf("\r\n Clear ALL");
	write_val(POWER,0);
	write_val(19,0);			
	write_val(8,0); 			
	write_val(7,0); 			
	usleep(300*1000);
	printf("\r\n Power On");
	write_val(POWER,1);;
	usleep(300*1000);

	printf("\r\n Clear ALL");
	write_val(POWER,0);
	write_val(19,0);			
	write_val(8,0); 			
	write_val(7,0); 			
	usleep(300*1000);
	printf("\r\n Power On");
	write_val(POWER,1);;
#endif
}

void GenINT0()
{
#ifndef ETRY_CODE
	int j = 0;
	write(fd_19, "1", 1); 
	write(fd_19, "0", 1);

#endif

}

void GenINT1SEC()
{
#ifndef ETRY_CODE
	int j = 0;
	write_val(19,1);
					sleep(1);
	for(j = 0; j < 1; j++);;

	write_val(19,0);
#endif

}

void RaspberryDorcaInit() {
#ifndef ETRY_CODE		
	PowerOn();
	PortOpen();
	Dorca3_SPI_Init(SPI0_SPEED);
#endif
	printf("\r\n WAKE UP DORCA !!!!");
	VPP_HIGH;
	Delay_us(1);
	VPP_LOW;
	printf("\r\n Delay 110ms !!!!");
	VPP_PA22_OUT;
	VPP_PA23_OUT;
	Delay_ms(100);
	delay_ms(10);

	VPP_PA22_OFF;
	VPP_PA23_OFF;
#ifndef ETRY_CODE
	SET_SPI0();
#endif
}

extern int g_KeyloadFailCnt;