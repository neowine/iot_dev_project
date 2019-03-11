#include <stdlib.h>
//#include <memory.h>
#include <stdio.h>
typedef unsigned char uint8_t;

#include "dorca30_function.h"

#include "aes.h"
#include <Arduino.h>
#ifdef COMPARE
#include "../include/aria.h"
#endif
#include "dorca30_api.h"
#include "dorca30_api_inside.h"

#include "dorca.h"
#include "miracl.h"

//#include "../interface/spi_interface.h"

//#include "aes128.h"
//#include "aes256.h"
//#include "aria128.h"
//#include "aria256.h"
#define ARIA_256
//#define AES_256
//#define ARIA_128
//#define PRINTFMODE 0
//#define RESULT_COMPARE
//#define DEBUG_DELAY
#define PRINTFMODE_PERMISSION 0
#define LAST 1
//#define PRINTLOG 0
//**********************************************************************************
//  CRC  OPLYNOM define
//**********************************************************************************
//Tested
#define CRC16_DNP	0x3D65		// DNP, IEC 870, M-BUS, wM-BUS, ...
#define CRC16_CCITT	0x1021		// X.25, V.41, HDLC FCS, Bluetooth, ...

//Other polynoms not tested
#define CRC16_IBM	0x8005		// ModBus, USB, Bisync, CRC-16, CRC-16-ANSI, ...
#define CRC16_T10_DIF	0x8BB7		// SCSI DIF
#define CRC16_DECT	0x0589		// Cordeless Telephones
#define CRC16_ARINC	0xA02B		// ACARS Aplications

#define POLYNOM		CRC16_CCITT   // Define the used polynom from one of the aboves
#define USING_KEYLOAD 1
//**********************************************************************************
#if 1
#define PRINTLOG(...) printk(__VA_ARGS__)
#else
#define PRINTLOG(...) (void)0
#endif
//**********************************************************************************
//  test define
//**********************************************************************************
#define WR_SIZE_1	   1
#define WR_SIZE_3      3
#define WR_SIZE_8      8
#define WR_SIZE_16     16
#define WR_SIZE_64     64
#define VPP_LOW		AT91F_PIO_ClearOutput(AT91C_BASE_PIOA,PA01)//	PORTC &= 0xFb
#define VPP_HIGH  	AT91F_PIO_SetOutput(AT91C_BASE_PIOA, PA01)
#define AES128ENCODE 1
#define AES128DECODE 2
#define AES256ENCODE 3
#define AES256DECODE 4
#define ARIA128ENCODE 5
#define ARIA128DECODE 6
#define ARIA256ENCODE 7
#define ARIA256DECODE 8
#define SPI0_SPEED 1000*1000
#define SPI1_SPEED 500*1000

int test_size = 1  ; // hclee
unsigned char WriteData[64] = { 0x00, };
//**********************************************************************************

#define WHEREAMI() PRINTLOG("\r\n %s %d",__FILE__,__LINE__);
#define START printk("\r\n BEGIN TEST")
#define END    printk("\r\n END TEST")
#define FAIL  printk("\r\n FAIL")
#define TEST_MODE
extern int gPrintMode;
int gPrintOut = 0;
unsigned char w0p_answer[64] ={0x00, };
unsigned char w512p_answer[64] ={0x00, };
unsigned char wEndp_answer[64] ={0x00, };
unsigned char read_result[64] ={0x00, };
unsigned int cs = 1;
unsigned int LSFL_Init = 0x1d0f;
unsigned int NumOfIterEEPROM = 1;
unsigned int NumOfIterOKA = 1;
unsigned int NumOfIterPermission = 1;
unsigned int NumOfIterKEYLoad = 1;
unsigned int NumOfIterSHA = 1;
unsigned int NumofIterAll = 1;
int g_WRValue0 = -1;
int g_WRValue1 = -1;
int g_WRValue2 = -1;
int g_WRValue123 = 0;
unsigned int KL_TextSel = 0;
unsigned int KL_KeySel =0;                                   
unsigned int  KL_KeySaveSel  = 0;
unsigned int KEY_AES_CTRL = 0;
int OKAisFirst = 0;
int AriaIsFirst = 1;
int AesIsFirst = 1;
int Aes256 = 1;
int Aes128 = 1;
int Aria256 = 1;
int Aria128 = 1;
extern int gPrintOut;
unsigned int get_int();
unsigned int gTESTAllErrorCnt = 0;
unsigned int gTESTAllCnt =0 ;
unsigned char temp_buffer[256];
int g_ErrorCnt = 0;
extern unsigned char AESKey[16];
unsigned char SUPER_PW_CT[16] = {0xDC,0x44,0xB4,0x24,0xBC,0xB8,0x52,0x88,0xCE,0x3B,0xE4,0x24,0x30,0x86,0x4E,0x8B}; //77
unsigned char DETOUR_PW_CT[16] = {0x06,0xC8,0xD4,0x5B,0x62,0x8E,0xAE,0xA8,0xA3,0x0C,0x75,0x57,0x9F,0x32,0x12,0x11};	//88
unsigned char DESTROY0_PW_CT[16] = {0x3B,0x2E,0x01,0x68,0xEA,0xD4,0x6B,0xB6,0xA4,0x6F,0x0E,0x77,0xD5,0xA5,0x26,0x1E};//99	
unsigned char DESTROY1_PW_CT[16] = {0x3B,0xB5,0x28,0x7D,0x57,0x23,0x6B,0x36,0xE1,0x4B,0x01,0x2E,0xCA,0xC5,0x1A,0xA0};//aa
unsigned char EEPROM_PW_CT[16] = {0x45,0x4B,0xAE,0xE7,0x40,0xE8,0x3C,0x3D,0xE9,0x5C,0x62,0x02,0x1B,0x95,0x98,0x5B};//bb
unsigned char UID_PW_CT[16] = {0x6B,0x7A,0xE0,0x9F,0x86,0x05,0x88,0x19,0x23,0x1F,0xB3,0xB2,0x88,0x18,0x69,0x5C};//cc			
unsigned char *pPW_CT[6];

unsigned char OKA_TEXT[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00};
unsigned char KEY_GLOBAL_BUFFER[32];

int gFrameNumber = 0;
extern Serial_ Serial;

void printbyte(void *pData,int size );

int ReleaseSuperWirePERM();
int ReleasePermision();
int GetPermissionByPW(unsigned char * SUPER_PW_CT, int TYPE);
unsigned char SPI_Mode_Set(unsigned char m);
void SetZero_RG_SLEEP_TIMER();
unsigned char OpModeSet(void);
unsigned char crc_make_(unsigned char *crc);
void PrintHITMISS(int success);
void PrintPASSFAIL(int success);
int CheckEEBUF(void);
void PrintBuffer(int type, unsigned char *data, unsigned char *addr);
void endOP(void);
int OKA_CTRL(void);
void PrintCnt(int HitCnt, int MissCnt, int TotalCnt);
void KEY_SET(unsigned char *KEY);
void ReadStatusRegister();
void Reset(void);
void SetKEYNormal();
int LOCK_TEST();
int GetSuperWirePermission();
void SET_SPI0();

void GenINT0()
{
	INT0();

}

void printk(char *fmt, ... )
{

}

void delay_us(unsigned int us)	
{
	//printk("\r\n Delay");
	//delayMicroseconds(us*2);
	delayMicroseconds(us);
}
void Delay_us(unsigned int us)	
{
	//printk("\r\n Delay");
	//delayMicroseconds(us*2);
		delayMicroseconds(us);
}
void Delay_ms(unsigned int us)	
{
	//printk("\r\n Delay");
	//delayMicroseconds(us*1000*2);
	delayMicroseconds(us*1000);
}

void delay_ms(unsigned int i)
{
	//	Delay_ms(i*2);
	Delay_ms(i);
}

char get_char() 
{
	return getchar();
}
int fd0;
int fd1;
unsigned char tspi_interface(unsigned int cs, unsigned char inst, unsigned char *addr,unsigned char count, unsigned char opcode,unsigned char param0, unsigned char param1, unsigned char *tx_data, unsigned char *rx_data, int Byte_num)
{
	int addr_temp = 0;
	addr_temp = (addr[0] << 8) | addr[1]; 

	if(inst == 0x31 || inst == 0x30){// write
		spi_write(0,inst,addr_temp,Byte_num,tx_data);
		//printf("\r\n spi_write(fd,inst,addr_temp,Byte_num,tx_data)");
	}
    else{//read
    	spi_read(0,inst,addr_temp,Byte_num,rx_data);
		//printf("\r\n spi_read(fd,inst,addr_temp,Byte_num,rx_data)");    	
    }

}

char _uart_get_char()
{


}

void hexstr2bytes( char * str, uint8_t * result) {
	int i, n;
	char tmp[3] = "00";

	n=strlen(str)/2;
	for(i=0; i<n; i++)
	{
		memcpy(tmp, &str[i*2], 2);
		result[i] = (uint8_t) strtoul(tmp, NULL, 16);
	}

}

void printbyte(void *pData,int size ){

 int i = 0;
 char *Data = (char *)pData;
 //for( i = 0 ; i < size; i++)
 //	Serial.println(Data[i],HEX);

}

void printbyte2(unsigned char *pData,int size )
{
	
}

void printbyte_enc(unsigned char *pData,int size )
{

}



void END_OPERATION(void)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];	   
	int success = 1;

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		
	endOP();

}

#if 0
unsigned char crc_make( unsigned char count, unsigned char opcode, unsigned char param0, unsigned char param1, unsigned char *tx_data,unsigned char *crc);
#else
unsigned char crc_make( unsigned char count, unsigned char *tx_data,unsigned char *crc);
#endif
unsigned short crc16(unsigned short crcValue, unsigned char newByte); 
void PrintTime(int Score, int type)
{
	double temp = 128/(Score*30); // bps/us
	double temp2 =  temp;//bps/sec
	double dSpeed = 0;
	switch(type) {
	case AES128ENCODE :
		printk("  :AES-128-ENCRYPT");
		break;
	case AES128DECODE :
		printk("  :AES-128-DECRYPT");
		break;
	case AES256ENCODE :
		printk("  :AES-256-ENCRYPT");
		break;
	case AES256DECODE :
		printk("  :AES-256-DECRYPT");
		break;
	case ARIA128ENCODE:
		printk("  :ARIA-128-ENCRYPT");
		break;
	case ARIA128DECODE:
		printk("  :ARIA-128-DECRYPT");
		break;
	case ARIA256ENCODE:
		printk("  :ARIA-256-ENCRYPT");
		break;
	case ARIA256DECODE:
		printk("  :ARIA-256-DECRYPT");
	default:
		break;
	}
	printk("\n Operating time %d us",(int) (Score*32.87));
	dSpeed = (double)(128*1000*1)/(double)(Score*32.87);
	printk("\n %5.5fKbps",dSpeed);

}
unsigned char ucHEX_SET(unsigned char * data, int loop)
{
	int i, j;
	unsigned char temp;
	return 0;
	for(i=0; i<loop; i++)
	{
		data[i] = 0x00;

		printk(" 0x");

		for(j=1; j>=0; j--)
		{
			while(1)
			{		
				temp = 'z';
				temp = _uart_get_char();
				if(temp >= '0' && temp <= '9')
				{
					PRINTLOG("%c", temp);
					data[i] += (temp - 48) << (j * 4);
					break;
				}
				else if(temp >= 'A' && temp <= 'F')
				{
					PRINTLOG("%c", temp);
					data[i] += (temp - 55) << (j * 4);
					break;
				}
				else if(temp >= 'a' && temp <= 'f')
				{
					PRINTLOG("%c", temp);
					data[i] += (temp - 87) << (j * 4);
					break;
				}
				else if(temp =='x')
				{
					return 1;
					//break;
				}
				if(temp == 'x') return 1;
			}
		}
		if(temp == 'x') return 1;
	}

	printk("\r\n");
	return 0;
}

unsigned char OpModeSet(void)
{
#ifdef COMPARE

	unsigned int i;
	unsigned int inst = 0x00;
	unsigned char addr[2] = { 0x06, 0x04};
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}

	PRINTLOG("\r\n Set RG_ST0_OPMODE Start"); 

	inst = 0x31;
	tx_data[0] = 0x06;
	tspi_interface(cs, inst, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);



	inst = 0x21;
	addr[0] = 0x06; addr[1] = 0x01;
	tx_data[0] = 0x00;	
	tspi_interface(cs, inst, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	PRINTLOG("\r\n spi_rx_data    :"); for ( i=0; i<1; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_data[i]); }


	PRINTLOG("\r\n Set RG_ST0_OPMODE End"); 

	return 0;
#endif
}

unsigned char ADDR_NOR_MODE_WRITE_TEST()
{
#ifdef COMPARE

	unsigned int i;
	unsigned int inst = 0x00;
	unsigned char addr[2] = { 0x00, 0x00 };
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char test_data_64[64] = { 0xa0, 0xa7, 0x2d, 0x81, 0x24, 0x12, 0xef, 0x31, 0x25, 0xd2, 0x31, 0x0d, 0xc7, 0xa2, 0x15, 0x31,
		0xa4, 0x2b, 0x10, 0x56, 0x09, 0x25, 0xca, 0x41, 0xbe, 0x92, 0xf3, 0x15, 0x21, 0x3d, 0x90, 0xe5,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xdf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28
	}  ;

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}

	PRINTLOG("\r\n Set ADDR_NOR_MODE_WRITE Start"); 

	PRINTLOG("\r\n %dByte Data Write Start",test_size); 
	inst = 0x31;
	addr[0] = 0x05; addr[1] = 0x80; // hclee
#if 0
	for( i=0; i<test_size; i++) tx_data[i]= test_data_64[i];	
#else
	for( i=0; i<test_size; i++) tx_data[i] = rand();
	for( i=0; i<test_size; i++) WriteData[i] = tx_data[i];
#endif
	tspi_interface(cs, inst, addr, NULL, NULL, NULL, NULL, tx_data, rx_data, test_size);
	PRINTLOG("\r\n %dByte Data Write End",test_size); 

	PRINTLOG("\r\n Set ADDR_NOR_MODE_WRITE END"); 


	return 0;
#endif
}


unsigned char ADDR_NOR_MODE_READ_TEST()
{
#ifdef COMPARE

	unsigned int i;
	unsigned int inst = 0x00;
	unsigned char addr[2] = { 0x00, 0x00 };
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char answer_data_64[64] = { 0xa0, 0xa7, 0x2d, 0x81, 0x24, 0x12, 0xef, 0x31, 0x25, 0xd2, 0x31, 0x0d, 0xc7, 0xa2, 0x15, 0x31,
		0xa4, 0x2b, 0x10, 0x56, 0x09, 0x25, 0xca, 0x41, 0xbe, 0x92, 0xf3, 0x15, 0x21, 0x3d, 0x90, 0xe5,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xdf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28
	}  ;
	unsigned char test_flag = 0;

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}

	printk("\r\n Set ADDR_NOR_MODE_READ Start");

#if 0	
	PRINTLOG("\r\n 1Byte Data Read Start"); 
	inst = 0x21;
	//addr[0] = 0x02; addr[1] = 0x00;
	addr[0] = 0x08; addr[1] = 0x00;
	tx_data[0] = 0x00;	
	tspi_interface(cs, inst, addr, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	//              PRINTLOG("\r\n spi_rx_data    :"); for ( i=0; i<64; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_data[i]); }
	PRINTLOG("\r\n 1Byte Data Read End");

	PRINTLOG("\r\n 1Byte Data Read Start"); 
	inst = 0x21;
	//addr[0] = 0x02; addr[1] = 0x00;
	addr[0] = 0x08; addr[1] = 0x01;
	tx_data[0] = 0x00;	
	tspi_interface(cs, inst, addr, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	///	              PRINTLOG("\r\n spi_rx_data    :"); for ( i=0; i<64; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_data[i]); }
	PRINTLOG("\r\n 1Byte Data Read End");
#endif

	printk("\r\n %dByte Data Read Start",test_size); 
	inst = 0x21;
	addr[0] = 0x05; addr[1] = 0x80; // hclee
	//addr[0] = 0x08; addr[1] = 0x01;
	tx_data[0] = 0x00;	
	tspi_interface(cs, inst, addr, NULL, NULL, NULL, NULL, tx_data, rx_data, test_size);

	///	              PRINTLOG("\r\n spi_rx_data    :"); for ( i=0; i<64; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_data[i]); }
	printk("\r\n %dByte Data Read End",test_size);

#if 0
	for( i=0; i<test_size; i++) if( rx_data[i] != answer_data_64[i] ) test_flag = 1;
#else
	for( i=0; i<test_size; i++) if( rx_data[i] != WriteData[i] )
	{ 
		test_flag = 1; 
		//PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
		printk("\r\n write_data[%d] = 0x%02x, rx_data[%d] = 0x%02x", i,WriteData[i], i ,rx_data[i]);
		//PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	}
#endif	
	if(test_flag != 0) 
	{   
		printk("\r\n\n===========================================================");
		printk("\r\n test Fail !!!");
		printk("\r\n\n===========================================================\n");
		return 1;
	}
	else
	{
		printk("\r\n\n===========================================================");        
		printk("\r\n test Pass");         
		printk("\r\n\n===========================================================");
	}
	printk("\r\n Set ADDR_NOR_MODE_READ END");

	return 0;
#endif
}



unsigned short crc16(unsigned short crcValue, unsigned char newByte) 
{
#ifdef COMPARE

	unsigned char i;

	for (i = 0; i < 8; i++) {

		if (((crcValue & 0x8000) >> 8) ^ (newByte & 0x80)){
			crcValue = (crcValue << 1)  ^ POLYNOM;
		}else{
			crcValue = (crcValue << 1);
		}

		newByte <<= 1;
	}

	return crcValue;
#endif
}



unsigned char crc_make_(unsigned char *crc)
{
#ifdef COMPARE

	unsigned int crc_temp = LSFL_Init;
	unsigned int count = 0;
	unsigned char aux = 0;
	unsigned char input = 0;
#if 0
	unsigned char data[9] = { 0xc2,0xa2,0x15,0x0d,0x03,0x03,0x02,0x0b,0x01 } ;
#else
	unsigned char data[14] = { 0x10, 0xA7, 0x2D, 0x81, 0x24, 0x12, 0xEF, 0x31, 0x25, 0xD2, 0x31, 0x0D, 0xC7, 0xA2 } ;
#endif


	PRINTLOG("\r\n CRC Make Start " );

	count = sizeof(data);


	PRINTLOG("\r\n LFSR init = %x", LSFL_Init);

	while (aux < count)
	{
		crc_temp = crc16(crc_temp, data[aux]);
		aux++;
	}

	crc[0] = (unsigned char) (crc_temp >> 8);
	crc[1] = (unsigned char) (crc_temp & 0x00FF);

	PRINTLOG("\r\n CRC Make END " );
#endif
}

unsigned char crc_make( unsigned char cnt, unsigned char *data, unsigned char *crc)
{
#ifdef COMPARE

	int i;
	unsigned int crc_temp = LSFL_Init;
	unsigned int count = 0;
	unsigned char aux = 0;
	unsigned char input = 0;
#if 0
	unsigned char crc_data[9] = { 0xc2,0xa2,0x15,0x0d,0x03,0x03,0x02,0x0b,0x01 } ;
#elif 0
	unsigned char crc_data[14] = { 0x10, 0xA7, 0x2D, 0x81, 0x24, 0x12, 0xEF, 0x31, 0x25, 0xD2, 0x31, 0x0D, 0xC7, 0xA2 } ;
#elif 1
	unsigned char crc_data[64] = { 0x00, };
#endif

	PRINTLOG("\r\n CRC Make Start " );

	PRINTLOG("\r\n  CRC input txdata : ");
	for( i=0; i<(cnt-4); i++ ) PRINTLOG(" %02x", data[i]);


	//count = sizeof(data);
	count = cnt-2;
	PRINTLOG("\r\n count = %d", count);
	//PRINTLOG("\r\n LFSR init = %x", LSFL_Init);

	crc_data[0] = cnt;

	for( i=1; i< count; i++) crc_data[i] = data[i-1];

	PRINTLOG("\r\n make crc data : ");
	for( i=0; i<count; i++ ) PRINTLOG(" %02x", crc_data[i]);

	while (aux < count)
	{
		crc_temp = crc16(crc_temp, crc_data[aux]);
		aux++;
	}

	crc[0] = (unsigned char) (crc_temp >> 8);
	crc[1] = (unsigned char) (crc_temp & 0x00FF);

	PRINTLOG("\r\n CRC Make END " );
#endif
}


unsigned char CMD_NOR_MODE_WRITE_TEST()
{
#ifdef COMPARE
	unsigned int i;
	unsigned int inst = 0x00;
	unsigned char addr[2] = { 0x00, };
	unsigned char count,opcode,param0,param1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char test_data[10] = { 0x24, 0x12, 0xEF, 0x31, 0x25, 0xD2, 0x31, 0x0D, 0xC7, 0xA2 }; 

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}

	PRINTLOG("\r\n Set CMD_NOR_MODE_WRITE_TEST Start");

	// CMD data set
	count = 0x10; // 0x10 == 16bytes
	opcode = 0xA7;
	param0 = 0x2d;
	param1 = 0x81;
	//tx_data set
	for( i=0; i<sizeof(test_data); i++) tx_data[i] = test_data[i];

	inst = 0x11;
	addr[0] = 0x01; addr[1] = 0x00;
	tspi_interface (cs, inst, addr, count, opcode, param0, param1, tx_data, rx_data, 10);

	PRINTLOG("\r\n Set CMD_NOR_MODE_WRITE_TEST END");
#endif
}


unsigned char CMD_NOR_MODE_READ_TEST()
{
#ifdef COMPARE
	unsigned int i;
	unsigned int inst = 0x00;
	unsigned char addr[2] = { 0x00, 0x00 };
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}

	PRINTLOG("\r\n CMD_NOR_MODE_READ_TEST Start");

	PRINTLOG("\r\n 16Byte Data Read Start"); 
	inst = 0x01;
	addr[0] = 0x02; addr[1] = 0x00;
	//addr[0] = 0x08; addr[1] = 0x01;
	tx_data[0] = 0x00;	
	tspi_interface(cs, inst, addr, NULL, NULL, NULL, NULL, tx_data, rx_data, 12);

	PRINTLOG("\r\n spi_rx_data    :"); for ( i=0; i<64; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_data[i]); }

	PRINTLOG("\r\n 16Byte Data Read End");


	PRINTLOG("\r\n CMD_NOR_MODE_READ_TEST END");

	return 0;
#endif
}

void ClearBuffer(unsigned char * buf, int size)
{
	memset(buf,0,size);
}


int WriteRGEBUF(unsigned char *data)
{
#ifdef COMPARE
	int i;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	tx_data[0] = 0x0E;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = ST1_MEM_TEST_RG_EEBUF_WR;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_MEM_TEST_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	for(i = 0; i < 64 ; i++)
		tx_data[i] = data[i];
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF100, NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W, RG_ACCESS, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	return 0;
#endif
}


int eep_page_write(unsigned int msb, unsigned int lsb, unsigned char *data, unsigned char read_flag)
{
#if 1

	int i;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char rx_temp_buffer[64];	
	int j = 0;
	unsigned char temp_addr[2];
	int success = 1;
	for( i=0; i<64; i++)
	{
		tx_data[i] = 0; rx_data[i] = 0;
	}
	GetSuperWirePermission();
#if PRINTFMODE
	PRINTLOG("\r\n\n");
    Serial.println(__LINE__);
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       EEPROM Write Process Start                                    ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 

	//   PRINTLOG("\r\n call eep_page_write ");
	//RG_ST0_OPMODE -> ST0_MEM_TEST
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_ST0_OPMODE => 0x0E                              ==");
	PRINTLOG("\r\n=========================================================================");
#endif
    Serial.println(__LINE__);

	tx_data[0] = 0x0E;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef READ_RG	
	tspi_interface(cs, ADDR_NOR_R, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#endif
#if 0
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_R, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#endif    
	//RG_EET_CTRL -> EEPROM Test Mode Enable
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_EET_CTRL SET => 0x01                                       ==");
	PRINTLOG("\r\n=========================================================================");
#endif 
	tx_data[0] = 0x01;
    Serial.println(__LINE__);

	tspi_interface(cs, ADDR_NOR_W, RG_EET_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef READ_RG		
	tspi_interface(cs, ADDR_NOR_R, RG_EET_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#endif
    Serial.println(__LINE__);

	//RG_EET_OPMODE -> STEM_WRITE_MAIN_AUTO
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_EET_OPMODE SET => STEM_WRITE_MAIN_AUTO (0x0D)                    ==");
	PRINTLOG("\r\n=========================================================================");
#endif
	tx_data[0] = STEM_WRITE_MAIN_AUTO;//0xd
    Serial.println(__LINE__);


	tspi_interface(cs, ADDR_NOR_W, RG_EET_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef READ_RG		
	tspi_interface(cs, ADDR_NOR_R, RG_EET_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#endif

	//RG_EET_BYOB_LEN -> 64Bytes set
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_EET_BYOB_LEN SET => 64Bytes   (0x40)                             ==");
	PRINTLOG("\r\n=========================================================================");
#endif
	tx_data[0] = 64;
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_LEN, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef READ_RG		
	tspi_interface(cs, ADDR_NOR_R, RG_EET_BYOB_LEN, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#endif
    Serial.println(__LINE__);


	//RG_EET_BYOB_ADDR_LSB -> 0x0000
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_EET_BYOB_ADDR_LSB SET=> MSB : 0x%02x  LSB: 0x%02x             ==", msb, lsb);
	PRINTLOG("\r\n=========================================================================");
#endif
	tx_data[0] = lsb;
	tx_data[1] = msb;
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
#ifdef READ_RG		
	tspi_interface(cs, ADDR_NOR_R, RG_EET_BYOB_ADDR_LSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
#endif

    Serial.println(__LINE__);

	//RG_MEM_TEST_OPMODE -> ST1_MEM_TEST_EE_WRRD_EN
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_ST1_MEM_TEST_OPMODE SET => ST1_MEM_TEST_RG_EEBUF_WR  (0x02)           ==");
	PRINTLOG("\r\n=========================================================================");
#endif
#if 0
	tx_data[0] = ST1_MEM_TEST_EE_WRRD_EN;
#else
	tx_data[0] = ST1_MEM_TEST_RG_EEBUF_WR;
#endif
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_MEM_TEST_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef READ_RG		
	tspi_interface(cs, ADDR_NOR_R, RG_ST1_MEM_TEST_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#endif

    Serial.println(__LINE__);


	//RG_EEBUF100 -> 64bytes 0xff data write
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       EEPROM%02x%02x SET 64Bytes Write                                  ==",msb,lsb);
	PRINTLOG("\r\n=========================================================================");
#endif 
	j = 63;
	//    for( i=0; i<64; i++)tx_data[i] = TV0E0002_PAT0[j--];
	for( i=0; i<64; i++)tx_data[i] = data[i];

	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF100, NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	//tspi_interface(cs, ADDR_NOR_R, RG_EEBUF100, NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
    Serial.println(__LINE__);


#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_ST1_MEM_TEST_OPMODE  SET  ST1_MEM_TEST_EE_WR_EN(0x03)                             ==");
	PRINTLOG("\r\n=========================================================================");
#endif 

	tx_data[0] = ST1_MEM_TEST_EE_WR_EN;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_MEM_TEST_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef READ_RG		
	tspi_interface(cs, ADDR_NOR_R, RG_ST1_MEM_TEST_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#endif


#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       Delay : 8ms                                                  ==");
	PRINTLOG("\r\n=========================================================================");
#endif 
	delay_ms(8);

#if PRINTFMODE
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       EEPROM Write Process End                                      ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 
#if 0
	switch(msb)
	{
	case 0x00 : for(i=0; i<64; i++) w0p_answer[i] = tx_data[i]; break;
	case 0x80 : for(i=0; i<64; i++) w512p_answer[i] = tx_data[i]; break;
	case 0xff : for(i=0; i<64; i++) wEndp_answer[i] = tx_data[i]; break;
	}
#endif
	if(read_flag == 1) 
	{
		/*
		#if 0      
		#if PRINTFMODE
		PRINTLOG("\r\n=========================================================================");
		PRINTLOG("\r\n==       RG_EEBUF100 64Bytes Read                                       ==");
		PRINTLOG("\r\n=========================================================================");
		#endif 
		for( i=0; i<64; i++) tx_data[i] = 0x00;
		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF100, NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
		#endif    
		*/            
#if PRINTFMODE
		PRINTLOG("\r\n\n");
		PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
		PRINTLOG("\r\n==       EEPROM READ Process Start                                     ==");
		PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 


		//RG_MEM_TEST_OPMODE -> ST1_MEM_TEST_EE_WRRD_EN
#if PRINTFMODE
		PRINTLOG("\r\n=========================================================================");
		PRINTLOG("\r\n==       RG_ST1_MEM_TEST_OPMODE SET => ST1_MEM_TEST_STANDBY  (0x01)           ==");
		PRINTLOG("\r\n=========================================================================");
#endif
		tx_data[0] = ST1_MEM_TEST_STANDBY;
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_MEM_TEST_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef READ_RG		
		tspi_interface(cs, ADDR_NOR_R, RG_ST1_MEM_TEST_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#endif


#if PRINTFMODE
		PRINTLOG("\r\n=========================================================================");
		PRINTLOG("\r\n==       EEPROM%02x%02x 64Bytes Read                                       ==",msb,lsb);
		PRINTLOG("\r\n=========================================================================");
#endif 
		temp_addr[0] = msb;
		temp_addr[1] = lsb;	
		tspi_interface(cs, 0x20, temp_addr, NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
		memcpy(rx_temp_buffer,rx_data,64);
		delay_us(10);


	}
	endOP();
	delay_us(10);

/*
	PRINTLOG("\r\n================write data================");
	PRINTLOG("\r\n addr =%02x%02x",msb,lsb);
	PRINTLOG("\r\n spi_tx_data    :"); 
	for ( i=0; i<64; i++ )
	{ 
		if ( ( i !=0 ) & ( i % 16 == 0 ) )
			PRINTLOG("\n                 ");
		if( i % 4 == 0)
			PRINTLOG("|");
		PRINTLOG(" 0x%02x", data[i]); 
	} 	


	PRINTLOG("\r\n================read data================");
	PRINTLOG("\r\n addr =%02x%02x",msb,lsb);
	PRINTLOG("\r\n spi_rx_data    :"); //for ( i=0; i<64; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_temp_buffer[i]); } 
	for ( i=0; i<64; i++ )
	{ 
		if ( ( i !=0 ) & ( i % 16 == 0 ) )
			PRINTLOG("\n                 ");
		if( i % 4 == 0)
			PRINTLOG("|");
		PRINTLOG(" 0x%02x", rx_temp_buffer[i] ); 
	} 	
*/
	{
		//#if PRINTFMODE
		
		//#endif
		if(memcmp(data,rx_temp_buffer,64) != 0)
		{
					int temp2 = (msb << 8) | lsb;
			PRINTLOG("\r\n compare A_EEPROM and data");

			//#if PRINTFMODE
			printk("\r\n memcmp(data,rx_temp_buffer,64)  %d",memcmp(data,rx_temp_buffer,64) );
			PRINTLOG("\r\n FAIL TO WRITE addr %04x page number %d",temp2,temp2/64);

			PRINTLOG("\r\n WRITE DATA\r\n");
			printbyte(data,64);

			PRINTLOG("\r\n READ DATA\r\n");
			printbyte(rx_temp_buffer,64);
			//#endif

			Serial.println("\r\n================write data================");
			PRINTLOG("\r\n addr =%02x%02x",msb,lsb);
			Serial.println(msb,HEX);
    		Serial.println(lsb,HEX);
			Serial.println("\r\n spi_tx_data    :"); 
			for ( i=0; i<64; i++ )
			{ 
				if ( ( i !=0 ) & ( i % 16 == 0 ) )
					PRINTLOG("\n                 ");
				if( i % 4 == 0)
					PRINTLOG("|");
	    		Serial.println(data[i],HEX);				
			} 	


			PRINTLOG("\r\n================read data================");
			PRINTLOG("\r\n addr =%02x%02x",msb,lsb);
			Serial.println(msb,HEX);
    		Serial.println(lsb,HEX);			
			PRINTLOG("\r\n spi_rx_data    :"); //for ( i=0; i<64; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_temp_buffer[i]); } 
			for ( i=0; i<64; i++ )
			{ 
				if ( ( i !=0 ) & ( i % 16 == 0 ) )
					PRINTLOG("\n                 ");
				if( i % 4 == 0)
					PRINTLOG("|");
				PRINTLOG(" 0x%02x", rx_temp_buffer[i] ); 
	    		Serial.println(rx_temp_buffer[i],HEX);								
			} 	



			Serial.println("\r\n=========================================================================");
			Serial.println("\r\n==       FAIL TO WRITE   EEPROM                                 ==");
			Serial.println("\r\n=========================================================================");
			
			success = 0;
		}
		else
		{
			//						PRINTLOG("\r\n 1.1 EMCU->EEPROM 1.2 EEPROM->RG_EEBUF SUCCESS");
			Serial.println("\r\n=========================================================================");
			Serial.println("\r\n==       SUCCESS TO WRITE   EEPROM                                     ==");
			Serial.println("\r\n=========================================================================");
		}
	}
	ReleasePermision();
	return success;
#endif
}

int eep_all_page_write(unsigned char *data)
{
#ifdef COMPARE

	int i,j,iResult,k,MissCnt = 0,HitCnt = 0;
	int success = 1;
	printk("\r\n START eep_all_page_write");
	for(j = 0; j <= 0xffc0 ; j += 64)
	{
		int MSB = (j >> 8) & 0xFF;
		int LSB = j & 0xFF;

		iResult = eep_page_write(MSB, LSB,data, 1);
		printk("\r\n END of %dth iteration",i+1);								

		if(iResult == 0)
		{
			MissCnt++;printk("   FAIL");

		}
		else
		{
			printk("   PASS");
			HitCnt++;
		}
		END;
	}
	printk("\r\n 513 page 64bytes write test END");
	PrintCnt(HitCnt,MissCnt,0xffff/64);
	printk("\r\n END eep_all_page_write");						
	return 1;
#endif

}

int eep_page_read(unsigned int msb, unsigned int lsb,int compare, unsigned char *pData)
{
#if 1

	int i;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char fail_cnt = 0;
	unsigned char temp_addr[2] ;
	int index = 0;
	int success = 1;

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0; rx_data[i] = 0;
	}

	GetSuperWirePermission();
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_ST0_OPMODE SET -> 0x0E                           ==");
	PRINTLOG("\r\n=========================================================================");
#endif 
	tx_data[0] = 0x0E;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	tx_data[0] = ST1_MEM_TEST_STANDBY;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_MEM_TEST_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

#if 1


#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       EEPROM%02x%02x 64Bytes Read                                       ==",msb,lsb);
	PRINTLOG("\r\n=========================================================================");
#endif 
	temp_addr[0] = msb;
	temp_addr[1] = lsb;
	for( i=0; i<64; i++) tx_data[i] = 0x00;
	tspi_interface(cs, 0x20, temp_addr, NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	delay_us(10);
#if PRINTFMODE
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       EEPROM READ Process End                                       ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif
#endif    
	endOP();

	delay_us(10);
	ReleasePermision();
	if(compare)
	{
		switch(msb)
		{
		case 0x80 : for( i=0; i<64; i++) 
					{
						if(g_WRValue0 != rx_data[i]) fail_cnt++;
					}
					PRINTLOG("\r\n msb 0x%02x",msb);
					PRINTLOG("\r\nsaved value 0x%02x",g_WRValue0);
					break;
		case 0xDF : for( i=0; i<64; i++) 
					{
						if(g_WRValue1 != rx_data[i]) fail_cnt++;
					}
					PRINTLOG("\r\n msb 0x%02x",msb);
					PRINTLOG("\r\n saved value 0x%02x",g_WRValue1);
					break;
		case 0xFF : for( i=0; i<64; i++) 
					{
						if(g_WRValue2 != rx_data[i]) fail_cnt++;
					}
					PRINTLOG("\r\n msb 0x%02x",msb);
					PRINTLOG("\r\n saved value 0x%02x",g_WRValue2)	;
					break;				
		}	

	}
	for(i = 0; i < 64; i++)
	{
		read_result[i] = rx_data[i];
		if(pData != NULL)
			pData[i] = rx_data[i];
	}
	printk("\r\n TRSRST");
	{
		printk("\r\n addr =%02x%02x",msb,lsb);
		printk("\r\n================read data================");
		printk("\r\n spi_rx_data    :"); for ( i=0; i<64; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) printk("\n                 "); printk(" 0x%02x", rx_data[i]); } 

		if(fail_cnt != 0 )
		{
			printk("\r\n=========================================================================");
			printk("\r\n==       MISS TO READ                                       ==");
			printk("\r\n=========================================================================");
			success = 0;
		}
		else
		{
			if(compare == 1)
			{
				printk("\r\n=========================================================================");
				printk("\r\n==       HIT TO READ                                       ==");
				printk("\r\n=========================================================================");
			}
		}
	}

	return success;
#endif
}
void PrintCnt(int HitCnt, int MissCnt, int TotalCnt)
{
	printk("\r\n---------------------------------------------");
	printk("\r\nHIT Cnt : %d   MISS Cnt : %d    TOTAL Cnt : %d",HitCnt,MissCnt,TotalCnt);
	gTESTAllCnt++;
	if(MissCnt == 0)
		Serial.println(" PASS");
	else
		{
			printk("\r\n FAIL");
			gTESTAllErrorCnt++;
		}
	printk("\r\n---------------------------------------------");
}
#define ERROR_EXIT 0
unsigned char EE_WR_TEST_Main()
{
#if 1

	int i;
	int j;
	int k;
	unsigned char temp;
	unsigned char eeValue;	
	unsigned char w_data[1];
	int iResult = 0;
	int HitCnt = 0;
	int MissCnt = 0;
	unsigned char data_buf[64];
L_Start_block:
	while(1)
	{  
		Serial.println("\r\n\n");
		Serial.println("\r\n  *****************************************************");
		Serial.println("\r\n  *          EEPROM Write And Read TEST               *");
		Serial.println("\r\n  *****************************************************");
		//    PRINTLOG("\r\n  * i. EEPROM Write Read Mode Init                    *");
		//Serial.println("\r\n  * number of iteration     %d                          *",NumOfIterEEPROM);
		Serial.println("\r\n  * i. Input number of iteration                        *");
		Serial.println("\r\n  * q. 513 page 64bytes write test                      *");
		Serial.println("\r\n  * w. 513 page 64bytes read test                       *");
		Serial.println("\r\n  * e. 895 page 64bytes write test                      *");
		Serial.println("\r\n  * r. 895 page 64bytes read test                       *");
		Serial.println("\r\n  * a. 1023 page 64bytes write test                     *");
		Serial.println("\r\n  * s. 1023 page 64bytes read test                      *");
		Serial.println("\r\n  * d. XXXX page 64bytes wrtie & read test              *");
		Serial.println("\r\n  * f. XXXX page 64bytes read test                      *");		
		Serial.println("\r\n  * g. 513 page random value 64bytes wrtie & read test  *");		
		Serial.println("\r\n  * v. all pages random value 64bytes wrtie & read test  *");
		Serial.println("\r\n  * 1. Set All page as given value                     *");
#if 1
		//PRINTLOG("\r\n  * 1. 948 page 64bytes write test                    *");	
		//PRINTLOG("\r\n  * 0. 948 page 64bytes user value write test         *");	

		//    PRINTLOG("\r\n  * r. 123page 64bytes read test                      *");
#endif	
		Serial.println("\r\n  -----------------------------------------------------");
		Serial.println("\r\n  * m. Top Menu                                       *"); 
		Serial.println("\r\n  -----------------------------------------------------");
		Serial.println("\r\n  *****************************************************");  
		Serial.println("\r\n");
		Serial.println("Select :  ");
		temp = 'z' ;
		while (temp == 'z')
		{
				 HitCnt = 0;
				 MissCnt = 0;
				L_TEMP:
				//while(Serial.available()  == 0 );
				//Serial.println("Looping");
				if(Serial.available() > 0)
					temp = Serial.read();
				else
					goto L_TEMP;
	
				if ( temp != 'z' ) Serial.println( temp);
			switch ( temp )
			{
			case 'i' : 
				Serial.println("\r\n input number of iteration : (4digit)");
				Serial.println("\r\n 0x");
				NumOfIterEEPROM = get_int();
				NumOfIterEEPROM =( NumOfIterEEPROM<<8)| get_int();	
				break;
			case '1':
				Serial.println("\r\n all page 64bytes write test START");
				Serial.println("\r\n write data :");
				ucHEX_SET(w_data,1);  
				memset(data_buf,w_data[0],64);
				eep_all_page_write(data_buf);
				break;
			case 'q' :
				Serial.println("\r\n 513 page 64bytes write test START");
				Serial.println("\r\nInput write data :");
				ucHEX_SET(w_data,1);
				L_TEMP2:
				//while(Serial.available()  == 0 );
				//Serial.println("Looping");
				#if 1
				if(Serial.available() > 0)
					eeValue = Serial.read();
				else
					goto L_TEMP2;	
				Serial.println("Looping");
				Serial.println(eeValue,HEX);
				#endif
				Dorca3_SPI_Init(1000*1000);

				w_data[0] = eeValue;
				g_WRValue0 = w_data[0];			  
				memset(data_buf,w_data[0],64);
				Serial.println("Looping Start");
				for(i = 0; i < NumOfIterEEPROM; i++)
				{
					START;
					iResult = eep_page_write(0x80, 0x40,data_buf, 1);
					//Serial.println("\r\n END of %dth iteration",i+1);								

					if(iResult == 0)
					{
						MissCnt++;Serial.println("   FAIL");
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
						goto L_Start_block;
#endif
					}
					else
					{
						Serial.println("   PASS");
						HitCnt++;
					}
					END;
				}
				Serial.println("\r\n 513 page 64bytes write test END");
				PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
    			Dorca3_Close();
				break;


			case 'w' :
				Serial.println("\r\n 513 page 64bytes read test START");
				for(i = 0; i < NumOfIterEEPROM; i++)
				{
					START;
					iResult =	eep_page_read(0x80, 0x40,1,NULL); 
					//Serial.println("\r\n END of %dth iteration",i+1);								
					if(iResult == 0)
					{
						MissCnt++;Serial.println("   FAIL");
#if ERROR_EXIT
						PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
						goto L_Start_block;
#endif
					}					
					else
					{
						Serial.println("   PASS");					
						HitCnt++;
					}
					END;
				}
				Serial.println("\r\n 513 page 64bytes read test END");
				PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
				break;     
			case 'e' :  
				Serial.println("\r\n 895 page 64bytes write test START");
				Serial.println("\r\n write data :");
				ucHEX_SET(w_data,1);
				g_WRValue1 = w_data[0];
				memset(data_buf,w_data[0],64);				
				for(i = 0; i < NumOfIterEEPROM; i++)	
				{
					START;
					iResult = eep_page_write(0xDF, 0xC0,data_buf, 1); 
					//Serial.println("\r\n END of %dth iteration",i+1);								
					if(iResult == 0)
					{
						MissCnt++;Serial.println("   FAIL");
#if ERROR_EXIT
						PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
						goto L_Start_block;
#endif
					}					
					else
					{
						Serial.println("   PASS");					
						HitCnt++;
					}
					END;
				}		    
				Serial.println("\r\n 895 page 64bytes write test END");
				PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
				break;	   
			case 'r' : 
				Serial.println("\r\n 895 page 64bytes read test START");
				for(i = 0; i < NumOfIterEEPROM; i++)
				{
					iResult = eep_page_read(0xDF, 0xC0,1,NULL);
					//Serial.println("\r\n END of %dth iteration",i+1);								
					if(iResult == 0)
					{
						MissCnt++;Serial.println("   FAIL");
#if ERROR_EXIT
						PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
						goto L_Start_block;
#endif
					}
					else
					{
						Serial.println("   PASS");					
						HitCnt++;
					} 

				}
				Serial.println("\r\n 895 page 64bytes read test END");
				PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);					
				break;           
			case 'a' :  
				Serial.println("\r\n 1023 page 64bytes write test START");
				Serial.println("\r\n write data :");
				ucHEX_SET(w_data,1);
				g_WRValue2 = w_data[0];
				memset(data_buf,w_data[0],64);				
				for(i = 0; i < NumOfIterEEPROM; i++)			  
				{
					iResult = eep_page_write(0xFF, 0xC0, data_buf, 1);
					//Serial.println("\r\n END of %dth iteration",i+1);								
					if(iResult == 0)
					{
						MissCnt++;Serial.println("   FAIL");
#if ERROR_EXIT
						PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
						goto L_Start_block;
#endif
					}
					else
					{
						Serial.println("   PASS");					
						HitCnt++;
					}
				}		    
				Serial.println("\r\n 1023 page 64bytes write test END");
				PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);					
				break;
			case 's' : 
				Serial.println("\r\n 1023 page 64bytes read test START");
				for(i = 0; i < NumOfIterEEPROM; i++)	
				{
					iResult  = eep_page_read(0xFF, 0xC0,1,NULL);
					//Serial.println("\r\n END of %dth iteration",i+1);								
					if(iResult == 0)
					{
						MissCnt++;Serial.println("   FAIL");
#if ERROR_EXIT
						PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
						goto L_Start_block;
#endif
					}
					else
					{
						Serial.println("   PASS");					
						HitCnt++;
					}
				}		    
				Serial.println("\r\n 1023 page 64bytes read test END");
				PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);					
				break;   

			case 'd':
				{

					unsigned int MSB,LSB;
					Serial.println("\r\n XXXX page 64bytes wrtie & read test START");
					Serial.println("\r\n MSB 0x");
					MSB = get_int();
					Serial.println("\r\n LSB 0x");
					LSB = get_int();				
					Serial.println("\r\n write data :");
					ucHEX_SET(w_data,1);	
					for(i = 0; i < NumOfIterEEPROM; i++)	
					{

						memset(data_buf,w_data[0],64);
						iResult = eep_page_write(MSB,LSB,data_buf,1);
						//Serial.println("\r\n END of %dth iteration",i+1);								
						if(iResult == 0)
						{
							MissCnt++;Serial.println("   FAIL");
#if ERROR_EXIT
							PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
							goto L_Start_block;
#endif
						}
						else
						{
							Serial.println("   PASS");						
							HitCnt++;
						}
					}
					Serial.println("\r\n XXXX page 64bytes wrtie & read test END");
				}		    
				PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);					
				break;   

			case 'f':
				{
					unsigned int MSB,LSB;
					Serial.println("\r\n XXXX page 64bytes read test START");
					Serial.println("\r\n MSB 0x");
					MSB = get_int();
					Serial.println("\r\n LSB 0x");
					LSB = get_int();				
					for(i = 0; i < NumOfIterEEPROM; i++)	
					{

						iResult = eep_page_read(MSB,LSB,0,NULL);

						//Serial.println("\r\n END of %dth iteration",i+1);								
						if(iResult == 0)
						{
							MissCnt++;Serial.println("   FAIL");
#if ERROR_EXIT
							PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
							goto L_Start_block;
#endif
						}
						else
						{
							Serial.println("   PASS");						
							HitCnt++;
						}
					}		    
					Serial.println("\r\n XXXX page 64bytes read test END");
					PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);					
					break;   
				}		    
			case 'g':
				{
					Serial.println("\r\n 513 page random value 64bytes wrtie & read test START");
					for(i = 0; i < NumOfIterEEPROM; i++)
					{
						START;
						for(j = 0; j < 64; j++)
						{
							data_buf[j] = rand()&0xFF;
						}
						iResult = eep_page_write(0x80, 0x40,data_buf, 1);
						//Serial.println("\r\n END of %dth iteration",i+1);								

						if(iResult == 0)
						{
							MissCnt++;Serial.println("   FAIL");
#if ERROR_EXIT

							PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
							goto L_Start_block;
#endif
						}
						else
						{
							Serial.println("   PASS");
							HitCnt++;
						}
						END;

					}
					Serial.println("\r\n 513 page random value 64bytes wrtie & read test END");
					PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);					
					break;
				}
			case 'v':
				{
					Serial.println("\r\n  all page random value 64bytes wrtie & read test  START");
					for(i = 0; i < NumOfIterEEPROM; i++)
					{


						for(j = 0; j <= 0xffc0 ; j += 64)
						{
							int MSB = (j >> 8) & 0xFF;
							int LSB = j & 0xFF;
							START;
							srand(j);
							for(k = 0; k < 64; k++)
							{
								data_buf[k] = rand()&0xFF;
							}
							iResult = eep_page_write(MSB, LSB,data_buf, 1);
							//Serial.println("\r\n END of %dth iteration",i+1);								

							if(iResult == 0)
							{
								MissCnt++;Serial.println("   FAIL");
#if ERROR_EXIT

								PrintCnt(HitCnt,MissCnt,NumOfIterEEPROM);
								goto L_Start_block;
#endif
							}
							else
							{
								Serial.println("   PASS");
								HitCnt++;
							}
							END;
						}

					}
					Serial.println("\r\n  all page random value 64bytes wrtie & read test  END");
					PrintCnt(HitCnt,MissCnt,0xffc0/64*NumOfIterEEPROM);					
					break;
				}
			case 'm' : return 0;                   
			default : temp = 'p';
				break;
			}
		}
	}

	return 0;
#endif
}


unsigned char WRITE_TEST_F()
{

	unsigned int i;
	unsigned char inst = 0x00;
	unsigned char addr[2] = { 0x06, 0x04};
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}

	printk("\r\n Set RG_ST0_OPMODE Start"); 

	inst = 0x31;
	tx_data[0] = 0x0f;
	tspi_interface(cs, inst, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);



	inst = 0x21;
	addr[0] = 0x06; addr[1] = 0x01;
	tx_data[0] = 0x00;	
	tspi_interface(cs, inst, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	printk("\r\n spi_rx_data    :"); for ( i=0; i<1; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_data[i]); }


	printk("\r\n Set RG_ST0_OPMODE End"); 


	return 0;
}
unsigned char WRITE_TEST_5()
{

	unsigned int i;
	unsigned char inst = 0x00;
	unsigned char addr[2] = { 0x06, 0x04};
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}
	SetZero_RG_SLEEP_TIMER();
	printk("\r\n Set RG_AES_CTRL Start"); 

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tspi_interface(cs, ADDR_NOR_R, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	printk("\r\n Set RG_ST0_OPMODE Start"); 

	tx_data[0] = 0x05;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tspi_interface(cs, ADDR_NOR_R, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	printk("\r\n RG_RNDGEN_USER");

	tx_data[0] = 0x00;		  
	tspi_interface(cs, ADDR_NOR_W, RG_RNDGEN_USER, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tspi_interface(cs, ADDR_NOR_R, RG_RNDGEN_USER, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	//PRINTLOG("\r\n spi_rx_data    :"); for ( i=0; i<1; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_data[i]); }


	//PRINTLOG("\r\n Set RG_ST0_OPMODE End"); 


	return 0;
}

unsigned int get_int()
{
	unsigned int iResult = 0;
	int loop = 0;
	int i = 0;
	unsigned char ch;
	unsigned char converted_ch = 0;
	unsigned char converted_ch_array[4];

	//PRINTLOG("\r\n input number of digits :");
	//loop = get_char() - 0x30;
	//PRINTLOG("\r\n");

	for( i = 0; i < 2; i++)
	{
		ch = get_char();
		if(ch >= '0' && ch <= '9')
			converted_ch = ch - 0x30;

		if(ch >= 'A' && ch <= 'F')
			converted_ch = ch - 0x37;

		if(ch >= 'a' && ch <= 'f')
			converted_ch = ch - 0x57;
		converted_ch_array[i] = converted_ch;
		iResult = (iResult<<4) + converted_ch;
	}
	/*
	PRINTLOG("\r\n each digit");
	for(i = 0; i < 4; i++)
	{
	PRINTLOG("\r\n %x",converted_ch_array[i] );
	}
	*/
	//PRINTLOG("\r\n iResult 0x%04x",iResult);
	return iResult;

}

unsigned int get_a_int()
{
	unsigned int iResult = 0;
	int loop = 0;
	int i = 0;
	unsigned char ch;
	unsigned char converted_ch = 0;
	unsigned char converted_ch_array[4];

	//PRINTLOG("\r\n input number of digits :");
	//loop = get_char() - 0x30;
	//PRINTLOG("\r\n");

	for( i = 0; i < 1; i++)
	{
		ch = get_char();
		if(ch >= '0' && ch <= '9')
			converted_ch = ch - 0x30;

		if(ch >= 'A' && ch <= 'F')
			converted_ch = ch - 0x37;

		if(ch >= 'a' && ch <= 'f')
			converted_ch = ch - 0x57;
		converted_ch_array[i] = converted_ch;
		iResult = (iResult<<4) + converted_ch;
	}
	/*
	PRINTLOG("\r\n each digit");
	for(i = 0; i < 4; i++)
	{
	PRINTLOG("\r\n %x",converted_ch_array[i] );
	}
	*/
	//PRINTLOG("\r\n iResult 0x%04x",iResult);
	return iResult;

}
void RG_SLEEP_TIMER()
{
	unsigned int i;
	unsigned char inst = 0x00;
	unsigned char addr[2] = { 0x06, 0x04};
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char value0 = 0; 
	unsigned char value1 = 1; 
	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}

	printk("\r\n Set RG_SLEEP_TIMER Start"); 
	printk("\r\n input 0x10650 0x10651");
	printk("   0x");
	value0 = get_int()&0xff;
	printk("   0x");
	value1 = get_int()&0xff;
	printk("\r\nvalue0 0x%02x, value1 0x%02x",value0,value1);
	printk("\r\n wake up");
	printk("\r\nprint off");

	tx_data[0] = 0;




	inst = 0x31;
	tspi_interface(cs, inst, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	inst = 0x31;
	tx_data[0] = value0;
	tspi_interface(cs, inst, RG_SLEEP_TIMER_MSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	inst = 0x31;
	tspi_interface(cs, inst, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = value1;
	tspi_interface(cs, inst, RG_SLEEP_TIMER_LSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	inst = 0x21;
	tx_data[0] = 0x00;	


	inst = 0x31;
	tspi_interface(cs, inst, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	inst = 0x21;
	tspi_interface(cs, inst, RG_SLEEP_TIMER_MSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n ADDRESS 0x10650'S VALUE");
	printk("\r\n spi_rx_data    :"); for ( i=0; i<1; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_data[i]); }

	gPrintOut = 0;
	inst = 0x31;
	tspi_interface(cs, inst, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	gPrintOut = 1;
	inst = 0x21;
	tx_data[0] = 0x00;	
	tspi_interface(cs, inst, RG_SLEEP_TIMER_LSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n ADDRESS 0x10651'S VALUE");
	printk("\r\n spi_rx_data    :"); for ( i=0; i<1; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_data[i]); }	


}
void SetZero_RG_SLEEP_TIMER()
{
	unsigned int i;
	unsigned char inst = 0x00;
	unsigned char addr[2] = { 0x06, 0x04};
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char value0 = 0; 
	unsigned char value1 = 1; 
	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}
	printk("\r\n SetZero_RG_SLEEP_TIMER");
	printk("\r\nprint off");
	gPrintOut = 0;
	inst = 0x31;
	for(i = 0; i < 10; i++)
	tspi_interface(cs, inst, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	//gPrintOut = 1;
	//gPrintOut = 0;
	inst = 0x31;
	tx_data[0] = 0;
	tspi_interface(cs, inst, RG_SLEEP_TIMER_MSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	inst = 0x31;
	tx_data[0] = 0;
	tspi_interface(cs, inst, RG_SLEEP_TIMER_LSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	gPrintOut = 1;
	printk("\r\nprint on");
	inst = 0x21;
	tx_data[0] = 0x00;	
	printk("\r\n ADDRESS 0x10650'S VALUE");
	tspi_interface(cs, inst, RG_SLEEP_TIMER_MSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n spi_rx_data    :"); for ( i=0; i<1; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_data[i]); }

	inst = 0x21;
	tx_data[0] = 0x00;	
	printk("\r\n ADDRESS 0x10651'S VALUE");
	tspi_interface(cs, inst, RG_SLEEP_TIMER_LSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	printk("\r\n spi_rx_data    :"); for ( i=0; i<1; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) PRINTLOG("\n                 "); PRINTLOG(" 0x%02x", rx_data[i]); }	


}
void RG_SLEEP_TIMER_Menu()
{
	unsigned char temp ;
	while(1)
	{
		temp = 'z' ;
		printk("\r\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  *            RG_SLEEP_TIMER  TEST MAIN                                  *");
		printk("\r\n  *****************************************************");
		printk("\r\n  * 1. Set Timer's value as 0                                                     *");	
		printk("\r\n  * 2. Set Timer's value                                                            *");
		printk("\r\n  * m. return to top menu                                                         *");	
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n");

		printk("\r\n");
		printk("\r\n  * Select : ");
		while(temp == 'z')
		{
			temp = _uart_get_char();

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");

			if(temp == 'm')
			{
				printk("\r\nm is pressed");
				return;
			}

			switch ( temp )
			{

			case '1' : SetZero_RG_SLEEP_TIMER();
				break ;
			case '2' : RG_SLEEP_TIMER();
				break ;
			default : temp = 'z'; break;
			}
		}
	}

}


#define ITER_RAND_TEST 500*10000



#if 0

			case '2' : RG_SLEEP_TIMER();
				break ;
			default : temp = 'z'; break;
			}
		}
	}

}
#define ITER_RAND_TEST 500*10000
void GetRND()
{
	unsigned int i;
	int k = 0;
	int j = 0;
	int ii = 0;
	unsigned char inst = 0x00;
	unsigned char addr[2] = { 0x06, 0x04};
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char result[16];
	FILE *pFile = fopen("random_values","wt");
	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}


	inst = 0x31;
	tx_data[0] = 0x3;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);





	inst = 0x31;
	tx_data[0] = 0x8;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);





	inst = 0x31;
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_RNDGEN_USER, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	for( k  = 0; k  < ITER_RAND_TEST; k ++)
	{

		//fprintk(pFile,"\r\n");
        printk("*"); 
		for(j = 0; j < 16; j++) {
		inst = 0x31;
		tx_data[0] = 0x2;
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_RND_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		delay_us(2);
		inst = 0x21;
		tx_data[0] = 0x00;	
		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
		
		if( 0 == j) {
			  for(ii = 0; ii<16; ii++)
				 result[ii] = rx_data[ii];
		}
		else {
			  for(ii = 0; ii <16; ii++)
				 result[ii] ^= rx_data[ii];  	
		}
/*		
		printk("\r\n result");
		printbyte(result,16);
		printk("\r\n rx_data");
		printbyte(rx_data,16);
*/	
		inst = 0x31;
		tx_data[0] = 0x00;
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_RND_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		}
		for(ii = 0; ii < 16; ii++)
			fprintk(pFile,"%02X",result[ii]);
		
		fprintk(pFile,"\r\n");	

	}
    fclose(pFile);
	
	//tx_data[0] = 0x01;
	//tspi_interface(cs, ADDR_NOR_W, RG_ST1_RND_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();

}
#endif

void GetRND()
{
#ifdef COMPARE

	int toggle = 0;
	unsigned int i;
	int k = 0;
	int j = 0;
	int ii = 0;
	unsigned char inst = 0x00;
	unsigned char addr[2] = { 0x06, 0x04};
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char result[16];
	FILE *pFile = fopen("random_values","at");
	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}
	printk("\r\n COUNT %d \r\n",ITER_RAND_TEST);

	inst = 0x31;
	tx_data[0] = 0x3;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);





	inst = 0x31;
	tx_data[0] = 0x8;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);





	inst = 0x31;
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_RNDGEN_USER, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	for( k  = 0; k  < ITER_RAND_TEST; k ++)
	{

		//fprintk(pFile,"\r\n");
	//	toggle ^= 1;
    //    printk("\r%d",toggle); 

		inst = 0x31;
		tx_data[0] = 0x2;
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_RND_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		delay_us(2);
		inst = 0x21;
		tx_data[0] = 0x00;	
		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
		for( ii=  0; ii < 16; ii++)
		fprintk(pFile,"%02X",rx_data[ii]);	
		inst = 0x31;
		tx_data[0] = 0x00;
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_RND_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		fprintk(pFile,"\r\n");	

	}
    fclose(pFile);
	
	//tx_data[0] = 0x01;
	//tspi_interface(cs, ADDR_NOR_W, RG_ST1_RND_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
#endif
}

void SetMIDRCNT(int mode, unsigned char *pData)
{
#ifdef COMPARE

	int i;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	unsigned char temp_addr[2];
	int k = 0;

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0; rx_data[i] = 0;
	}

#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_ST0_OPMODE => 0x0B                             ==");
	PRINTLOG("\r\n=========================================================================");
#endif
	tx_data[0] = 0xB;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x01;		
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_MIDR_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	delay_us(110);



	memcpy(tx_data,pData,8);

	//    tspi_interface(cs, 0x30, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);

	//    tspi_interface(cs, 0x20, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);
	if(mode == 0)
	{
		tspi_interface(cs, 0x30, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);    
	}
	if(mode == 1)
	{
		tspi_interface(cs, 0x30, MIDR_CNT1 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);    
		//tspi_interface(cs, 0x20, MIDR_CNT1 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);	
	}

	inst = 0x20;	
	tspi_interface(cs,  ADDR_NOR_R, RG_ACCESS, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		 
	delay_ms(8);

	tx_data[0] = 0;

	tspi_interface(cs,  ADDR_NOR_W,   RG_ST1_MIDR_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		 

	endOP();
#endif
}
void SetMIDR_INCDEC(unsigned char data)
{
#ifdef COMPARE

	int i;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	unsigned char temp_addr[2];
	int k = 0;
	unsigned char Data[64];

	//	SetKEYNormal();

	pPW_CT[RG_PERM_SUPER_PASS ] = SUPER_PW_CT;
	pPW_CT[RG_PERM_DETOUR_PASS ] = DETOUR_PW_CT;
	pPW_CT[RG_PERM_DESTORY0_PASS ] = DESTROY0_PW_CT;
	pPW_CT[RG_PERM_DESTORY1_PASS] = DESTROY1_PW_CT;
	pPW_CT[RG_PERM_EEPROM_PASS] = EEPROM_PW_CT;
	pPW_CT[RG_PERM_UID_PASS] = UID_PW_CT;	
	GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
	//GetPermissionByPW(pPW_CT[RG_PERM_UID_PASS],RG_PERM_UID_PASS);
	for( i=0; i<64; i++)
	{
		tx_data[i] = 0; rx_data[i] = 0;
	}

#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_ST0_OPMODE => 0x07                             ==");
	PRINTLOG("\r\n=========================================================================");
#endif
	tx_data[0] = 0x07;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = A_MIDR[1];
	tx_data[1] = A_MIDR[0];
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(2);
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       WRITE 0x3 to MIDR_INCDEC 				                               ==");
	PRINTLOG("\r\n=========================================================================");
#endif	 
	inst = 0x20;	
	temp_addr[0] =0xed;
	temp_addr[1] =0x00;		
	//	tspi_interface(cs,  inst, temp_addr, NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	tx_data[0] = data;	
	inst = 0x30;	
	for(i = 0; i < 64; i++)
		tx_data[i] = rx_data[i];
	delay_ms(1);
	temp_addr[0] =0xed;
	//	temp_addr[1] =0x00;		
	temp_addr[1] =0x20;		
	tx_data[0] = data;
	tspi_interface(cs,  inst, temp_addr, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	delay_ms(8);

	endOP();
	delay_us(5);
	ReleasePermision();
#endif

}
void ReadMIDR_Region()
{
	//	GetSuperWirePermission();
	eep_page_read(0xED,0x0,0,NULL);	
	//	ReleasePermision();
}

void ResetMIDR_Region()
{
	unsigned char data[64] = { 0,};
	//GetSuperWirePermission();	
	eep_page_write(0xED,0x0,data,1);
	//ReleasePermision();	
}
void MIDR_TEST(void)
{
#ifdef COMPARE

	int i;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	unsigned char temp_addr[2];
	int k = 0;

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0; rx_data[i] = 0;
	}

#if PRINTFMODE
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       MIDR_TEST                                    ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 

	//   PRINTLOG("\r\n call eep_page_write ");
	//RG_ST0_OPMODE -> ST0_MEM_TEST
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_ST0_OPMODE => 0x0B                             ==");
	PRINTLOG("\r\n=========================================================================");
#endif
	tx_data[0] = 0xB;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       RG_ST1_MIDR_OPMODE => 0x1                             ==");
	PRINTLOG("\r\n=========================================================================");
#endif	
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_MIDR_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       delay_ms(16);// 				                               ==");
	PRINTLOG("\r\n=========================================================================");
#endif	 		
	delay_us(110);//

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0; rx_data[i] = 0;
	}


#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       WRITE 0x3 to MIDR_INCDEC 				                               ==");
	PRINTLOG("\r\n=========================================================================");
#endif	 
	tx_data[0] = 0;	
	inst = 0x30;	
	tspi_interface(cs,  inst, MIDR_INCDEC, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==      READ RG_ACCESS 				                               ==");
	PRINTLOG("\r\n=========================================================================");
#endif	 	
	tspi_interface(cs, ADDR_NOR_R, RG_ACCESS, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef PRINT_MODE	
	PRINTLOG("\r\n WAIT until clearing RSFLAG");   	
#endif	
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==       delay_ms(8);// 				                               ==");
	PRINTLOG("\r\n=========================================================================");
#endif	 		
	delay_ms(8);//

#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==      WRITE 0x00 RG_ST1_MIDR_OPMODE 				                               ==");
	PRINTLOG("\r\n=========================================================================");
#endif	 	
	tx_data[0] = 0x00;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_MIDR_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef PRINTFMODE		
	PRINTLOG("\r\n------------------- PAR I END-------------------");
#endif  	

	tx_data[0] = 0x01;	
#ifdef PRINTFMODE		
	PRINTLOG("\r\n 	READ 0xED00 ");
	eep_page_write(0xED,0x0,0,1);
	eep_page_read(0xED,0x0,0,NULL);	
#endif	

	PRINTLOG("\r\n------------------- PAR I END-------------------");

	tx_data[0] = 0x01;		
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_MIDR_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	delay_us(110);



	tspi_interface(cs, 0x20, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);	
	tspi_interface(cs, 0x20, MIDR_CNT1 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);	
	for( i=0; i<64; i++)
	{
		tx_data[i] = 0; rx_data[i] = 0;
	}

	tx_data[0] = 0xFF;		
	tx_data[1] = 0xFF;		
	//    tspi_interface(cs, 0x30, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);

	//    tspi_interface(cs, 0x20, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);	
	tspi_interface(cs, 0x30, MIDR_CNT1 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);

	tspi_interface(cs, 0x20, MIDR_CNT1 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);	





#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==      READ MIDR_INCDEC 				                               ==");
	PRINTLOG("\r\n=========================================================================");
#endif	 	
	inst = 0x20;	
	tspi_interface(cs,  ADDR_NOR_R, RG_ACCESS, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		 
	delay_ms(8);
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==      READ  MIDR_CNT0 				                               ==");
	PRINTLOG("\r\n=========================================================================");
#endif	 	

	tx_data[0] == 0;
	tspi_interface(cs,  ADDR_NOR_W,   RG_ST1_MIDR_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		 


	tx_data[0] = 0x01;		
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_MIDR_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	delay_us(110);



	tspi_interface(cs, 0x20, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);	
	tspi_interface(cs, 0x20, MIDR_CNT1 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);	

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0; rx_data[i] = 0;
	}

	tx_data[0] = 0xFF;				
	tx_data[1] = 0xFF;		
	//    tspi_interface(cs, 0x30, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);
	//    tspi_interface(cs, 0x20, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);	
	tspi_interface(cs, 0x30, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);

	tspi_interface(cs, 0x20, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);	





#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==      READ MIDR_INCDEC 				                               ==");
	PRINTLOG("\r\n=========================================================================");
#endif	 	
	inst = 0x20;	
	tspi_interface(cs,  ADDR_NOR_R, RG_ACCESS, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		 
	delay_ms(8);
#if PRINTFMODE
	PRINTLOG("\r\n=========================================================================");
	PRINTLOG("\r\n==      READ  MIDR_CNT0 				                               ==");
	PRINTLOG("\r\n=========================================================================");
#endif	 	

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] == 0;
	tspi_interface(cs,  ADDR_NOR_W,   RG_ST1_MIDR_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		 



#endif
}

int OKA_1FramePON_EE_OKA_OVERRIDE_1()
{
#ifdef COMPARE

	int i,j;
	unsigned int inst = 0x00;
	int success = 1;
	unsigned char addr[2] = { 0x00, 0x00 };
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char data[16];

	memset(tx_data,0,64);
	tx_data[4] = 0x03;
	if( OKAisFirst == 0)
	{
		printk("\r\n 	tx_data[4] = 0x03;");
		eep_page_write(0xEB,0x40, tx_data, 1);	
		OKAisFirst = 1;
	}

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_OKA_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x0A;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x02;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 15;

	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_KEYA0_A0051[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA0_A0051[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_KEYA1_A0051[j--];
	}		
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA4_0_A0051[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_CTA4_0_A0051,16) == 0)
		printk("\r\n PART II PASS");
	else
	{
		success = 0;
		printk("\r\n data");
		printbyte(data,16);
		printk("\r\n expected ");
		printbyte(AES_CTA4_0_A0051,16);			
		printk("\r\n PART II FAIL");	
	}

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_CTA4_1_A0051[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_PTA4_1_A0051,16) == 0)
		printk("\r\n PART III PASS");
	else
	{
		success = 0;

		printk("\r\n data");
		printbyte(data,16);	


		printk("\r\n expected ");
		printbyte(AES_PTA4_1_A0051,16);			
		printk("\r\n PART III FAIL");	
	}

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA4_2_A0051[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_CTA4_2_A0051,16) == 0)
		printk("\r\n PART 4 PASS");
	else
	{
		success = 0;

		printk("\r\n data");
		printbyte(data,16);
		printk("\r\n PART 4 FAIL"); 
	}

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
	return success;

#endif

}


void OKA_Test_Main(void)
{
#ifdef COMPARE
	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;

L_OKA_START:
	while(1)
	{
		temp = 'z' ;

		printk("\r\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  *            OKA     TEST MAIN                      *");
		printk("\r\n  *****************************************************");
		printk("\r\n  * number of iteration     %d                        *",NumOfIterOKA );
		printk("\r\n  * i. Input number of iteration                      *");
		printk("\r\n  * 1. oka one frame (TV0A0001)                       *");	
		printk("\r\n  * 2. oka two frame (TV0A0002)                       *");
		printk("\r\n  * 3. oka SW and HW cowork one frame                 *");
		printk("\r\n  * 4. oka SW and HW cowork two frame                 *");		
		printk("\r\n  * 5. oka ONE FRAME MODE EE_OKA_OVERRIDE_1 (TV0A0051)*");				

		//		printk("\r\n  * 5. oka one frame 1:0 (TV0A0051)                   *");				
		printk("\r\n  * m. return to top menu                             *");	
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n");

		printk("\r\n");
		printk("\r\n  * Select : ");

		while(temp == 'z')
		{
			int HitCnt = 0;
			int MissCnt = 0;
			temp = _uart_get_char();

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");
			if(temp == 0x0d)
				goto L_OKA_START;
			if(temp == 'm')
			{
				printk("\r\nm is pressed");
				return;
			}
			memset(tx_data,0,64);
			tx_data[4] = 0x02;
			printk("\r\n	tx_data[4] = 0x02;");
			eep_page_write(0xEB,0x40, tx_data, 1);
			OKAisFirst = 0;
			switch ( temp )
			{
			case 'i' : 
				printk("\r\n input number of iteration : (4digit)");
				printk("\r\n 0x");
				NumOfIterOKA = get_int();
				NumOfIterOKA =( NumOfIterOKA<<8)| get_int();		 
				break;

			case '1' : 
				printk("\r\n OKA ONE FRAME TEST BEGIN");
				for(i = 0; i < NumOfIterOKA;i++)
				{
					//	iResult = OKA_Test();
					START;
					iResult = OKA_Test_0613();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n OKA ONE FRAME TEST END");
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);


				break;
			case '2' :
				printk("\r\n OKA TWO FRAME TEST START");
				for(i = 0; i < NumOfIterOKA;i++)
				{
					START;
					iResult = OKA_Test2_0613();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n OKA TWO FRAME TEST END");				
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				break; 


			case '3':
				printk("\r\n OKA SW AND HW COWORK ONE FRAME TEST START");
				for(i = 0; i < NumOfIterOKA;i++)
				{
					//	iResult = OKA_Test();
					START;
					iResult = OKA_CTRL();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n OKA SW AND HW COWORK ONE FRAME TEST END");
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				break;
			case '4':
				printk("\r\n OKA SW AND HW COWORK TWO FRAME TEST START");
				for(i = 0; i < NumOfIterOKA;i++)
				{
					//	iResult = OKA_Test();
					START;
					iResult = OKA_CTRL2Frame();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n OKA SW AND HW COWORK TWO FRAME TEST END");
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				break;				
			case '5':
				printk("\r\n OKA_1FramePON_EE_OKA_OVERRIDE_1(); START");
				for(i = 0; i < NumOfIterOKA;i++)
				{
					START;
					iResult = OKA_1FramePON_EE_OKA_OVERRIDE_1();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n OKA_1FramePON_EE_OKA_OVERRIDE_1(); END");				
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);				

				break;

			default : temp = 'p'; break;
			}
			/*
			case '5':
			printk("\r\n oka one frame 1:0 (TV0A0051) TEST START");
			for(i = 0; i < NumOfIterOKA;i++)
			{
			//	iResult = OKA_Test();
			START;
			iResult = OKA_1Frame1_0();
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
			MissCnt++;FAIL;
			#if ERROR_EXIT

			END;
			PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
			goto L_Start_block;
			#endif
			}
			else
			{
			printk("   PASS");

			HitCnt++;
			}
			END;
			}
			printk("\r\n oka one frame 1:0 (TV0A0051) TEST END");
			PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
			break;				
			*/				


		}
	}
	#endif
}
void SetDATACfg(unsigned char *pData, unsigned char *addr)
{
	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;

	GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);


	tx_data[0] = 0x07;
	//	ReadStatusRegister();

	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE	  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = addr[1];// 0x00
	tx_data[1] = addr[0];// 0xeb
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);

	tspi_interface(cs, 0x30, addr	   , NULL, NULL, NULL, NULL, pData, rx_data, 64);
	PrintBuffer(TYPE_TX,pData,addr);
	delay_ms(8);
	tspi_interface(cs, 0x20, addr	   , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	delay_us(10);
	PrintBuffer(TYPE_RX,rx_data,addr);
	endOP();
	ReleasePermision();



}

void SetDATACfgIndex(int index,unsigned char *addr)
{
	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	unsigned char final_addr[2];
	unsigned char last_addr[2];
	int iAddr;	
	GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);

	iAddr = (addr[0] <<8) | addr[1];
	iAddr += 63;
	last_addr[0] = (iAddr>>8) &0xFF; 
	last_addr[1] =	iAddr &0xFF ;
	tx_data[0] = 0x07;
	//	ReadStatusRegister();

	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE	  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = final_addr[1] = addr[1];// 0x00
	tx_data[1] = final_addr[0] = addr[0];// 0xeb
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);
	tx_data[0] = 0xFF;
	final_addr[1] += index;
#if 1
	tspi_interface(cs, 0x30, final_addr	   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tspi_interface(cs, 0x30, last_addr	   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#else
	tspi_interface(cs, 0x30, addr	   , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
#endif

	//	PrintBuffer(TYPE_TX,pData,addr);
	printk("\r\n index 0x%02x WRITE 0x%02X ADDR[0] 0x%02x  ADDR[1] 0x%02x",index,tx_data[0], final_addr[0],final_addr[1]);
	printk("\r\n index 0x%02x WRITE 0x%02X ADDR[0] 0x%02x  ADDR[1] 0x%02x",index,tx_data[0], last_addr[0],last_addr[1]);	
	delay_ms(8);
	tspi_interface(cs, 0x20, addr	   , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	delay_us(10);
	//PrintBuffer(TYPE_RX,rx_data,addr);
	endOP();
	ReleasePermision();

	//ReadStatusRegister();


}

unsigned char LockBuffer[32];
int  LOCK_TEST(int index)
{
	int i,j;
	unsigned char tx_data[64];
	unsigned char Data[64];
	unsigned char Addr[2];
	unsigned char msb = 0xe9;
	unsigned char lsb = 0x00;
	//SetKEYNormal();
	printk("\r\n LOCK_TEST");
	memset(Data,0,64);
	Data[index] = 0xFF;
	Addr[0] = 0xEC;
	Addr[1] = 0x80;
	SetDATACfgIndex(index,Addr);
	//	SetDATACfg(Data,Addr);
}

void CLEAR_UZER_ZONE()
{
	int Page,SubPage;
	unsigned char Buffer[64];
	memset(Buffer,0,64);
	for(Page  = 1; Page  <= 0xF ; Page++)
	{
		for(SubPage = 0; SubPage < 4; SubPage++)
		{
			int PageAddress = 0xF000 + Page * 4* 64 + SubPage*64;
			int msb = (PageAddress>>8) & 0xFF;
			int lsb = PageAddress & 0xFF;
			eep_page_write(msb, lsb,Buffer,1);
		}
	}


}

void CFG_LOCK_Test_Main(void)
{
	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;

L_OKA_START:
	while(1)
	{
		temp = 'z' ;

		printk("\r\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  *            CFG_LOCK     TEST MAIN                 *");
		printk("\r\n  *****************************************************");
		printk("\r\n  * number of iteration     %d                        *",NumOfIterOKA );
		printk("\r\n  * i. Input number of iteration                      *");
		printk("\r\n  * 1. Setting LOCK                          *");	
		printk("\r\n  * 2. clear  USER ZONE                          *");	
		printk("\r\n  * 3. Direct INPUT                          *");	
		printk("\r\n  * m. return to top menu                                 *");	
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n");
		{
			unsigned char addr[2];
			SetKEYNormal();		
			GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);


			addr[0] = 0xEC;
			addr[1] = 0x80;
			tx_data[0] = 0x07;
			//	ReadStatusRegister();
			tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE	  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

			tspi_interface(cs, 0x20, addr	   , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
			delay_us(10);
			PrintBuffer(TYPE_RX,rx_data,addr);
			endOP();
			ReleasePermision();
			//ReadStatusRegister();
		}

		printk("\r\n");
		printk("\r\n  * Select : ");

		while(temp == 'z')
		{
			int HitCnt = 0;
			int MissCnt = 0;
			temp = _uart_get_char();

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");
			if(temp == 0x0d)
				goto L_OKA_START;
			if(temp == 'm')
			{
				printk("\r\nm is pressed");
				return;
			}
			switch ( temp )
			{
			case 'i' : 
				printk("\r\n input number of iteration : (4digit)");
				printk("\r\n 0x");
				NumOfIterOKA = get_int();
				NumOfIterOKA =( NumOfIterOKA<<8)| get_int();		 
				break;

			case '1' : 
				{
					int lock_index = 0;
					printk("\r\ninput lock address:");
					lock_index = get_int();
					LOCK_TEST(lock_index);
				}
				break;
			case '2' : 
				{
					CLEAR_UZER_ZONE();
				}
				break;	
			case '3' :
				{
					unsigned char Buffer[64];
					memset(Buffer,0,64);
					printk("input data : ");
					for(i = 0; i < 32 ; i++)
					{
						Buffer[i] = get_int();
						printk(",");

					}
					eep_page_write(0xec,0x80,Buffer,1);
				}
			case '4' :

				{
					unsigned char addr[2];
					GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);


					addr[0] = 0xEC;
					addr[1] = 0x80;
					tx_data[0] = 0x07;
					//	ReadStatusRegister();
					tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE	  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
					tx_data[0] = 0x80;// 0x00
					tx_data[1] = 0xEC;// 0xeb
					tspi_interface(cs, 0x20, addr	   , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
					delay_us(10);
					PrintBuffer(TYPE_RX,rx_data,addr);
					endOP();
					ReleasePermision();
				}
			default : temp = 'p'; break;
			}
		}
	}
}

int SAVE_KEY_REVERSE(int TYPE)
{
	int i;
	int success = 1;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char data[64];
	unsigned char rx_data[64];
	int j = 0;
	unsigned char temp_addr[2];
	unsigned char KEY_128_SUPER[16];//all 0x11
	unsigned char KEY_128_DETOUR[16];///all 0x22
	unsigned char KEY_128_DETORY0[16];//all 0x33
	unsigned char KEY_128_DETORY1[16];//all 0x44
	unsigned char KEY_128_EEPROM[16];// all 0x55
	unsigned char KEY_128_UID[16];//all 0x66	
	unsigned char *KEY_128;
	unsigned char  PW_SUPER[16] ;//all 0x77
	unsigned char  PW_DETOUR[16] ;//all 0x88
	unsigned char  PW_DETORY0[16];//all 0x99		
	unsigned char  PW_DETORY1[16];//all 0xaa
	unsigned char  PW_EEPROM[16] ;//all 0xbb
	unsigned char  PW_UID[16];//all 0xcc		
	unsigned char  *PW;
	int msb =0x00,lsb= 0x00;
	msb = ADDR_EE_KEY_AES_x0[0];
	lsb =  ADDR_EE_KEY_AES_x0[1];
	PRINTLOG("\r\n *************************************************************************");
	PRINTLOG("\r\n 	SAVE_KEY_REVERSE");
	PRINTLOG("\r\n *************************************************************************");	
	for( i=0; i<64; i++)
	{
		tx_data[i] = 0; 
		rx_data[i] = 0;
		data[i] = 0;
	}
	for( i = 0; i < 16; i++)
	{
		if(TYPE == RG_PERM_SUPER_PASS )
		{
			KEY_128_SUPER[i] = 0x11;
			PW_SUPER[i] = 0x77;
		}
		if(TYPE == RG_PERM_DETOUR_PASS )
		{
			KEY_128_DETOUR[i] = 0x11;
			PW_DETOUR[i] = 0x88;
		}
		if(TYPE == RG_PERM_DESTORY0_PASS )
		{
			KEY_128_DETORY0[i] = 0x11;
			PW_DETORY0[i] = 0x99;
		}
		if(TYPE == RG_PERM_DESTORY1_PASS )
		{
			KEY_128_DETORY1[i] = 0x11;
			PW_DETORY1[i] = 0xaa;
		}
		if(TYPE == RG_PERM_EEPROM_PASS )
		{
			KEY_128_EEPROM[i] = 0x11;
			PW_EEPROM[i] = 0xbb;
		}
		if(TYPE == RG_PERM_UID_PASS )
		{
			KEY_128_UID[i] = 0x11;
			PW_UID[i] = 0xcc;
		}
	}

	if(TYPE == RG_PERM_SUPER_PASS )
	{
		KEY_128 =KEY_128_SUPER;
		PW = PW_SUPER;
	}
	if(TYPE == RG_PERM_DETOUR_PASS )
	{
		KEY_128 =KEY_128_DETOUR;
		PW = PW_DETOUR;
	}
	if(TYPE == RG_PERM_DESTORY0_PASS )
	{
		KEY_128 = KEY_128_DETORY0;
		PW = PW_DETORY0;
	}
	if(TYPE == RG_PERM_DESTORY1_PASS )
	{
		KEY_128 = KEY_128_DETORY1;
		PW = PW_DETORY1;
	}
	if(TYPE == RG_PERM_EEPROM_PASS )
	{
		KEY_128 = KEY_128_EEPROM;
		PW = PW_EEPROM;
	}
	if(TYPE == RG_PERM_UID_PASS )
	{
		KEY_128 = KEY_128_UID;
		PW = PW_UID;
		PRINTLOG("\r\n RG_PERM_UID_PASS %d",__LINE__);
	}


	j = 15;
	for( i=16; i<32; i++)
		//for( i=0; i<16; i++)
	{
		tx_data[i] = KEY_128[j--];
	}
	if(eep_page_write(msb, lsb,tx_data, 1) )
	{
		PRINTLOG("\r\n 1 EE_KEY_AES_x0 setting HIT");

	}
	else
	{
		success = 0;
	}
	for( i=0; i<64; i++)
	{
		tx_data[i] = 0; rx_data[i] = 0;
	}
	j = 15;
	for(i = 0; i <16;i++)
		tx_data[i] = PW[j--];
	if(TYPE == RG_PERM_SUPER_PASS )
	{
		msb = ADDR_SUPER_PW[0];
		lsb = ADDR_SUPER_PW[1];
		PRINTLOG("\r\n enter RG_PERM_SUPER_PASS");
		eep_page_write(ADDR_SUPER_PW_CNT_PAGE[0],ADDR_SUPER_PW_CNT_PAGE[1],data,1);
		//eep_page_write(0xef,0x80,data,1);
	}
	if(TYPE == RG_PERM_DETOUR_PASS )
	{
		msb = ADDR_DETOUR_PW[0];
		lsb = ADDR_DETOUR_PW[1];
		eep_page_write(ADDR_DETOUR_PW_CNT_PAGE[0],ADDR_DETOUR_PW_CNT_PAGE[1],data,1);
		//		eep_page_write(0xef,0xC0,data,1);		
	}
	if(TYPE == RG_PERM_DESTORY0_PASS )
	{
		msb = ADDR_DESTORY0_PW[0];
		lsb = ADDR_DESTORY0_PW[1];
		eep_page_write(ADDR_DESTORY0_PW_CNT_PAGE[0],ADDR_DESTORY0_PW_CNT_PAGE[1],data,1);
		//		eep_page_write(0xf0,0x00,data,1);		
	}
	if(TYPE == RG_PERM_DESTORY1_PASS )
	{
		msb = ADDR_DESTORY1_PW[0];
		lsb = ADDR_DESTORY1_PW[1];
		eep_page_write(ADDR_DESTORY1_PW_CNT_PAGE[0],ADDR_DESTORY1_PW_CNT_PAGE[1],data,1);
		//		eep_page_write(0xf0,0x40,data,1);		
	}
	if(TYPE == RG_PERM_EEPROM_PASS )
	{
		msb = ADDR_EEPROM_PW[0];
		lsb = ADDR_EEPROM_PW[1];
		eep_page_write(ADDR_EEPROM_PW_CNT_PAGE[0],ADDR_EEPROM_PW_CNT_PAGE[1],data,1);
		//		eep_page_write(0xf0,0x80,data,1);		
	}
	if(TYPE == RG_PERM_UID_PASS )
	{
		msb = ADDR_UID_PW[0];
		lsb = ADDR_UID_PW[1];
		eep_page_write(ADDR_UID_PW_CNT_PAGE[0],ADDR_UID_PW_CNT_PAGE[1],data,1);
		PRINTLOG("\r\n RG_PERM_UID_PASS %d",__LINE__);		
		//		eep_page_write(0xf0,0xC0,data,1);		
	}
	if(eep_page_write(msb, lsb,tx_data, 1) )
	{
		PRINTLOG("\r\n 2 PW setting HIT");
	}
	else
	{
		success = 0;
	}

	PRINTLOG("\r\n *************************************************************************");
	PRINTLOG("\r\n END 	SAVE_KEY_REVERSE");
	PRINTLOG("\r\n *************************************************************************");	
	return success;

}
#define TEST_COUNT_ON 1
int GetPermissionByPW(unsigned char * SUPER_PW_CT, int TYPE)
{
	int i;
	int result = 1;
	unsigned int inst = 0;
	int PERM_TYPE = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	unsigned char temp_addr[2];
	int k = 0;
	int success = 0;
	for(i = 0; i < 64; i++)
	{
		tx_data[i] = 0;
		rx_data[i] = 0;
	}


#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       PERMISSION   TEST                                    ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 
#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET  RG_EE_KEY_AES_CTRL AS 0                                    ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET  RG_AES_CTRL AS 0x3                                   ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = 0x03;	
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET  RG_PERM_GET_CTRL AS 0                                   ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = TYPE;	
	tspi_interface(cs, ADDR_NOR_W, RG_PERM_GET_CTRL , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET  RG_ST0_OPMODE AS 0x0C                                   ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = 0x0C;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		
	tx_data[0] = 0x00;	
	tspi_interface(cs, ADDR_NOR_W, RG_PERM_GET_EE_RD_PRE_SP , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		
	delay_ms(16);
#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       Delay 16MS                                   ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 		


#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET  RG_ST2_SYMCIP_OPMODE AS 0x03                                  ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = 0x03;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       Delay 30US                                   ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 		
	delay_us(30);

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET  RG_ST2_SYMCIP_OPMODE AS 0x01                                  ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = 0x01;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET  RG_ST2_SYMCIP_OPMODE AS 0x04                                  ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = 0x04;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	j = 15;
	for(i = 0 ; i < 16; i++)
	{
		tx_data[i] = SUPER_PW_CT[j--];	

	}
	PRINTLOG("\r\n !!!!!!! PASS WD  !!!!!!!");
	printbyte(tx_data,16);
#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET  RG_EEBUF400 BY CIPHER TEXT                                  ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 		
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400 , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET  RG_ST2_SYMCIP_OPMODE AS 0x01                                  ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = 0x01;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       wait 16MS                                  ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	delay_ms(16);

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       READ RG_PERM_GET_CTRL1                             ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	rx_data[0] = 0;	
	tspi_interface(cs, ADDR_NOR_R, RG_PERM_GET_CTRL1 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		
	PRINTLOG("\r\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	//  PRINTLOG("PERM_TYPE %d",TYPE);
	switch (TYPE) 
	{

	case RG_PERM_SUPER_PASS:
		PERM_TYPE = 1 << 5;
		temp_addr[0] = ADDR_SUPER_PW_CNT[0];
		temp_addr[1] = ADDR_SUPER_PW_CNT[1];
		if( (rx_data[0] & PERM_TYPE) == 0)
		{
			result = 0;
#if TEST_COUNT_ON 	
			PRINTLOG("\r\nMISS TO GET SUPER_PERMISSION");
#endif
		}
		else{
#if TEST_COUNT_ON  	
			PRINTLOG("\r\n**HIT TO GET SUPER_PERMISSION");
			PRINTLOG("\r\n rx_data %02x  %02x",rx_data[0],PERM_TYPE);
#endif
		}
		break;
	case RG_PERM_DETOUR_PASS:
		PERM_TYPE = 1 << 4;
		temp_addr[0] = ADDR_DETOUR_PW_CNT[0];
		temp_addr[1] = ADDR_DETOUR_PW_CNT[1];
		if( (rx_data[0] & PERM_TYPE) == 0)
		{
			result = 0;
#if TEST_COUNT_ON			
			PRINTLOG("\r\nMISS TO GET DETOUR_PERMISSION");
#endif
		}
		else
		{
#if TEST_COUNT_ON	       
			PRINTLOG("\r\nHIT TO GET DETOUR_PERMISSION");
#endif
		}

		break;

	case RG_PERM_DESTORY0_PASS:
		PERM_TYPE = 1 << 3;
		temp_addr[0] = ADDR_DESTORY0_PW_CNT[0];
		temp_addr[1] = ADDR_DESTORY0_PW_CNT[1];
		if( (rx_data[0] & PERM_TYPE) == 0)
		{
			result = 0;
#if TEST_COUNT_ON			
			PRINTLOG("\r\nMISS TO GET DESTORY0_PERMISSION");
#endif		
		}
		else
		{
#if TEST_COUNT_ON	       
			PRINTLOG("\r\nHIT TO GET DESTORY0_PERMISSION");
#endif
		}

		break;


	case RG_PERM_DESTORY1_PASS:
		PERM_TYPE = 1 << 2;		
		temp_addr[0] = ADDR_DESTORY1_PW_CNT[0];
		temp_addr[1] = ADDR_DESTORY1_PW_CNT[1];
		if( (rx_data[0] & PERM_TYPE) == 0)
		{
			result = 0;
#if TEST_COUNT_ON			
			PRINTLOG("\r\nMISS TO GET DESTORY1_PERMISSION");
#endif
		}
		else
		{
#if TEST_COUNT_ON	       
			PRINTLOG("\r\nHIT TO GET DESTORY1_PERMISSION");
#endif
		}

		break;

	case RG_PERM_EEPROM_PASS:
		PERM_TYPE = 1 << 1;				
		temp_addr[0] = ADDR_EEPROM_PW_CNT[0];
		temp_addr[1] = ADDR_EEPROM_PW_CNT[1];
		if( (rx_data[0] & PERM_TYPE) == 0)
		{
			result = 0;
#if TEST_COUNT_ON			
			PRINTLOG("\r\nMISS TO GET EEPROM_PERMISSION");
#endif
		}
		else
		{
#if TEST_COUNT_ON	       
			PRINTLOG("\r\nHIT TO GET EEPROM_PERMISSION");
#endif
		}
		break;

	case RG_PERM_UID_PASS:
		PERM_TYPE = 1 ;					
		temp_addr[0] = ADDR_UID_PW_CNT[0];
		temp_addr[1] = ADDR_UID_PW_CNT[1];		
		if( (rx_data[0] & PERM_TYPE) == 0)
		{
			result = 0;
#if TEST_COUNT_ON			
			PRINTLOG("\r\nMISS TO GET UID_PERMISSION");
#endif
		}
		else
		{
#if TEST_COUNT_ON
			PRINTLOG("\r\nHIT TO GET UID_PERMISSION");
#endif
		}
		break;

	default:
		PRINTLOG("\r\nPERM TYPE ERROR %d",PERM_TYPE);
		break;

	}

	PRINTLOG("\r\n GetPermResult 0x%02x",rx_data[0]);


	inst = 0x20; 	 

	tspi_interface(cs, inst, temp_addr , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		
	PRINTLOG("\r\n temp_addr 0x%02x%02x",temp_addr[0],temp_addr[1]);
	g_ErrorCnt = rx_data[0];

	switch (TYPE) 
	{

	case RG_PERM_SUPER_PASS:
		PRINTLOG("\r\n EE_SUPER_PW_CNT");
		break;
	case RG_PERM_DETOUR_PASS:
		PRINTLOG("\r\n EE_DETOUR_PW_CNT");		
		break;
	case RG_PERM_DESTORY0_PASS:
		PRINTLOG("\r\n EE_DESTORY0_PW_CNT");		
		break;
	case RG_PERM_DESTORY1_PASS:
		PRINTLOG("\r\n EE_DESTORY1_PW_CNT");		
		break;
	case RG_PERM_EEPROM_PASS:
		PRINTLOG("\r\n EE_EEPROM_PW_CNT");		
		break;
	case RG_PERM_UID_PASS:
		PRINTLOG("\r\n EE_UID_PW_CNT");		
		break;

	default:
		PRINTLOG("\r\nPERM TYPE ERROR %d",PERM_TYPE);
		break;

	}

	PRINTLOG(" %d",rx_data[0]);



	switch (TYPE) 
	{

	case RG_PERM_SUPER_PASS:

		if(rx_data[0] != 0)
		{
			result = 0;
#if TEST_COUNT_ON
			PRINTLOG("\r\nMISS TO GET SUPER_PERMISSION");
#endif
		}
		else
		{
#if TEST_COUNT_ON
			PRINTLOG("\r\nHIT TO GET SUPER_PERMISSION");
#endif
		}

		break;
	case RG_PERM_DETOUR_PASS:
		if(rx_data[0] != 0)
		{
			result = 0;
#if TEST_COUNT_ON
			PRINTLOG("\r\nMISS TO GET DETOUR_PERMISSION");
#endif
		}
		else
		{
#if TEST_COUNT_ON
			PRINTLOG("\r\nHIT TO GET DETOUR_PERMISSION");
#endif
		}

		break;

	case RG_PERM_DESTORY0_PASS:
		if(rx_data[0] != 0)
		{
			result = 0;
#if TEST_COUNT_ON
			PRINTLOG("\r\nMISS TO GET DESTORY0_PERMISSION");
#endif
		}
		else
		{
#if TEST_COUNT_ON
			PRINTLOG("\r\nHIT TO GET DESTORY0_PERMISSION");
#endif
		}

		break;


	case RG_PERM_DESTORY1_PASS:
		if(rx_data[0] != 0)
		{
			result = 0;
#if TEST_COUNT_ON
			PRINTLOG("\r\nMISS TO GET DESTORY1_PERMISSION");
#endif
		}
		else
		{
#if TEST_COUNT_ON
			PRINTLOG("\r\nHIT TO GET DESTORY1_PERMISSION");
#endif
		}

		break;

	case RG_PERM_EEPROM_PASS:
		if(rx_data[0] != 0)
		{
			result = 0;
#if TEST_COUNT_ON
			PRINTLOG("\r\nMISS TO GET EEPROM_PERMISSION");
#endif
		}
		else
		{
#if TEST_COUNT_ON
			PRINTLOG("\r\nHIT TO GET EEPROM_PERMISSION");
#endif
		}

		break;

	case RG_PERM_UID_PASS:

		if(rx_data[0] != 0)
		{
			result = 0;
#if TEST_COUNT_ON
			PRINTLOG("\r\nMISSTO GET UID_PERMISSION");
#endif
		}
		else
		{
#if TEST_COUNT_ON
			PRINTLOG("\r\nHIT TO GET UID_PERMISSION");
#endif
		}

		break;

	default:
		PRINTLOG("\r\nPERM TYPE ERROR");
		break;

	}    
#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");	
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET RG_ST0_OPMODE AS 0x01                            ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = 0x01;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);			

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET RG_ACCESS AS 0                            ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = 0;	
	tspi_interface(cs, ADDR_NOR_W, RG_ACCESS , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);			
	delay_us(5);
	return result;

}
int ReleasePermision()
{
	int success = 1;
	int i;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	unsigned char temp_addr[2];
	int k = 0;

	delay_us(5);
	endOP();
	//ReadStatusRegister();
#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET RG_ST0_OPMODE AS 0x0C                            ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = 0x0C;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);			

	//tx_data[0] = 0x0;	
	//tspi_interface(cs, ADDR_NOR_W, RG_PERM_GET_EE_RD_PRE_SP , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	//delay_ms(16);


#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       SET RG_PERM_RELEASE AS 0x1                            ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	tx_data[0] = 0x0;	
	tspi_interface(cs, ADDR_NOR_W, RG_PERM_RELEASE , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       READ RG_PERM_GET_CTRL1                            ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 	
	delay_us(5);
	tx_data[0] = 0;	
	tspi_interface(cs, ADDR_NOR_R, RG_PERM_GET_CTRL1 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);			

	if(rx_data[0] != 0 )
	{
		PRINTLOG("\r\n MISS TO RELEASE PERMISSION 0x%02x", rx_data[0]);
		success = 0;
		Serial.println("\r\n MISS TO RELEASE PERMISSION");		

	}
	else
	{
		Serial.println("\r\n HIT TO RELEASE PERMISSION");

	}

	return success;

}

int PERMISSION_TEST(int TYPE)
{
#ifdef COMPARE

	int i;
	unsigned int inst = 0;
	int pass = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	unsigned char temp_addr[2];
	unsigned char msb;

	unsigned char lsb;
	int k = 0;
	//	unsigned char SUPER_PW_CT[16] = {0xCF,0xCD,0xEA,0x4B,0xBC,0x6B,0x74,0x6A,0xED,0x57,0xA2,0x71,0x2B,0xCE,0x88,0xE6};
	unsigned char SUPER_PW_CT[16] = {0xDC,0x44,0xB4,0x24,0xBC,0xB8,0x52,0x88,0xCE,0x3B,0xE4,0x24,0x30,0x86,0x4E,0x8B}; //77
	unsigned char DETOUR_PW_CT[16] = {0x06,0xC8,0xD4,0x5B,0x62,0x8E,0xAE,0xA8,0xA3,0x0C,0x75,0x57,0x9F,0x32,0x12,0x11};	//88
	unsigned char DESTROY0_PW_CT[16] = {0x3B,0x2E,0x01,0x68,0xEA,0xD4,0x6B,0xB6,0xA4,0x6F,0x0E,0x77,0xD5,0xA5,0x26,0x1E};//99	
	unsigned char DESTROY1_PW_CT[16] = {0x3B,0xB5,0x28,0x7D,0x57,0x23,0x6B,0x36,0xE1,0x4B,0x01,0x2E,0xCA,0xC5,0x1A,0xA0};//aa
	unsigned char EEPROM_PW_CT[16] = {0x45,0x4B,0xAE,0xE7,0x40,0xE8,0x3C,0x3D,0xE9,0x5C,0x62,0x02,0x1B,0x95,0x98,0x5B};//bb
	unsigned char UID_PW_CT[16] = {0x6B,0x7A,0xE0,0x9F,0x86,0x05,0x88,0x19,0x23,0x1F,0xB3,0xB2,0x88,0x18,0x69,0x5C};//cc			
	unsigned char* PW_CT;
	unsigned char SUPER_PW_CT_Wrong[16];

	PRINTLOG("\r\n\r\n\r\n\r\n\r\n");
	//GetSuperWirePermission();
	SAVE_KEY_REVERSE(TYPE);	

	switch (TYPE)
	{
	case RG_PERM_SUPER_PASS :
		printk("\r\n PERMISSION TEST RG_PERM_SUPER_PASS");
		break;
	case RG_PERM_DETOUR_PASS:
		printk("\r\n PERMISSION TEST RG_PERM_DETOUR_PASS");
		break;
	case RG_PERM_DESTORY0_PASS:
		printk("\r\n PERMISSION TEST RG_PERM_DESTORY0_PASS");
		break;
	case RG_PERM_DESTORY1_PASS:
		printk("\r\n PERMISSION TEST RG_PERM_DESTORY1_PASS");
		break;
	case RG_PERM_EEPROM_PASS:
		printk("\r\n PERMISSION TEST RG_PERM_EEPROM_PASS");
		break;	
	case RG_PERM_UID_PASS:
		printk("\r\n PERMISSION TEST RG_PERM_UID_PASS");
		break;	
	default:
		PRINTLOG("\r\n WORNG PERMISSION TYPE %d",TYPE);
	}


	//gPrintOut = 1;
	eep_page_read(0xe9,00,0,NULL);
	memset(tx_data,0,64);

	//gPrintOut = 1;
	if(TYPE == RG_PERM_SUPER_PASS )
	{
		msb = ADDR_SUPER_PW[0];
		lsb = ADDR_SUPER_PW[1];
		PW_CT = SUPER_PW_CT;

	}
	if(TYPE == RG_PERM_DETOUR_PASS )
	{
		msb = ADDR_DETOUR_PW[0];
		lsb = ADDR_DETOUR_PW[1];
		PW_CT = DETOUR_PW_CT;

	}
	if(TYPE == RG_PERM_DESTORY0_PASS )
	{
		msb = ADDR_DESTORY0_PW[0];
		lsb = ADDR_DESTORY0_PW[1];
		PW_CT = DESTROY0_PW_CT;		

	}
	if(TYPE == RG_PERM_DESTORY1_PASS )
	{
		msb = ADDR_DESTORY1_PW[0];
		lsb = ADDR_DESTORY1_PW[1];
		PW_CT = DESTROY1_PW_CT;				

	}
	if(TYPE == RG_PERM_EEPROM_PASS )
	{
		msb = ADDR_EEPROM_PW[0];
		lsb = ADDR_EEPROM_PW[1];
		PW_CT = EEPROM_PW_CT;

	}
	if(TYPE == RG_PERM_UID_PASS )
	{
		msb = ADDR_UID_PW[0];
		lsb = ADDR_UID_PW[1];
		PW_CT = UID_PW_CT;

	}		 



	eep_page_read(msb,lsb,0,NULL);
	//ReleasePermision();

	//gPrintOut = 0;
	g_ErrorCnt  = 0;
	if(GetPermissionByPW(PW_CT,TYPE) == 0)
	{
		pass = 0;
		PRINTLOG("\r\nMiss to get first Permission ");
		//goto L_EXIT_FAIL;
	}
	ReleasePermision();

	for(j = 0; j < 2; j++)
	{

		for(i = 0 ; i < 16; i++)
			SUPER_PW_CT_Wrong[i]  = j;

		if(GetPermissionByPW(SUPER_PW_CT_Wrong,TYPE) ==1)
		{
			pass = 0;
			//goto L_EXIT_FAIL;

		}
		if(g_ErrorCnt != (j+1) )		
		{
			PRINTLOG("\r\n CNT missmatch  CNT %d  expected %d   %d",g_ErrorCnt , (j+1),__LINE__);
			//goto L_EXIT_FAIL;
		}

	}
	if(g_ErrorCnt == 2)
	{
		PRINTLOG("\r\n  CNT HIT   %d",g_ErrorCnt);
	}
	else
	{
		PRINTLOG("\r\n  CNT MISS  expected 2  result %d",g_ErrorCnt ,__LINE__);
		pass = 0;
	}

	if(GetPermissionByPW(PW_CT,TYPE) == 0)
	{
		pass = 0;
		//goto L_EXIT_FAIL;
	}
	ReleasePermision();
	if(g_ErrorCnt == 0)
	{
		//		PRINTLOG("\r\n error cnt pass %d",__LINE__);
		PRINTLOG("\r\n  CNT HIT   %d",__LINE__);
	}
	else
	{
		PRINTLOG("\r\n CNT MISS  %d",__LINE__);
		pass = 0;
	}

	for(j = 0; j < 10; j++)
	{

		for(i = 0 ; i < 16; i++)
			SUPER_PW_CT_Wrong[i]  = j;

		if(GetPermissionByPW(SUPER_PW_CT_Wrong,TYPE) ==1)
		{
			pass = 0;
			if(g_ErrorCnt != (j+1) )		
			{
				PRINTLOG("\r\n CNT missmatch  CNT %d  expected %d   %d",g_ErrorCnt , (j+1),__LINE__);
				//goto L_EXIT_FAIL;
			}

		}
	}
	if(g_ErrorCnt == 10){
		PRINTLOG("\r\n CNT HIT 10");
	}
	else
	{
		PRINTLOG("\r\n CNT MISS expected 10 result %d",g_ErrorCnt);
		pass = 0;
	}
	if(  GetPermissionByPW(PW_CT,TYPE) == 1)
	{
		pass = 0;
		//goto L_EXIT_FAIL;

	}
	if(g_ErrorCnt == 10){
		PRINTLOG("\r\n CNT HIT 10");

	}
	else
	{
		PRINTLOG("\r\n CNT MISS expected 10 result %d",g_ErrorCnt);
		pass = 0;
	} 
	//gPrintOut = 1;

L_EXIT_FAIL:
	if(pass)
	{
		PRINTLOG("\r\nTEST Permssion PASS");    
		return 1;
	}

	else
	{
		PRINTLOG("\r\nTEST Permssion FAIL");
		return 0;
	}
 #endif
}
int ChangePW(int TYPE)
{
#ifdef COMPARE

	int i;
	unsigned int inst = 0;
	int pass = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	unsigned char temp_addr[2];
	unsigned char msb;
	unsigned char lsb;
	int k = 0;
	unsigned char SUPER_PW_CT[16] = {0xDC,0x44,0xB4,0x24,0xBC,0xB8,0x52,0x88,0xCE,0x3B,0xE4,0x24,0x30,0x86,0x4E,0x8B}; //77
	unsigned char DETOUR_PW_CT[16] = {0x06,0xC8,0xD4,0x5B,0x62,0x8E,0xAE,0xA8,0xA3,0x0C,0x75,0x57,0x9F,0x32,0x12,0x11};	//88
	unsigned char DESTORY0_PW_CT[16] = {0x3B,0x2E,0x01,0x68,0xEA,0xD4,0x6B,0xB6,0xA4,0x6F,0x0E,0x77,0xD5,0xA5,0x26,0x1E};//99	
	unsigned char DESTORY1_PW_CT[16] = {0x3B,0xB5,0x28,0x7D,0x57,0x23,0x6B,0x36,0xE1,0x4B,0x01,0x2E,0xCA,0xC5,0x1A,0xA0};//aa
	unsigned char EEPROM_PW_CT[16] = {0x45,0x4B,0xAE,0xE7,0x40,0xE8,0x3C,0x3D,0xE9,0x5C,0x62,0x02,0x1B,0x95,0x98,0x5B};//bb
	unsigned char UID_PW_CT[16] = {0x6B,0x7A,0xE0,0x9F,0x86,0x05,0x88,0x19,0x23,0x1F,0xB3,0xB2,0x88,0x18,0x69,0x5C};//cc
	unsigned char *PW_CT;
	unsigned char SUPER_PW_CHANGE_CT[16] = {0x3B,0xB5,0x28,0x7D,0x57,0x23,0x6B,0x36,0xE1,0x4B,0x01,0x2E,0xCA,0xC5,0x1A,0xA0};   //aa
	unsigned char DETOUR_PW_CHANGE_CT[16] = {0x45,0x4B,0xAE,0xE7,0x40,0xE8,0x3C,0x3D,0xE9,0x5C,0x62,0x02,0x1B,0x95,0x98,0x5B}; //bb
	unsigned char DESTORY0_PW_CHANGE_CT[16]={0x6B,0x7A,0xE0,0x9F,0x86,0x05,0x88,0x19,0x23,0x1F,0xB3,0xB2,0x88,0x18,0x69,0x5C}; //cc
	unsigned char DESTORY1_PW_CHANGE_CT[16] = {0x53,0x77,0x35,0xB4,0x67,0xEB,0x91,0xED,0x06,0x77,0xD5,0x46,0x3D,0x51,0xEF,0x22}; //dd
	unsigned char EEPROM_PW_CHANGE_CT[16] = {0x24,0xE0,0x8A,0x84,0xE6,0xD1,0xC9,0xFD,0x10,0x4A,0x2B,0xEB,0x32,0xD7,0x83,0xD5}; //ee
	unsigned char UID_PW_CHANGE_CT[16] = {0x88,0x28,0x0B,0x2C,0xD6,0xD2,0x93,0x6D,0x95,0x7A,0x77,0x95,0x40,0x1F,0x74,0x45};	//ff
	unsigned char *PW_CHANGE_CT;
	unsigned char SUPER_PW_CHANGE_PT[16];   //aa
	unsigned char DETOUR_PW_CHANGE_PT[16]; //bb
	unsigned char DESTORY0_PW_CHANGE_PT[16]; //cc
	unsigned char DESTORY1_PW_CHANGE_PT[16]; //dd
	unsigned char EEPROM_PW_CHANGE_PT[16]; //ee
	unsigned char UID_PW_CHANGE_PT[16];	//ff
	unsigned char *PT;
	for(i = 0; i < 16 ; i++)
	{
		SUPER_PW_CHANGE_PT[i] = 0xaa;   //aa
		DETOUR_PW_CHANGE_PT[i] = 0xbb; //bb
		DESTORY0_PW_CHANGE_PT[i] = 0xcc; //cc
		DESTORY1_PW_CHANGE_PT[i] = 0xdd; //dd
		EEPROM_PW_CHANGE_PT[i] = 0xee; //ee
		UID_PW_CHANGE_PT[i] = 0xff;	
	}

	switch (TYPE)
	{
	case RG_PERM_SUPER_PASS :
		printk("\r\n ChangePW TEST RG_PERM_SUPER_PASS");
		PW_CT = SUPER_PW_CT;
		PW_CHANGE_CT = SUPER_PW_CHANGE_CT;
		PT = SUPER_PW_CHANGE_PT;
		break;
	case RG_PERM_DETOUR_PASS:
		printk("\r\n ChangePW TEST RG_PERM_DETOUR_PASS");

		PW_CT = DETOUR_PW_CT;
		PW_CHANGE_CT = DETOUR_PW_CHANGE_CT;
		PT = DETOUR_PW_CHANGE_PT;		
		break;
	case RG_PERM_DESTORY0_PASS:
		printk("\r\n ChangePW TEST RG_PERM_DESTORY0_PASS");
		PW_CT = DESTORY0_PW_CT;
		PW_CHANGE_CT = DESTORY0_PW_CHANGE_CT;
		PT = DESTORY0_PW_CHANGE_PT;		
		break;
	case RG_PERM_DESTORY1_PASS:
		printk("\r\n ChangePW TEST RG_PERM_DESTORY1_PASS");
		PW_CT = DESTORY1_PW_CT;
		PW_CHANGE_CT = DESTORY1_PW_CHANGE_CT;
		PT = DESTORY1_PW_CHANGE_PT;	
		break;
	case RG_PERM_EEPROM_PASS:
		printk("\r\n ChangePW TEST RG_PERM_EEPROM_PASS");
		PW_CT = EEPROM_PW_CT;
		PW_CHANGE_CT = EEPROM_PW_CHANGE_CT;
		PT = EEPROM_PW_CHANGE_PT;	
		break;	
	case RG_PERM_UID_PASS:
		printk("\r\n ChangePW TEST RG_PERM_UID_PASS");
		PW_CT = UID_PW_CT;
		PW_CHANGE_CT = UID_PW_CHANGE_CT;
		PT = UID_PW_CHANGE_PT;			
		break;	
	default:
		PRINTLOG("\r\n WORNG PERMISSION TYPE %d",TYPE);
	}
	//GetSuperWirePermission();
	SAVE_KEY_REVERSE(TYPE);
	//eep_page_write(0xE9, 0x00, 0xFF, 1);
	//gPrintOut = 1;


	if(TYPE == RG_PERM_SUPER_PASS )
	{
		msb = ADDR_SUPER_PW[0];
		lsb =ADDR_SUPER_PW[1];
	}
	if(TYPE == RG_PERM_DETOUR_PASS )
	{
		msb = ADDR_DETOUR_PW[0];
		lsb = ADDR_DETOUR_PW[1];
	}
	if(TYPE == RG_PERM_DESTORY0_PASS )
	{
		msb = ADDR_DESTORY0_PW[0];
		lsb = ADDR_DESTORY0_PW[1];
	}
	if(TYPE == RG_PERM_DESTORY1_PASS )
	{
		msb = ADDR_DESTORY1_PW[0];
		lsb = ADDR_DESTORY1_PW[1];
	}
	if(TYPE == RG_PERM_EEPROM_PASS )
	{
		msb = ADDR_EEPROM_PW[0];
		lsb = ADDR_EEPROM_PW[1];
	}
	if(TYPE == RG_PERM_UID_PASS )
	{
		msb = ADDR_UID_PW[0];
		lsb = ADDR_UID_PW[1];
	}		 

	eep_page_read(msb,lsb,0,NULL);
	//ReleasePermision();
	//gPrintOut = 0;
	GetPermissionByPW(PW_CT,TYPE);
	delay_ms(100);
	GetPermissionByPW(PW_CHANGE_CT,TYPE);
	delay_ms(100);
	//gPrintOut = 1;
	/*
	if(TYPE == RG_PERM_SUPER_PASS )
	{
	msb = 0xED;
	lsb = 0x80;
	}
	if(TYPE == RG_PERM_DETOUR_PASS )
	{
	msb = 0xED;
	lsb = 0xC0;
	}
	if(TYPE == RG_PERM_DESTORY0_PASS )
	{
	msb = 0xEE;
	lsb = 0x00;
	}
	if(TYPE == RG_PERM_DESTORY1_PASS )
	{
	msb = 0xEE;
	lsb = 0x40;
	}
	if(TYPE == RG_PERM_EEPROM_PASS )
	{
	msb = 0xEE;
	lsb = 0x80;
	}
	if(TYPE == RG_PERM_UID_PASS )
	{
	msb = 0xEE;
	lsb = 0xC0;
	}
	*/
	delay_ms(100);
	ReleasePermision();
	//GetSuperWirePermission();
	eep_page_read(msb,lsb,0,NULL);

	if(memcmp(read_result,PT,6) == 0)
	{
		PRINTLOG("\r\nChange password PASS");
		return 1;
	}
	else
	{
		PRINTLOG("\r\nChange password FAIL");
		return 0;
	}
#endif
}


void PERMISSION_TEST_MENU()
{
#if 1

	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	int j = 0;


	unsigned int inst = 0;
	int pass = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int HitCnt,MissCnt;
	unsigned char temp_addr[2];
	unsigned char msb;
	unsigned char lsb;
	unsigned char Data[64];

	memset(Data,0,64);
	j = 15;
	for( i=16; i<32; i++)
		//for( i=0; i<16; i++)
	{
		tx_data[i] = 0x11;
	}
	//	unsigned char SUPER_PW_CT[16] = {0x0F,0x9C,0x00,0x4B,0x2C,0xB0,0x97,0xE6,0xF6,0x7A,0x8F,0x6F,0x34,0x76,0x11,0x17};
	pPW_CT[RG_PERM_SUPER_PASS ] = SUPER_PW_CT;
	pPW_CT[RG_PERM_DETOUR_PASS ] = DETOUR_PW_CT;
	pPW_CT[RG_PERM_DESTORY0_PASS ] = DESTROY0_PW_CT;
	pPW_CT[RG_PERM_DESTORY1_PASS] = DESTROY1_PW_CT;
	pPW_CT[RG_PERM_EEPROM_PASS] = EEPROM_PW_CT;
	pPW_CT[RG_PERM_UID_PASS] = UID_PW_CT;	
	//	SetKEYNormal();

L_Start_block:
	while(1)
	{
		temp = 'z' ;

		printk("\r\n");
		printk("\r\n  *********************************************************");
		printk("\r\n  *            Permission     TEST MAIN                   *");
		printk("\r\n  *********************************************************");
		printk("\r\n  * number of iteration     %d                            *",NumOfIterPermission );
		printk("\r\n  * i. Input number of iteration                          *");
		printk("\r\n  * 1. Supper Permission TEST  (500000)                   *");	
		printk("\r\n  * 2. DETOUR Permission TEST (500001)                    *");	
		printk("\r\n  * 3. DESTORY0 Permission TEST (500002)                  *");	
		printk("\r\n  * 4. DESTORY1 Permission TEST (500003)                  *");	
		printk("\r\n  * 5. EEPROM Permission TEST  (500004)                   *");	
		printk("\r\n  * 6. UID Permission TEST     (500005)                   *");	
		printk("\r\n  * 7. Supper Permission Password change TEST   (500006)  *");	
		printk("\r\n  * 8. DETOUR Permission Password change TEST (500007)    *");	
		printk("\r\n  * 9. DESTORY0 Permission Password change TEST (500008)  *");	
		printk("\r\n  * a. DESTORY1 Permission Password change TEST (500009)  *");	
		printk("\r\n  * s. EEPROM Permission Password change TEST  (500010)   *");	
		printk("\r\n  * d. UID Permission Password change TEST        (500011)*");	
		printk("\r\n  * q. Get  Supper Permission                             *");
		printk("\r\n  * w. Get  DETOUR Permission                             *");	 
		printk("\r\n  * e. Get  DESTORY0 Permission                           *");		 
		printk("\r\n  * r. Get  DESTORY1 Permission                           *");		 	 
		printk("\r\n  * t. Get  EEPROM Permission                             *");	 
		printk("\r\n  * y. Get  UID Permission                                *");	 	 
		printk("\r\n  * x. Get  All Permission  (500018)                      *");	 	 	 
		printk("\r\n  * c. release Permssion                                  *");	 	 
		printk("\r\n  * v. check Permssion                                    *");	
		printk("\r\n  * b. key load                                           *");		
		printk("\r\n  * u. Get And Release XXXX  Permission                   *");
		printk("\r\n  * o. Get SuperWire  Permission                          *");
		printk("\r\n  * p. Release SuperWire  Permission                      *");	

		printk("\r\n  * k. TEST ALL MANU 1000                      *");			
		printk("\r\n  * m. return to top menu                                 *");	
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n");

		printk("\r\n");
		printk("\r\n  * Select : ");


		while(temp == 'z')
		{
			temp = _uart_get_char();

			if(temp == 0x0d)
				goto L_Start_block;

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");

			if(temp == 'm')
			{
				printk("\r\nm is pressed");
				return;
			}
			HitCnt = 0;
			MissCnt = 0;
			switch ( temp )
			{
			case 'i' : 
				printk("\r\n input number of iteration : (4digit)");
				printk("\r\n 0x");
				NumOfIterPermission = get_int();
				NumOfIterPermission = (NumOfIterPermission<<8) | get_int();				 
				break;

			case '1' : 
				printk("\r\n SUPER PERM TEST BEGIN");				
				for(i = 0; i < NumOfIterPermission;i++)
				{
					//for(j = 0; j < 6; j++)
					START;
					iResult = PERMISSION_TEST(RG_PERM_SUPER_PASS );
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				printk("\r\n SUPER PERM TEST END");				
				goto L_Start_block;
				break;
			case '2' : 
				printk("\r\n DETOUR PERM TEST BEGIN");				
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;
					//for(j = 0; j < 6; j++)
					iResult =  PERMISSION_TEST(RG_PERM_DETOUR_PASS );
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				printk("\r\n DETOUR PERM TEST END");				
				goto L_Start_block;
				break;
			case '3' : 
				printk("\r\n DESTORY0 PERM TEST BEGIN");				
				for(i = 0; i < NumOfIterPermission;i++)
				{
					//for(j = 0; j < 6; j++)
					START;
					iResult =  PERMISSION_TEST(RG_PERM_DESTORY0_PASS );
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				printk("\r\n DESTORY0 PERM TEST END");									
				goto L_Start_block;				
				break;

			case '4' : 
				printk("\r\n DESTORY1 PERM TEST BEGIN");														
				for(i = 0; i < NumOfIterPermission;i++)
				{
					//for(j = 0; j < 6; j++)
					START;
					iResult =  PERMISSION_TEST(RG_PERM_DESTORY1_PASS );
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);			
				printk("\r\n DESTORY1 PERM TEST END");														
				goto L_Start_block;
				break;
			case '5' : 
				printk("\r\n EEPROM PERM TEST BEGIN");																			
				for(i = 0; i < NumOfIterPermission;i++)
				{
					//for(j = 0; j < 6; j++)
					START;
					iResult =  PERMISSION_TEST(RG_PERM_EEPROM_PASS );
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);				
				printk("\r\n EEPROM PERM TEST END");																			
				goto L_Start_block;
				break;	
			case '6' : 
				printk("\r\n UID PERM TEST BEGIN");
				for(i = 0; i < NumOfIterPermission;i++)
				{
					//for(j = 0; j < 6; j++																				
					START;
					iResult =  PERMISSION_TEST(RG_PERM_UID_PASS );
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);				
				printk("\r\n UID PERM TEST END");																								
				break;			
			case '7' :
				printk("\r\n SUPER PW CHANGE TEST BEGIN");				
				for(i = 0; i < NumOfIterPermission;i++)
				{		
					START;
					iResult = ChangePW(RG_PERM_SUPER_PASS );
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				printk("\r\n SUPER PW CHANGE TEST END");																								
				goto L_Start_block;
				break; 
			case '8' :
				printk("\r\n DETOUR PW CHANGE TEST BEGIN");
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;																				
					iResult = ChangePW(RG_PERM_DETOUR_PASS );
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				printk("\r\n DETOUR PW CHANGE TEST END");																								
				goto L_Start_block;
				break; 
			case '9' :
				printk("\r\n DESTORY0 PW CHANGE TEST BEGIN");
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;																				
					iResult =   ChangePW(RG_PERM_DESTORY0_PASS );
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;		
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				printk("\r\n DESTORY0 PW CHANGE TEST END");																								
				goto L_Start_block;
				break; 
			case 'a' :
				printk("\r\n DESTORY1 PW CHANGE TEST BEGIN");
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;																			
					iResult =  ChangePW(RG_PERM_DESTORY1_PASS );
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				printk("\r\n DESTORY1 PW CHANGE TEST END");																								
				goto L_Start_block;
				break; 
			case 's' :
				printk("\r\n EEPROM PW CHANGE TEST BEGIN");				
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;
					iResult =   ChangePW(RG_PERM_EEPROM_PASS );
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				printk("\r\n EEPROM PW CHANGE TEST END");																								
				goto L_Start_block;
				break; 
			case 'd' :
				printk("\r\n UID PW CHANGE TEST BEGIN");					
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;
					iResult = ChangePW(RG_PERM_UID_PASS);
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;	
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				printk("\r\n UID PW CHANGE TEST END");				
				goto L_Start_block;
				break; 		
			case 'q' :
				printk("\r\n SUPER PERM GET TEST BEGIN");				
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;
					iResult = GetPermissionByPW(SUPER_PW_CT, RG_PERM_SUPER_PASS);
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				printk("\r\n SUPER PERM GET TEST END");				
				goto L_Start_block;
				break; 						
			case 'w' :
				printk("\r\n DETOUR PERM GET TEST BEGIN");								
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;
					iResult = GetPermissionByPW(DETOUR_PW_CT, RG_PERM_DETOUR_PASS);
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				printk("\r\n DETOUR PERM GET TEST BEGIN");				
				goto L_Start_block;
				break; 		
			case 'e' :
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;
					iResult = GetPermissionByPW(DESTROY0_PW_CT, RG_PERM_DESTORY0_PASS);
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				goto L_Start_block;
				break; 		
			case 'r' :
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;
					iResult = GetPermissionByPW(DESTROY1_PW_CT, RG_PERM_DESTORY1_PASS);
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				goto L_Start_block;
				break; 		
			case 't' :
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;
					iResult = GetPermissionByPW(EEPROM_PW_CT, RG_PERM_EEPROM_PASS);
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				goto L_Start_block;
				break; 		
			case 'y' :
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;

					//SetKEYNormal();

					iResult = GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				goto L_Start_block;
				break; 		
			case 'x' :
				iResult = 1;
				for(i = 0; i < NumOfIterPermission;i++)
				{
					START;
					for(j = 5;  j >= 0; j--)
					{
						if(GetPermissionByPW(pPW_CT[j], j) == 0 )
							iResult = 0;
					}
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT
						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				goto L_Start_block;
				break; 						
			case 'c' :	
				ReleasePermision();
				goto L_Start_block;

				break; 				
			case 'v':
				tspi_interface(cs, ADDR_NOR_R, RG_PERM_GET_CTRL1 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		
				printk("\r\n GetPermResult 0x%02x",rx_data[0]);
				goto L_Start_block;
				break;		
			case 'b':
				for(i = 5; i >= 0; i--)
				{
					if(i == RG_PERM_SUPER_PASS )
						printk("\r\n  * 0. Supper Permission KEY                                              *");	
					if(i == RG_PERM_DETOUR_PASS )
						printk("\r\n  * 1. DETOUR Permission KEY                                              *");	
					if(i == RG_PERM_DESTORY0_PASS )
						printk("\r\n  * 2. DESTORY0 Permission KEY                                              *");	
					if(i== RG_PERM_DESTORY1_PASS)
						printk("\r\n  * 3. DESTORY1 Permission KEY                                              *");	
					if(i == RG_PERM_EEPROM_PASS)
						printk("\r\n  * 4. EEPROM Permission KEY                                              *");	
					if(i == RG_PERM_UID_PASS )
						printk("\r\n  * 5. UID Permission KEY                                              *");	
					//GetSuperWirePermission();
					if(SAVE_KEY_REVERSE(i) == 0)
					{
						PRINTLOG("\r\n LOAD KEY FAIL %d",i);
						if(i == RG_PERM_SUPER_PASS)
							printk("\r\n  * 0. Supper Permission KEY                                              *");	
						if(i == RG_PERM_DETOUR_PASS)
							printk("\r\n  * 1. DETOUR Permission KEY                                              *");	
						if(i == RG_PERM_DESTORY0_PASS)
							printk("\r\n  * 2. DESTORY0 Permission KEY                                              *");	
						if(i== RG_PERM_DESTORY1_PASS)
							printk("\r\n  * 3. DESTORY1 Permission KEY                                              *");	
						if(i == RG_PERM_EEPROM_PASS)
							printk("\r\n  * 4. EEPROM Permission KEY                                              *");	
						if(i == RG_PERM_UID_PASS)
							printk("\r\n  * 5. UID Permission KEY                                              *");	
						goto L_Start_block;
					}
					//ReleasePermision();
				}
				printk("\r\n Write SeedKey");
				memset(tx_data,0x11,64);
				eep_page_write(0xec, 0, tx_data, 1);
				printk("\r\n KEY LOAD SUCCESS");
				goto L_Start_block;

				break;		
			case 'u':
				{

					int perm_type = 0;
					int select = 0;
					while(1)
					{


L_Start_permission:									
						printk("\r\n Input permission type ");
						printk("\r\n  * 0. Supper Permission Get & Release TEST     (500012)                                         *");	
						printk("\r\n  * 1. DETOUR Permission Get & Release  TEST  (500013)                                            *");	
						printk("\r\n  * 2. DESTORY0 Permission Get & Release  TEST  (500014)                                            *");	
						printk("\r\n  * 3. DESTORY1 Permission Get & Release  TEST   (500015)                                           *");	
						printk("\r\n  * 4. EEPROM Permission Get & Release  TEST   (500016)                                           *");	
						printk("\r\n  * 5. UID Permission TEST Get & Release        (500017)                                      *");	
						printk("\r\n  * m. return to menu                                              *");
						printk("\r\n Select");
						perm_type = get_char();	 
						HitCnt = 0;
						MissCnt = 0;
						//PRINTLOG("\r\n get_char_result %x");
						switch(perm_type)
						{
						case '0':
							select = RG_PERM_SUPER_PASS ;
							printk("\r\n SUPER GET AND RELEASE TEST BEGIN");
							break;
						case '1':
							select =RG_PERM_DETOUR_PASS ;
							printk("\r\n DETOUR GET AND RELEASE TEST BEGIN");							
							break;
						case '2':
							select = RG_PERM_DESTORY0_PASS ;
							printk("\r\n DESTORY0 GET AND RELEASE TEST BEGIN");														
							break;
						case '3':
							select =RG_PERM_DESTORY1_PASS ;
							printk("\r\n DESTORY1 GET AND RELEASE TEST BEGIN");																					
							break;
						case '4':
							select = RG_PERM_EEPROM_PASS;
							printk("\r\n EEPROM GET AND RELEASE TEST BEGIN");							
							break;
						case '5':
							select = RG_PERM_UID_PASS;
							printk("\r\n UID GET AND RELEASE TEST BEGIN");														
							break;
						case 'm':
							goto L_Start_block;
							break;
						case 0x0d:
							goto L_Start_permission;
							break;
						}
						for(i = 0; i < NumOfIterPermission;i++)
						{		 
							//gPrintOut = 0;
							iResult = GetPermissionByPW(pPW_CT[select], select);
							//gPrintOut = 1;
							printk("\r\n END of %dth iteration!!!",i+1);

							if(ReleasePermision() == 0)
								iResult = 0;
							if(iResult == 0)
							{
								MissCnt++;
								printk("\r\n TEST FAIL");
#if ERROR_EXIT
								PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
								goto L_Start_block;
#endif
							}
							else
							{

								printk("\r\n TEST PASS");
								HitCnt++;
							}



						} 
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);													
					}
					switch(perm_type)
					{
					case '0':
						select = RG_PERM_SUPER_PASS ;
						printk("\r\n SUPER GET AND RELEASE TEST END");
						break;
					case '1':
						select =RG_PERM_DETOUR_PASS ;
						printk("\r\n DETOUR GET AND RELEASE TEST END");							
						break;
					case '2':
						select = RG_PERM_DESTORY0_PASS ;
						printk("\r\n DESTORY0 GET AND RELEASE TEST END");														
						break;
					case '3':
						select =RG_PERM_DESTORY1_PASS ;
						printk("\r\n DESTORY1 GET AND RELEASE TEST END");																					
						break;
					case '4':
						select = RG_PERM_EEPROM_PASS;
						printk("\r\n EEPROM GET AND RELEASE TEST END");							
						break;
					case '5':
						select = RG_PERM_UID_PASS;
						printk("\r\n UID GET AND RELEASE TEST END");														
						break;
					case 'm':
						goto L_Start_block;
						break;
					case 0x0d:
						goto L_Start_permission;
						break;
					}
				}
				break;
			case 'o':
				GetSuperWirePermission();
				break;
			case 'p':
				ReleasePermision();
				break;
			case 'k':
				{
					printk("\r\n SUPER PERM TEST BEGIN");				
					for(i = 0; i < NumOfIterPermission;i++)
					{
						//for(j = 0; j < 6; j++)
						START;
						iResult = PERMISSION_TEST(RG_PERM_SUPER_PASS );
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT

							END;
							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");

							HitCnt++;
						}
						END;
					}
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
					HitCnt = MissCnt = 0;										
					printk("\r\n SUPER PERM TEST END"); 			
					printk("\r\n DETOUR PERM TEST BEGIN");				
					for(i = 0; i < NumOfIterPermission;i++)
					{
						START;
						//for(j = 0; j < 6; j++)
						iResult =  PERMISSION_TEST(RG_PERM_DETOUR_PASS );
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
							END;

							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
							HitCnt++;
						}
						END;
					}
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
					HitCnt = MissCnt = 0;										
					printk("\r\n DETOUR PERM TEST END");				
					printk("\r\n DESTORY0 PERM TEST BEGIN");				
					for(i = 0; i < NumOfIterPermission;i++)
					{
						//for(j = 0; j < 6; j++)
						START;
						iResult =  PERMISSION_TEST(RG_PERM_DESTORY0_PASS );
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT

							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
							HitCnt++;
						}
						END;
					}
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
					HitCnt = MissCnt = 0;										
					printk("\r\n DESTORY0 PERM TEST END");									
					printk("\r\n DESTORY1 PERM TEST BEGIN");														
					for(i = 0; i < NumOfIterPermission;i++)
					{
						//for(j = 0; j < 6; j++)
						START;
						iResult =  PERMISSION_TEST(RG_PERM_DESTORY1_PASS );
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT

							END;
							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
							HitCnt++;
						}
						END;
					}
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);			
					HitCnt = MissCnt = 0;										
					printk("\r\n DESTORY1 PERM TEST END");														
					printk("\r\n EEPROM PERM TEST BEGIN");																			
					for(i = 0; i < NumOfIterPermission;i++)
					{
						//for(j = 0; j < 6; j++)
						START;
						iResult =  PERMISSION_TEST(RG_PERM_EEPROM_PASS );
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT

							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
							HitCnt++;
						}
						END;
					}
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);				
					HitCnt = MissCnt = 0;										
					printk("\r\n EEPROM PERM TEST END");																			
					printk("\r\n UID PERM TEST BEGIN");
					for(i = 0; i < NumOfIterPermission;i++)
					{
						//for(j = 0; j < 6; j++ 																			
						START;
						iResult =  PERMISSION_TEST(RG_PERM_UID_PASS );
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
							END;

							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
							HitCnt++;
						}
						END;
					}
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);				
					HitCnt = MissCnt = 0;										
					printk("\r\n UID PERM TEST END");																								
					
					printk("\r\n SUPER PW CHANGE TEST BEGIN");				
					for(i = 0; i < NumOfIterPermission;i++)
					{		
						START;
						iResult = ChangePW(RG_PERM_SUPER_PASS );
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
							END;

							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
							HitCnt++;
						}
						END;
					}
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
					HitCnt = MissCnt = 0;					
					printk("\r\n SUPER PW CHANGE TEST END");																								
					goto L_Start_block;
					break; 
					for(i = 0; i < NumOfIterPermission;i++)
					{
						START;																				
						iResult = ChangePW(RG_PERM_DETOUR_PASS );
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
							END;

							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
							HitCnt++;
						}
						END;
					}
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
					HitCnt = MissCnt = 0;					
					printk("\r\n DETOUR PW CHANGE TEST END");																								
					printk("\r\n DESTORY0 PW CHANGE TEST BEGIN");
					for(i = 0; i < NumOfIterPermission;i++)
					{
						START;																				
						iResult =	ChangePW(RG_PERM_DESTORY0_PASS );
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
							END;		
							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
							HitCnt++;
						}
						END;
					}
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
					HitCnt = MissCnt = 0;
					printk("\r\n DESTORY0 PW CHANGE TEST END"); 																							
					printk("\r\n DESTORY1 PW CHANGE TEST BEGIN");
					for(i = 0; i < NumOfIterPermission;i++)
					{
						START;																			
						iResult =  ChangePW(RG_PERM_DESTORY1_PASS );
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT

							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
							HitCnt++;
						}
						END;
					}
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
					printk("\r\n DESTORY1 PW CHANGE TEST END"); 																							
					printk("\r\n EEPROM PW CHANGE TEST BEGIN"); 			
					for(i = 0; i < NumOfIterPermission;i++)
					{
						START;
						iResult =	ChangePW(RG_PERM_EEPROM_PASS );
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT

							END;
							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
							HitCnt++;
						}
						END;
					}
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
					HitCnt = MissCnt = 0;
					printk("\r\n EEPROM PW CHANGE TEST END");																								
					printk("\r\n UID PW CHANGE TEST BEGIN");					
					for(i = 0; i < NumOfIterPermission;i++)
					{
						START;
						iResult = ChangePW(RG_PERM_UID_PASS);
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
							END;	
							PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
							HitCnt++;
						}
						END;
					}
					
					PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
					printk("\r\n UID PW CHANGE TEST END");				
				}
				goto L_Start_block;
				break;		

			default : temp = 'p'; break;
			}

		}
	}
#endif
}

void MIDR_TEST_MAIN()
{
#ifdef COMPARE

	int i;
	unsigned int inst = 0;
	int pass = 1;
	int j = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp ;
	int iResult = 0;
	unsigned char MIDRCNT0[8];
	unsigned char MIDRCNT1[8];
	unsigned char MIDR_INDEX0;
L_MIDR_START:
	while(1)
	{
		temp = 'z' ;
		tx_data[0] = 0x01;		
		tx_data[0] = 0xB;
#ifdef UID_MIDR
		GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
#endif
		tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		//#if PRINTFMODE
		tspi_interface(cs, 0x20, MIDR_CNT0 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);
		memcpy(MIDRCNT0,rx_data,8);
		tspi_interface(cs, 0x20, MIDR_CNT1 , NULL, NULL, NULL, NULL, tx_data, rx_data, 8);
		memcpy(MIDRCNT1,rx_data,8);
		tspi_interface(cs,  0x20, MIDR_INCDEC, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		MIDR_INDEX0 = rx_data[0];
		endOP();
#if UID_MIDR
		ReleasePermision();
#endif
		printk("\r\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  *            MIDR     TEST MAIN                                                  *");
		printk("\r\n  *****************************************************");
		//	 PRINTLOG("\r\n  * number of iteration     %d                        			    *",NumOfIterOKA );
		printk("\r\n  * MIDR_CNT0 =");
		for( i = 7; i >= 0; i--)
			printk("%02x ",MIDRCNT0[i]);

		printk("\r\n  * MIDR_CNT1 =");
		for( i = 7; i >= 0; i--)
			printk("%02x ",MIDRCNT1[i]);
		printk("\r\n * MIDR_INCDEC %02x",MIDR_INDEX0);
		printk("\r\n  * 1. Set MIDR_INCDEC                                         *");	
		printk("\r\n  * 2. Set MIDR_CNT0                                           *");
		printk("\r\n  * 3. Set MIDR_CNT1                                           *");		
		printk("\r\n  * 4. Reset MIDR Region                                       *");				
		printk("\r\n  * 5. Read MIDR Region                                        *");						
		printk("\r\n  * m. return to top menu                                      *");	
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n");

		printk("\r\n");
		printk("\r\n  * Select : ");

		while(temp == 'z')
		{
			temp = _uart_get_char();

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");

			if(temp == 0x0d)
				goto L_MIDR_START;
			if(temp == 'm')
			{
				printk("\r\nm is pressed");
				return;
			}

			switch ( temp )
			{
			case 'i' : 
				printk("\r\n input number of iteration : (4digit)");
				printk("\r\n 0x");
				NumOfIterOKA = get_int();
				NumOfIterOKA =( NumOfIterOKA<<8)| get_int();		 
				break;

			case '1' : 
				printk("\r\n input value (2digit)");					
				printk("\r\n 0x");			
				temp = 	get_int();
				SetMIDR_INCDEC(temp);
				goto L_MIDR_START;
				break;
			case '2' :
				printk("\r\n input value (16digit)");					
				printk("\r\n 0x");
				j = 7;
				for( i = 0; i < 8; i++)
				{
					temp = 	get_int();
					tx_data[j--]  = temp;
				}
				SetMIDRCNT(0, tx_data);		
				goto L_MIDR_START;
				break; 
			case '3':
				printk("\r\n input value (16digit)");					
				printk("\r\n 0x");
				j = 7;
				for( i = 0; i < 8; i++)
				{
					temp = 	get_int();
					tx_data[j--]  = temp;
				}
				SetMIDRCNT(1, tx_data);	
				goto L_MIDR_START;
			case '4':
				ResetMIDR_Region();
				goto L_MIDR_START;
			case '5':
				ReadMIDR_Region();
				goto L_MIDR_START;				 
			default :
				//					temp = 'p'; break;
				break;
			}

		}
	}
#endif
}

int GetSuperWirePermission(void)
{

}
void ReadKEYAES_X()
{
	PRINTLOG("\r\n READ AES_KEY_X \r\n");
	//GetSuperWirePermission();
	delay_ms(20);
	eep_page_read(ADDR_EE_KEY_AES_x0[0],ADDR_EE_KEY_AES_x0[1],0,NULL);
	eep_page_read(ADDR_EE_KEY_AES_x1[0],ADDR_EE_KEY_AES_x1[1],0,NULL);
	eep_page_read(ADDR_EE_KEY_AES_x2[0],ADDR_EE_KEY_AES_x2[1],0,NULL);
	eep_page_read(ADDR_EE_KEY_AES_x3[0],ADDR_EE_KEY_AES_x3[1],0,NULL);	
	//eep_page_read(0xE9,0x40);
	//eep_page_read(0xE9,0x80);	
	//eep_page_read(0xE9,0xC0);	
	//ReleasePermision();
	PRINTLOG("\r\n END READ AES_KEY_X \r\n");	
}
unsigned char lps1A[16] = {0};
#if 0
int OKA_Test2(void)
{

	int i,j;
	int is_pass = 1;
	unsigned int inst = 0x00;
	unsigned char addr[2] = { 0x00, 0x00 };
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char AES_KEYA0_A0002[] =    {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	unsigned char AES_PTA0_A0002[] =      {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	unsigned char AES_KEYA1_A0002[] =    {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F};
	unsigned char AES_PTA1_A0002[] =      {0x69,0xC4,0xE0,0xD8,0x6A,0x7B,0x04,0x30,0xD8,0xCD,0xB7,0x80,0x70,0xB4,0xC5,0x5A};
	unsigned char AES_PTA2_A0002[] =      {0xE4,0x4B,0x37,0x11,0x15,0x22,0x9A,0xC2,0xC6,0x55,0x6A,0xB9,0x19,0xF4,0x52,0xA3};
	unsigned char AES_KEYA2_A0002[] =    {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20};
	unsigned char AES_CTA2_A0002[] =      {0x0E,0x9E,0xC0,0xE7,0x85,0x29,0x23,0x75,0xC3,0x90,0x64,0x1C,0x62,0x01,0x9D,0xBD};
	unsigned char AES_PTA3_A0002[] =       {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F};
	unsigned char AES_PTA4_0_A0002[] =   {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	unsigned char AES_CTA4_0_A0002[] = {0x1A,0xF1,0xBE,0x44,0x5A,0x00,0xFF,0xBF,0x16,0xA4,0x55,0xCA,0xC2,0xE2,0xDB,0xA8};
	unsigned char AES_PTA4_1_0_A0002[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	unsigned char AES_CTA4_1_0_A0002[] = {0x1A,0xF1,0xBE,0x44,0x5A,0x00,0xFF,0xBF,0x16,0xA4,0x55,0xCA,0xC2,0xE2,0xDB,0xA8};
	unsigned char AES_CTA4_1_A0002[] =      {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F};
	unsigned char AES_PTA4_1_A0002[] = {0x5B,0x64,0xA9,0x8A,0x47,0x02,0x82,0x9A,0x4D,0x2B,0x29,0x43,0x1F,0xDB,0x0E,0xCD};
	unsigned char AES_CTA4_1_1_A0002[] = {0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F};
	unsigned char AES_PTA4_1_1_A0002[] = {0x54,0x77,0xF5,0xB6,0xFE,0x8E,0x11,0x7A,0x6E,0x5B,0xE8,0xF5,0xF3,0x89,0x93,0x39};
	unsigned char AES_PTA4_2_A0002[] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F};
	unsigned char AES_CTA4_2_A0002[] = {0xA3,0xF8,0x4F,0x04,0xC1,0x85,0x7C,0xAA,0x60,0x72,0x2A,0x41,0xD1,0x00,0x97,0x2E};
	unsigned char AES_PTA4_1_2_A0002[] = {0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F};
	unsigned char AES_CTA4_1_2_A0002[] = {0xD8,0xB3,0xE7,0x7C,0x7C,0xBA,0xEE,0x77,0xB1,0x2A,0x65,0x27,0xA6,0xAE,0x6F,0xE5};
#ifdef PRINTFMODE
	PRINTLOG("\r\n OKA_TEST2\r\n");
#endif
	inst = 0x31;
	tx_data[0] = 0x03;
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_AES_CTRL ");
#endif
	tspi_interface(cs, inst, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	inst = 0x21;
	tspi_interface(cs, inst, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_AES_CTRL 0x%02x",rx_data[0]);
#endif

	inst = 0x31;
	tx_data[0] = 0x01;
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_OKA_CTRL");
#endif
	tspi_interface(cs, inst, RG_OKA_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	inst = 0x21;
	tspi_interface(cs, inst, RG_OKA_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_OKA_CTRL 0x%02x",rx_data[0]);
#endif

	inst = 0x31;
	tx_data[0] = 0x0A;
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ST0_OPMODE:");
#endif
	tspi_interface(cs, inst, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	inst = 0x21;
	tspi_interface(cs, inst, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ST0_OPMODE 0x%02x",rx_data[0]);
#endif


	inst = 0x31;
	tx_data[0] = 0x02;
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ST1_OKA_OPMODE");
#endif
	tspi_interface(cs, inst, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	inst = 0x21;
	tspi_interface(cs, inst, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ST1_OKA_OPMODE 0x%02x",rx_data[0]);
#endif

	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_KEYA0_A0002[i];
	}
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_EEBUF510");
#endif
	tspi_interface(cs, inst, RG_EEBUF510, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);

	Delay_us(10);

	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_PTA0_A0002[i];
	}
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_EEBUF300");
#endif
	tspi_interface(cs, inst, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);

	Delay_us(10);
#ifdef PRINTFMODE
	PRINTLOG("\r\n[NOTE] ---- OKA2 Key Gen OAK2_0 ENC output ----\r\n");
#endif

	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_KEYA1_A0002[i];
	}
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_EEBUF510");
#endif
	tspi_interface(cs, inst, RG_EEBUF510, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);

	Delay_us(10);

	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_PTA1_A0002[i];
	}
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_EEBUF300");
#endif
	tspi_interface(cs, inst, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);

	Delay_us(10);

#ifdef PRINTFMODE
	PRINTLOG("\r\n[NOTE] ---- OKA2 Key Gen OAK2_1 ENC output ----\r\n");
#endif

	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_KEYA2_A0002[i];
	}
#ifdef PRINTFMODE	
	PRINTLOG("\r\n  RG_EEBUF510");
#endif
	tspi_interface(cs, inst, RG_EEBUF510, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);

	Delay_us(10);

	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_CTA2_A0002[i];
	}
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_EEBUF400");
#endif
	tspi_interface(cs, inst, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);

	Delay_us(10);
#ifdef PRINTFMODE
	PRINTLOG("\r\n[NOTE] ---- OKA2 Key Gen OAK2_2 DEC output ----\r\n");
#endif


	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_PTA3_A0002[i];
	}
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_EEBUF300");
#endif
	tspi_interface(cs, inst, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);

	Delay_us(10);
#ifdef PRINTFMODE
	PRINTLOG("\r\n[NOTE] ---- OKA2 Key Gen OAK2_3 ENC output ----\r\n");
#endif


	inst = 0x31;
	tx_data[0] = 0x01;
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ST1_OKA_OPMODE");
#endif
	tspi_interface(cs, inst, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	inst = 0x21;
	tspi_interface(cs, inst, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef PRINTFMODE	
	PRINTLOG("\r\n  RG_ST1_OKA_OPMODE 0x%02x",rx_data[0]);
#endif


	inst = 0x31;
	tx_data[0] = 0x03;
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ST1_OKA_OPMODE");
#endif
	tspi_interface(cs, inst, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	inst = 0x21;
	tspi_interface(cs, inst, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ST1_OKA_OPMODE 0x%02x",rx_data[0]);
#endif


	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_PTA4_0_A0002[i];
	}
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_EEBUF300");
#endif
	tspi_interface(cs, inst, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

#ifdef PRINTFMODE
	PRINTLOG("\r\n[NOTE] ---- OKA2 OAK2_4_0 1st frame ENC output ----\r\n");
#endif
	inst = 0x21;
	tspi_interface(cs, inst, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);


#ifdef PRINTFMODE
	PRINTLOG("\r\n compare AES_CTA4_0_A0002 and RG_EEBUF320");
#endif
	{
		unsigned char	AES_CTA4_0_A0002_Reverse[16];
		j = 0;
		for ( i = 15; i >= 0; i--)
		{
			AES_CTA4_0_A0002_Reverse[j++] = AES_CTA4_0_A0002[i];
		}
#ifdef PRINTFMODE
		PRINTLOG("\r\n AES_CTA4_0_A0002_Reverse\r\n");
#endif
		for(i = 0 ; i <= 15; i++)
		{
#ifdef PRINTFMODE
			PRINTLOG("0x%02x ", AES_CTA4_0_A0002_Reverse[i] );
#endif
		}

		if(memcmp(AES_CTA4_0_A0002_Reverse,rx_data,16) == 0)
		{
			int kkk = 0;
#ifdef PRINTFMODE
			PRINTLOG("\r\n compare success");
#endif
		}
		else
		{
#ifdef PRINTFMODE
			PRINTLOG("\r\n rx_data");

			for(i = 0 ; i <= 15; i++)
			{
				PRINTLOG("0x%02x ", rx_data[i] );
			}
			PRINTLOG("\r\n compare fail");
#endif
			is_pass = 0;
		}
	}

	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_PTA4_1_0_A0002[i];
	}

	tspi_interface(cs, inst, RG_EEBUF310, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
#ifdef PRINTFMODE
	PRINTLOG("\r\n[NOTE] ---- OKA2 OAK2_4_0 2nd frame ENC output ----\r\n");
#endif

	inst = 0x21;
	j = 0;
	tspi_interface(cs, inst, RG_EEBUF330, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

#ifdef PRINTFMODE
	PRINTLOG("\r\n compare AES_CTA4_1_0_A0002 and RG_EEBUF330");
#endif
	{
		unsigned char	AES_CTA4_1_0_A0002_Reverse[16];
		j = 0;
		for ( i = 15; i >= 0; i--)
		{
			AES_CTA4_1_0_A0002_Reverse[j++] = AES_CTA4_1_0_A0002[i];
		}
#ifdef PRINTFMODE
		PRINTLOG("\r\n AES_CTA4_1_0_A0002_Reverse\r\n");

		for(i = 0 ; i <= 15; i++)
		{
			PRINTLOG("0x%02x ", AES_CTA4_1_0_A0002_Reverse[i] );
		}
#endif

		if(memcmp(AES_CTA4_1_0_A0002_Reverse,rx_data,16) == 0)
		{
			int kkk = 0;
#ifdef PRINTFMODE
			PRINTLOG("\r\n compare success");
#endif
		}
		else
		{
#ifdef PRINTFMODE
			PRINTLOG("\r\n rx_data");
			for(i = 0 ; i <= 15; i++)
			{
				PRINTLOG("0x%02x ", rx_data[i] );
			}
			PRINTLOG("\r\n compare fail");
#endif
			is_pass = 0;
		}
	}

	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_CTA4_1_A0002[i];
	}

	tspi_interface(cs, inst, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

#ifdef PRINTFMODE
	PRINTLOG("\r\n[NOTE] ---- OKA2 OAK2_4_1 1st frame DEC output ----\r\n");
#endif

	inst = 0x21;
	tspi_interface(cs, inst, RG_EEBUF420, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

#ifdef PRINTFMODE
	PRINTLOG("\r\n compare AES_PTA4_1_A0002 and RG_EEBUF420");
#endif
	{
		unsigned char	AES_PTA4_1_A0002_Reverse[16];
		j = 0;
		for ( i = 15; i >= 0; i--)
		{
			AES_PTA4_1_A0002_Reverse[j++] = AES_PTA4_1_A0002[i];
		}
#ifdef PRINTFMODE
		PRINTLOG("\r\n AES_PTA4_1_A0002_Reverse\r\n");

		for(i = 0 ; i <= 15; i++)
		{
			PRINTLOG("0x%02x ", AES_PTA4_1_A0002_Reverse[i] );
		}
#endif		
		if(memcmp(AES_PTA4_1_A0002_Reverse,rx_data,16) == 0)
		{
			int kkk = 0;
#ifdef PRINTFMODE
			PRINTLOG("\r\n compare success");
#endif
		}
		else
		{
#ifdef PRINTFMODE
			PRINTLOG("\r\n rx_data");
			for(i = 0 ; i <= 15; i++)
			{
				PRINTLOG("0x%02x ", rx_data[i] );
			}
			PRINTLOG("\r\n compare fail");
#endif
			is_pass = 0;
		}
	}


	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_CTA4_1_1_A0002[i];
	}

	tspi_interface(cs, inst, RG_EEBUF410, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);


	inst = 0x21;
	tspi_interface(cs, inst, RG_EEBUF430, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

#ifdef PRINTFMODE
	PRINTLOG("\r\n compare AES_PTA4_1_1_A0002 and RG_EEBUF430");
#endif
	{
		unsigned char	AES_PTA4_1_1_A0002_Reverse[16];
		j = 0;
		for ( i = 15; i >= 0; i--)
		{
			AES_PTA4_1_1_A0002_Reverse[j++] = AES_PTA4_1_1_A0002[i];
		}
#ifdef PRINTFMODE
		PRINTLOG("\r\n AES_PTA4_1_A0002_Reverse\r\n");

		for(i = 0 ; i <= 15; i++)
		{
			PRINTLOG("0x%02x ", AES_PTA4_1_1_A0002_Reverse[i] );
		}
#endif		
		if(memcmp(AES_PTA4_1_1_A0002_Reverse,rx_data,16) == 0)
		{
			int kkk = 0;
#ifdef PRINTFMODE
			PRINTLOG("\r\n compare success");
#endif
		}
		else
		{
#ifdef PRINTFMODE
			PRINTLOG("\r\n rx_data");
			for(i = 0 ; i <= 15; i++)
			{
				PRINTLOG("0x%02x ", rx_data[i] );
			}
			PRINTLOG("\r\n compare fail");
#endif
			is_pass = 0;
		}
	}



	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_PTA4_2_A0002[i];
	}

	tspi_interface(cs, inst, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
#ifdef PRINTFMODE
	PRINTLOG("\r\n[NOTE] ---- OKA2 OAK2_4_2 1st frame ENC output ----\r\n");	
#endif
	inst = 0x21;
	tspi_interface(cs, inst, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
#ifdef PRINTFMODE
	PRINTLOG("\r\n---- OKA2 Data Processing. OAK2_4_2 1st frame ENC. ----\r\n");
#endif

#ifdef PRINTFMODE
	PRINTLOG("\r\n compare AES_CTA4_2_A0002 and RG_EEBUF320");
#endif
	{
		unsigned char	AES_CTA4_2_A0002_Reverse[16];
		j = 0;
		for ( i = 15; i >= 0; i--)
		{
			AES_CTA4_2_A0002_Reverse[j++] = AES_CTA4_2_A0002[i];
		}
#ifdef PRINTFMODE
		PRINTLOG("\r\n AES_CTA4_2_A0002\r\n");

		for(i = 0 ; i <= 15; i++)
		{
			PRINTLOG("0x%02x ", AES_CTA4_2_A0002_Reverse[i] );
		}
#endif

		if(memcmp(AES_CTA4_2_A0002_Reverse,rx_data,16) == 0)
		{
			int kkk = 0;
#ifdef PRINTFMODE
			PRINTLOG("\r\n compare success");
#endif
		}
		else
		{
#ifdef PRINTFMODE
			PRINTLOG("\r\n rx_data");
			for(i = 0 ; i <= 15; i++)
			{
				PRINTLOG("0x%02x ", rx_data[i] );
			}
			PRINTLOG("\r\n compare fail");
#endif
			is_pass = 0;
		}
	}


	inst = 0x31;
	j = 0;
	for ( i = 15; i >= 0; i--)
	{
		tx_data[j++] = AES_PTA4_1_2_A0002[i];
	}

	tspi_interface(cs, inst, RG_EEBUF310, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

#ifdef PRINTFMODE
	PRINTLOG("\r\n[NOTE] ---- OKA2 OAK2_4_1_2 2nd frame ENC output ----\r\n");	
#endif
	inst = 0x21;
	tspi_interface(cs, inst, RG_EEBUF330, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
#ifdef PRINTFMODE
	PRINTLOG("\r\n---- OKA2 Data Processing. OAK2_4_1_2 2nd frame ENC. ----\r\n");



	PRINTLOG("\r\n compare AES_CTA4_1_2_A0002 and RG_EEBUF320");
#endif
	{
		unsigned char	AES_CTA4_1_2_A0002_Reverse[16];
		j = 0;
		for ( i = 15; i >= 0; i--)
		{
			AES_CTA4_1_2_A0002_Reverse[j++] = AES_CTA4_1_2_A0002[i];
		}
#ifdef PRINTFMODE
		PRINTLOG("\r\n AES_CTA4_2_A0002\r\n");
		for(i = 0 ; i <= 15; i++)
		{
			PRINTLOG("0x%02x ", AES_CTA4_1_2_A0002_Reverse[i] );
		}
#endif

		if(memcmp(AES_CTA4_1_2_A0002_Reverse,rx_data,16) == 0)
		{
#ifdef PRINTFMODE
			PRINTLOG("\r\n compare success");
#endif
			is_pass = 1;
		}
		else
		{
#ifdef PRINTFMODE
			PRINTLOG("\r\n rx_data");
			for(i = 0 ; i <= 15; i++)
			{
				PRINTLOG("0x%02x ", rx_data[i] );
			}
			PRINTLOG("\r\n compare fail");
#endif
			is_pass = 0;
		}
	}

	inst = 0x31;
	tx_data[0] = 0x01;
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ST1_OKA_OPMODE");
#endif
	tspi_interface(cs, inst, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	inst = 0x21;
	tspi_interface(cs, inst, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ST1_OKA_OPMODE 0x%02x",rx_data[0]);
#endif

	inst = 0x31;
	tx_data[0] = 0x01;
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ST0_OPMODE:");
#endif
	tspi_interface(cs, inst, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	inst = 0x21;
	tspi_interface(cs, inst, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ST0_OPMODE 0x%02x",rx_data[0]);
#endif


	inst = 0x31;
	tx_data[0] = 0x00;
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ACCESS:");
#endif
	tspi_interface(cs, inst, RG_ACCESS, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	inst = 0x21;
	tspi_interface(cs, inst, RG_ACCESS, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#ifdef PRINTFMODE
	PRINTLOG("\r\n  RG_ACCESS 0x%02x",rx_data[0]);
#endif
	Delay_us(5);

	//PRINTLOG("\r\nTEST RESULT : ");

	if(is_pass)
	{
		PRINTLOG("PASS");
		return 0;
	}
	else
	{
		PRINTLOG("FAIL");
		return -1;
	}


}
#endif
int OKA_Test2_0613(void)
{
#ifdef COMPARE

	int i,j;
	unsigned int inst = 0x00;
	int success = 1;
	unsigned char addr[2] = { 0x00, 0x00 };
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char data1[16];
	unsigned char data2[16];	
	unsigned int iStart,iEnd;
	unsigned int totalEncode = 0;
	unsigned int totalDecode = 0;
	//AT91S_RTTC *pRSTC = (AT91S_RTTC *) 0xFFFFFD20;  
	tx_data[4] = 0x02;
	//printk("\r\n 	tx_data[4] = 0x02;");
	//eep_page_write(0xEB,0x40, tx_data, 1);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W, RG_OKA_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x0A;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x02;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_KEYA0_A0002[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA0_A0002[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_KEYA1_A0002[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data1[i] = rx_data[j--];
	}
	if( memcmp(data1,AES_CTA1_A0001,16) == 0)
		printk("\r\n PART 1 PASS");
	else
	{
		success = 0;
		printk("\r\n PART 1 FAIL");	
		printk("\r\ndata1");
		printbyte(data1,16);
		printk("\r\n expected");
		printbyte(AES_CTA1_A0001,16);

	}
	//printk("\r\n data\r\n");
	//printbyte(data,16);
	//printk("\r\n AES_CTA1_A0001\r\n");	
	//printbyte(AES_CTA1_A0001,16);	
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_KEYA2_A0002[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_CTA2_A0002[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA3_A0002[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA4_0_A0002[j--];
	}
	j = 15;
	for( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_PTA4_1_0_A0002[j--];
	}

	for( i = 0 ; i < 1; i++)
	{
	#if 0
	
		AT91F_RTTClearAlarmINT(pRSTC);
		AT91F_RTTClearRttIncINT(pRSTC);
		AT91F_RTTC_CfgPMC();
		AT91F_RTTSetPrescaler(pRSTC,1);
		AT91F_RTTRestart(pRSTC);	
		Delay_ms(1);
		iStart = pRSTC->RTTC_RTVR;
	#endif
		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		Delay_us(10);

		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
    #if 0
		iEnd = pRSTC->RTTC_RTVR;
	#endif	
		totalEncode += iEnd - iStart;
	}

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data1[i] = rx_data[j--];
	}	

	j = 31;
	for ( i = 0; i < 16; i++)
	{
		data2[i] = rx_data[j--];
	}	

	if(memcmp(data1,AES_CTA4_0_A0002,16) == 0 && memcmp(data2,AES_CTA4_1_0_A0002,16) == 0 )
	{
		printk("\r\n PART 2 PASS");
	}
	else
	{
		success = 0;
		printk("\r\n PART 2 FAIL");
		printk("\r\ndata1");
		printbyte(data1,16);
		printk("\r\n expected");
		printbyte(AES_CTA4_0_A0002,16);

		printk("\r\ndata2");
		printbyte(data2,16);		
		printk("\r\nexpected\r\n");
		printbyte(AES_CTA4_1_0_A0002,16);
	}

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_CTA4_1_A0002[j--];
	}
	j = 15;
	for( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_CTA4_1_1_A0002[j--];
	}
	for( i = 0 ; i < 1; i++)
	{
	#if 0
		AT91F_RTTClearAlarmINT(pRSTC);
		AT91F_RTTClearRttIncINT(pRSTC);
		AT91F_RTTC_CfgPMC();
		AT91F_RTTSetPrescaler(pRSTC,1);
		AT91F_RTTRestart(pRSTC);	
	#endif		
		Delay_ms(1);
//		iStart = pRSTC->RTTC_RTVR;
		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		Delay_us(10);

		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);

		//iEnd = pRSTC->RTTC_RTVR;
		totalDecode += iEnd - iStart;
	}

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data1[i] = rx_data[j--];
	}	

	j = 31;
	for ( i = 0; i < 16; i++)
	{
		data2[i] = rx_data[j--];
	}	

	if(memcmp(data1,AES_PTA4_1_A0002,16) == 0 && memcmp(data2,AES_PTA4_1_1_A0002,16) == 0 )
	{
		printk("\r\n PART 3 PASS");
	}
	else
	{
		success = 0;
		printk("\r\n PART 3 FAIL");
		printk("\r\ndata1\r\n");
		printbyte(data1,16);
		printk("\r\nexpected");
		printbyte(AES_PTA4_1_A0002,16);
		printk("\r\ndata2\r\n");
		printbyte(data2,16);		
		printk("\r\nexpected");
		printbyte(AES_PTA4_1_1_A0002,16);
	}




	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA4_2_A0002[j--];
	}
	j = 15;
	for( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_PTA4_1_2_A0002[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data1[i] = rx_data[j--];
	}	

	j = 31;
	for ( i = 0; i < 16; i++)
	{
		data2[i] = rx_data[j--];
	}	

	if(memcmp(data1,AES_CTA4_2_A0002,16) == 0 && memcmp(data2,AES_CTA4_1_2_A0002,16) == 0 )
	{
		printk("\r\n PART 4 PASS");
	}
	else
	{
		printk("\r\n PART 4 FAIL");
		printk("\r\ndata1");
		printbyte(data1,16);
		printk("\r\n expected");
		printbyte(AES_CTA4_2_A0002,16);

		printk("\r\ndata2\r\n");
		printbyte(data2,16);		
		printk("\r\n expected");
		printbyte(AES_CTA4_1_2_A0002,16);
	}


	///////////////////////////////////////////////////////////////////////////////////////////// dummy////////////////////////////////////
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
	Reset();
	//ReadStatusRegister();

	//PrintTime(totalEncode/(1000*2),AES128ENCODE );
	//PrintTime(totalDecode/(1000*2),AES128DECODE );
	return success;
#endif
}
/*
void TEMP_OKA();
{
int i,j;
unsigned int inst = 0x00;
int success = 1;
unsigned char addr[2] = { 0x00, 0x00 };
unsigned char tx_data[64];
unsigned char rx_data[64];
unsigned char data[16];
memset(tx_data,0,64);
tx_data[4] = 0x02;
printk("\r\n 	tx_data[4] = 0x02;");
eep_page_write(0xEB,0x40, tx_data, 1);
tx_data[0] = 0x03;
tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
tx_data[0] = 0;
tspi_interface(cs, ADDR_NOR_W, RG_OKA_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
tx_data[0] = 0x0A;
tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
tx_data[0] = 0x02;
tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
j = 15;
memset(tx_data,0,64);
for ( i = 16; i < 32; i++)
{
tx_data[i] = AES_KEYA0_A0001[j--];
}
tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
Delay_us(10);
j = 15;
memset(tx_data,0,64);
for ( i = 0; i < 16; i++)
{
tx_data[i] = AES_PTA0_A0001[j--];
}
tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
Delay_us(10);
j = 15;
memset(tx_data,0,64);
for ( i = 16; i < 32; i++)
{
tx_data[i] = AES_KEYA1_A0001[j--];
}
tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);

tx_data[0] = 0x01;
tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
endOP();
return success;


}
*/
int OKA_Test_0613(void)
{
#ifdef COMPARE

	int i,j;
	unsigned int inst = 0x00;
	int success = 1;
	unsigned char addr[2] = { 0x00, 0x00 };
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char data[16];
	memset(tx_data,0,64);
	tx_data[4] = 0x02;
	//printk("\r\n 	tx_data[4] = 0x02;");
	//eep_page_write(0xEB,0x40, tx_data, 1);
	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_OKA_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x0A;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x02;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_KEYA0_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA0_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_KEYA1_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_CTA1_A0001,16) == 0)
		printk("\r\n PART I PASS");
	else
	{
		success = 0;
		printk("\r\ndata");
		printbyte(data,16);
		printk("\r\n expected ");
		printbyte(AES_CTA1_A0001,16);		
		printk("\r\n PART I FAIL");	
	}
	//printk("\r\n data\r\n");
	//printbyte(data,16);
	//printk("\r\n AES_CTA1_A0001\r\n");	
	//printbyte(AES_CTA1_A0001,16);	
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_KEYA2_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_CTA2_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA3_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA4_0_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_CTA4_0_A0001,16) == 0)
		printk("\r\n PART II PASS");
	else
	{
		success = 0;
		printk("\r\n PART II FAIL");	
		success = 0;
		printk("\r\ndata");
		printbyte(data,16);

		printk("\r\n expected ");
		printbyte(AES_CTA4_0_A0001,16);	
	}

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_CTA4_1_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_PTA4_1_A0001,16) == 0)
		printk("\r\n PART III PASS");
	else
	{
		success = 0;
		printk("\r\n PART III FAIL");	
		success = 0;
		printk("\r\ndata");
		printbyte(data,16);		

		printk("\r\n expected ");
		printbyte(AES_PTA4_1_A0001,16); 

	}

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA4_2_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_CTA4_2_A0001,16) == 0)
		printk("\r\n PART 4 PASS");
	else
	{
		success = 0;
		printk("\r\n PART 4 FAIL");	
		success = 0;
		printk("\r\ndata");
		printbyte(data,16);		

		printk("\r\n expected ");
		printbyte(AES_CTA4_2_A0001,16); 

	}

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
	//ReadStatusRegister();
	return success;

#endif
}
#if 0
int OKA_Test_0613_256(void)
{
	int i,j;
	unsigned int inst = 0x00;
	int success = 1;
	unsigned char addr[2] = { 0x00, 0x00 };
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char data[16];
	unsigned char AES_KEYA0_A0001_256[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
	unsigned char AES_PTA0_A0001_256[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
	unsigned char AES_KEYA1_A0001_256[32]= {0x00,0x0C,0x02,0x0E,0x04,0x10,0x06,0x12,0x08,0x14,0x0A,0x16,0x0C,0x18,0x0E,0x1A,0x10,0x1C,0x12,0x1E,0x14,0x20,0x16,0x22,0x18,0x24,0x1A,0x26,0x1C,0x28,0x1E,0x2A};
	unsigned char AES_CTA1_A0001_256[16] = {0xFB,0xDA,0xC1,0x84,0x9E,0x81,0xE4,0x00,0x55,0xC8,0x1C,0x49,0x77,0x23,0x9E,0x89};
	unsigned char AES_PT3_A0001_256[16] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F};
	unsigned char AES_PTA4_0_A0001_256[16] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F};
	unsigned char AES_CT4_0_A0001_256[16] = {0x6B,0x2E,0xA5,0x77,0xDE,0xDE,0x80,0x89,0x58,0x15,0x5A,0xDD,0x6C,0xB6,0x45,0xBF};
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_OKA_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x0A;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x02;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 31;
	memset(tx_data,0,64);
	for ( i = 0; i < 32; i++)
	{
		tx_data[i] = AES_KEYA0_A0001_256[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA0_A0001_256[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
	j = 31;
	memset(tx_data,0,64);
	for ( i = 0; i < 32; i++)
	{
		tx_data[i] = AES_KEYA1_A0001_256[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_CTA1_A0001_256,16) == 0)
		printk("\r\n PART I PASS");
	else
	{
		success = 0;
		printk("\r\n PART I FAIL");	
	}
	//tx_data[0] = 0x01;
	//tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	//endOP();
	//return 0;

	//printk("\r\n data\r\n");
	//printbyte(data,16);
	//printk("\r\n AES_CTA1_A0001\r\n");	
	//printbyte(AES_CTA1_A0001,16);	
	j = 31;
	memset(tx_data,0,64);
	for ( i = 0; i < 32; i++)
	{
		tx_data[i] = AES_KEYA1_A0001_256[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_CTA1_A0001_256[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PT3_A0001_256[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA4_0_A0001_256[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_CT4_0_A0001_256,16) == 0)
		printk("\r\n PART II PASS");
	else
	{
		success = 0;
		printk("\r\n PART II FAIL");	
		printk("\r\n AES_CT4_0_A0001_256 \r\n");
		printbyte(AES_CT4_0_A0001_256,16);

		printk("\r\n data \r\n");
		printbyte(data,16);
	}

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_CTA4_1_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_PTA4_1_A0001,16) == 0)
		printk("\r\n PART III PASS");
	else
	{
		success = 0;
		printk("\r\n PART III FAIL");	
	}

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA4_2_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_CTA4_2_A0001,16) == 0)
		printk("\r\n PART 4 PASS");
	else
	{
		success = 0;
		printk("\r\n PART 4 FAIL");	
	}

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
	return success;


}
#endif
unsigned char SPI_Mode_Set(unsigned char m)
{
	unsigned int i;
	unsigned int inst = 0x00;
	unsigned char addr[2] = { 0x06, 0x01};
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr_1 = 0x33;

	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}

	switch(m)
	{
	case 0  : OpModeSet();
		// ADDR_NOR_MODE_TEST1();	              
		break;
	case 1  : 
		ADDR_NOR_MODE_WRITE_TEST();	              
		break;          
	case 2  : 
		ADDR_NOR_MODE_READ_TEST();
		break; 
	case 4  : 
		CMD_NOR_MODE_WRITE_TEST();
		break; 
	case 5  : 
		CMD_NOR_MODE_READ_TEST();
		break;           

	case 3  :
		tx_data[0] = 0x06;
		//spi_interface(1, 0x22, addr, tx_data, rx_data, 1);
		break;                   

	default : break;	

	}

	return 0;
}
unsigned char eep_opmode_set()
{
	return 0;
}
void endOP(void)
{

	int i;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	Delay_ms(2);
#if PRINTFMODE
	//  PRINTLOG("\r\n=========================================================================");
	//  PRINTLOG("\r\n==       RG_ST0_OPMODE SET=> 0x01                              ==");
	// PRINTLOG("\r\n=========================================================================");
#endif	 
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

#if PRINTFMODE
	// PRINTLOG("\r\n=========================================================================");
	//PRINTLOG("\r\n==       RG_ACCESS SET=> 0x00                              ==");
	// PRINTLOG("\r\n=========================================================================");
#endif	 
	tx_data[0] = 0x00;	
	tspi_interface(cs, ADDR_NOR_W, RG_ACCESS, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(2);
	delay_us(5);
}

void OKA_SW_KEYBASE_GEN(unsigned char *InitialPT,unsigned char *KEY0,unsigned char *KEY1,unsigned char *Keybase)
{
#ifdef COMPARE

	int i;

	unsigned char pt_data[16];
	unsigned char ct_data[16];

	for( i=0; i<16; i++ ) pt_data[i] = 0x00;
	for( i=0; i<16; i++ ) ct_data[i] = 0x00;


	for( i=0; i<16; i++ ) pt_data[i] = rand();
	for( i=0; i<16; i++ ) pt_data[i] = i * 0x10;
	//for( i=0; i<16; i++ ) UniqueID[i] = rand();     //  ex. MAC ID or Phone Number, etc..

	//--- Step 1
	//   TVALUE7 = 0x01;
	for( i=0; i<16; i++ )pt_data[i]= InitialPT[i];
	for( i=0; i<16; i++ ) AESKey[i] = KEY0[i];
	KeyExpansion();

	AES128_CIPHER(pt_data, ct_data);

	for( i=0; i<16; i++ ) lps1A[i] = ct_data[i];

	//--- Step 2
	//TVALUE7 = 0x02;

	for( i=0; i<16; i++ ) AESKey[i] = KEY1[i];
	for( i=0; i<16; i++ ) pt_data[i] = ct_data[i];

	KeyExpansion();

	AES128_CIPHER(pt_data, ct_data);

	for( i=0; i<16; i++ ) Keybase[i] = ct_data[i];

#endif
}
void OKA_SW_FULLKEY_GEN(unsigned char *KEY1, unsigned char *Userdata,unsigned char *KeybaseRecieve)
{
#ifdef COMPARE

	int i;
	unsigned char pt_data[16];
	unsigned char ct_data[16];

	//--- Step 3
	// TVALUE7 = 0x02;

	for( i=0; i<16; i++ ) AESKey[i] = KEY1[i];
	for( i=0; i<16; i++ ) ct_data[i] = KeybaseRecieve[i];

	KeyExpansion();

	AES128_DECIPHER(ct_data, pt_data);

	//--- Step 4
	//TVALUE7 = 0x03;

	for( i=0; i<16; i++ ) AESKey[i] = lps1A[i] ^ pt_data[i];
	for( i=0; i<16; i++ ) pt_data[i] = Userdata[i];

	KeyExpansion();

	AES128_CIPHER(pt_data, ct_data);

	//--- Final Key Generation
	//TVALUE7 = 0x00;
	for ( i=0; i<16; i++ ) AESKey[i] = ct_data[i];

	KeyExpansion();
#endif
}


void OKA_HW_KEYBASE_GEN(unsigned char *InitialPT,unsigned char *KEY0,unsigned char *KEY1,unsigned char *Keybase, int OKA_CTRL)
{
#ifdef COMPARE

	int i,j;
	unsigned int inst = 0x00;
	int is_pass = 1;
	unsigned char addr[2] = { 0x00, 0x00 };
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char data[16];

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = OKA_CTRL;
	tspi_interface(cs, ADDR_NOR_W, RG_OKA_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x0A;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x02;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = KEY0[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = InitialPT[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = KEY1[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
		Keybase[i] =data[i];
	}
#endif

}

void OKA_HW_FULLKEY_GEN(unsigned char *KEY1, unsigned char *USER_DATA,unsigned char *Keybase)
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	int pass = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp[64] ;
	unsigned char buf_data[64];
	unsigned char data[64];
	int success = 1;
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = KEY1[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = Keybase[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = USER_DATA[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
#endif


}
int OKA_CTRL2Frame()
{
#ifdef COMPARE

	int i;
	int j;
	int t;
	unsigned int inst = 0;
	int success = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp[64] ;
	unsigned char buf_data[64];
	unsigned char data[64];
	unsigned char KEY0A[16];
	unsigned char KEY0B[16];	
	unsigned char KEY1[16];
	unsigned char USERDATA[16];
	unsigned char InitailPTA[16];
	unsigned char InitailPTB[16];	
	unsigned char KEYBASE_SW[16];
	unsigned char KEYBASE_HW[16];
	unsigned char PT[16];
	unsigned char CT_SW[16];	
	unsigned char CT_HW[16];		
	unsigned char PT_SW[16];
	unsigned char PT_HW[16];	

	unsigned char PT2[16];
	unsigned char CT_SW2[16];	
	unsigned char CT_HW2[16];		
	unsigned char PT_SW2[16];
	unsigned char PT_HW2[16];	

	memset(tx_data,0,64);
	tx_data[4] = 0x02;
	printk("\r\n 	tx_data[4] = 0x02;");


	for(i = 0; i < 16; i++)
	{
		KEY0A[i] = rand() & 0xFF;
		KEY0B[i] = rand() & 0xFF;
		KEY1[i] = rand() & 0xFF;
		USERDATA[i] = rand() & 0xFF;
		InitailPTA[i] = rand() & 0xFF;
		InitailPTB[i] = rand() & 0xFF;
		PT[i] =  rand() & 0xFF;;
		PT2[i] =  rand() & 0xFF;;		
	}


	OKA_SW_KEYBASE_GEN(InitailPTA,KEY0A,KEY1,KEYBASE_SW);
	OKA_HW_KEYBASE_GEN(InitailPTB,KEY0B,KEY1,KEYBASE_HW,1);


	OKA_SW_FULLKEY_GEN(KEY1,USERDATA,KEYBASE_HW);
	OKA_HW_FULLKEY_GEN(KEY1,USERDATA,KEYBASE_SW);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	AES128_CIPHER(PT, CT_SW);
	AES128_CIPHER(PT2, CT_SW2);	
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = PT[j--];
	}
	j = 15;
	for( i = 16; i < 32; i++)
	{
		tx_data[i] = PT2[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		CT_HW[i] = rx_data[j--];
	}

	j = 31;
	for ( i = 0; i < 16; i++)
	{
		CT_HW2[i] = rx_data[j--];
	}

	if( memcmp(CT_SW,CT_HW,16) == 0)
		printk("\r\n OKA ENCODING PASS");
	else
	{
		success = 0;
		printk("\r\n CT_SW");
		printbyte(CT_SW,16);
		printk("\r\n CT_HW");
		printbyte(CT_HW,16);		
		printk("\r\n OKA ENCODING  FAIL");		
	}

	if( memcmp(CT_SW2,CT_HW2,16) == 0)
		printk("\r\n OKA ENCODING2 PASS");
	else
	{
		success = 0;
		printk("\r\n CT_SW2");
		printbyte(CT_SW2,16);

		printk("\r\n CT_HW2");
		printbyte(CT_HW2,16);

		printk("\r\n OKA ENCODING2  FAIL");		
	}

	//return;

	AES128_DECIPHER(CT_SW,PT_SW );
	AES128_DECIPHER(CT_SW2,PT_SW2 );	
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = CT_SW[j--];
	}
	j = 15;
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = CT_SW2[j--];
	}	
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		PT_HW[i] = rx_data[j--];
	}
	j = 31;
	for ( i = 0; i < 16; i++)
	{
		PT_HW2[i] = rx_data[j--];
	}	
	if( memcmp(PT_SW,PT_HW,16) == 0)
		printk("\r\n OKA DECODING PASS");
	else
	{
		success = 0;
		printk("\r\n PT_SW");
		printbyte(PT_SW,16);

		printk("\r\n PT_HW");
		printbyte(PT_HW,16);
		success = 0;
		printk("\r\n OKA DECODING  FAIL");
	}
	if( memcmp(PT_SW2,PT_HW2,16) == 0)
		printk("\r\n OKA DECODING PASS");
	else
	{
		success = 0;
		printk("\r\n PT_SW2");
		printbyte(PT_SW2,16);

		printk("\r\n PT_HW2");
		printbyte(PT_HW2,16);		
		printk("\r\n OKA DECODING  FAIL");
	}
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
	Reset();

	//ReadStatusRegister();
	return success;
#endif

}
int OKA_CTRL(void)
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	int success = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp[64] ;
	unsigned char buf_data[64];
	unsigned char data[64];
	unsigned char KEY0A[16];
	unsigned char KEY0B[16];	
	unsigned char KEY1[16];
	unsigned char USERDATA[16];
	unsigned char InitailPTA[16];
	unsigned char InitailPTB[16];	
	unsigned char KEYBASE_SW[16];
	unsigned char KEYBASE_HW[16];
	unsigned char PT[16];
	unsigned char CT_SW[16];	
	unsigned char CT_HW[16];		
	unsigned char PT_SW[16];
	unsigned char PT_HW[16];	
	memset(tx_data,0,64);
	tx_data[4] = 0x02;
	printk("\r\n 	tx_data[4] = 0x02;");


	for(i = 0; i < 16; i++)
	{
		KEY0A[i] = rand() & 0xFF;
		KEY0B[i] = rand() & 0xFF;
		KEY1[i] = rand() & 0xFF;
		USERDATA[i] = rand() & 0xFF;
		InitailPTA[i] = rand() & 0xFF;
		InitailPTB[i] = rand() & 0xFF;
		PT[i] =  rand() & 0xFF;;
	}


	OKA_SW_KEYBASE_GEN(InitailPTA,KEY0A,KEY1,KEYBASE_SW);
	OKA_HW_KEYBASE_GEN(InitailPTB,KEY0B,KEY1,KEYBASE_HW,0);


	OKA_SW_FULLKEY_GEN(KEY1,USERDATA,KEYBASE_HW);
	OKA_HW_FULLKEY_GEN(KEY1,USERDATA,KEYBASE_SW);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	AES128_CIPHER(PT, CT_SW);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = PT[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		CT_HW[i] = rx_data[j--];
	}
	if( memcmp(CT_SW,CT_HW,16) == 0)
		printk("\r\n OKA ENCODING PASS");
	else
	{
		success = 0;
		printk("\r\n CT_SW");
		printbyte(CT_SW,16);

		printk("\r\n CT_HW");
		printbyte(CT_HW,16);
		printk("\r\n OKA ENCODING  FAIL");		
	}

	AES128_DECIPHER(CT_SW,PT_SW );
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = CT_SW[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	for ( i = 0; i < 16; i++)
	{
		PT_HW[i] = rx_data[j--];
	}
	if( memcmp(PT_SW,PT_HW,16) == 0)
		printk("\r\n OKA DECODING PASS");
	else
	{
		success = 0;
		printk("\r\n PT_SW");
		printbyte(PT_SW,16);

		printk("\r\n PT_HW");
		printbyte(PT_HW,16);
		printk("\r\n OKA DECODING  FAIL");
	}
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
	//ReadStatusRegister();
	
	return success;
#endif


}

int OKA_KEYLOAD(void)
{
#ifdef COMPARE

	int i,j;
	unsigned int inst = 0x00;
	int success = 1;
	unsigned char addr[2] = { 0x00, 0x00 };
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char data[16];
	memset(tx_data,0,64);
	tx_data[4] = 0x02;
	printk("\r\n	tx_data[4] = 0x02;");
	eep_page_write(0xEB,0x40, tx_data, 1);
	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_OKA_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x0A;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x02;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_KEYA0_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA0_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_KEYA1_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);
	j = 15;
	for ( i = 0; i < 16; i++)
	{
		data[i] = rx_data[j--];
	}
	if( memcmp(data,AES_CTA1_A0001,16) == 0)
		printk("\r\n PART I PASS");
	else
	{
		success = 0;
		printk("\r\n PART I FAIL"); 
	}
	//printk("\r\n data\r\n");
	//printbyte(data,16);
	//printk("\r\n AES_CTA1_A0001\r\n");	
	//printbyte(AES_CTA1_A0001,16); 
	j = 15;
	memset(tx_data,0,64);
	for ( i = 16; i < 32; i++)
	{
		tx_data[i] = AES_KEYA2_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF500, NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	Delay_us(10);
	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_CTA2_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);

	j = 15;
	memset(tx_data,0,64);
	for ( i = 0; i < 16; i++)
	{
		tx_data[i] = AES_PTA3_A0001[j--];
	}
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	Delay_us(10);



	//j = 15;
	//tx_data[0] = 0x01;
	//tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	//endOP();
#if 1	
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
#else
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
#endif

#if 1 // for test oka key
	endOP();
#endif


	return success;

#endif



}

void FillData(int k, unsigned char *compare_data)
{
	int i = 0;
	int j = 0;
	int t = 0;
	unsigned char buffer[16];
	j = k;
	t  = 0;
	for( i = 0 ; i < 16; i++)
		buffer[t++] = j++;
	j = 15;
	for(i = 0; i < 16; i++)
	{
		compare_data[i] = buffer[j--];
	}
	j = k;	
	t  = 0;
	for( i = 16 ; i < 32; i++)
		buffer[t++] = j++;
	j = 15;
	for(i = 0; i < 16; i++)
	{
		compare_data[i] = buffer[j--];
	}
	j = k;	
	t = 0;
	for( i = 32 ; i < 48; i++)
		buffer[t++] = j++;
	j = 15;
	for(i = 0; i < 16; i++)
	{
		compare_data[i] = buffer[j--];
	}
	j = k;	
	t = 0;
	for( i = 48 ; i < 64; i++)
		buffer[t++] = j++;
	j = 15;
	for(i = 0; i < 16; i++)
	{
		compare_data[i] = buffer[j--];
	}

}
int KeyLoadDemo2(int KeyAseCtrl,int TextSel,int KeySel, int KeySaveSel, unsigned char *LoadKEY ,int mode)
//int KeyLoadDemo(int KeyAseCtrl,int TextSel,int KeySel, int KeySaveSel)
{
	int i;
	int j;
	unsigned int inst = 0;
	int pass = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp ;
	unsigned char buf_data[64];
	int success = 1;
	unsigned char AES_KEY_X3[16] = {0x05,0x0C,0xDA,0xDE,0xE1,0x56,0x41,0x13,0xA0,0x3F,0x86,0xA6,0x6E,0xC2,0x47,0xBC};//all 0405060708090A0B0C0D0E0F10111213		
	unsigned char AES_KEY_X2[16] = {0xB8,0x59,0xE9,0x66,0xDE,0xF9,0x7D,0x89,0x3D,0x7C,0x32,0x54,0x12,0x31,0x76,0xE6};//all 030405060708090A0B0C0D0E0F101112	
	unsigned char AES_KEY_X1[16] = {0xA9,0x2F,0x2B,0xE7,0xA9,0x76,0xA1,0x23,0x96,0xCB,0x5A,0xCC,0xE9,0xE4,0xA0,0xBD};//all 02030405060708090A0B0C0D0E0F1011
	unsigned char AES_KEY_X0[16]=  {0x02,0x8D,0xBD,0xE3,0x74,0x58,0x62,0xBF,0xA1,0xD4,0x57,0x37,0x07,0xB7,0xE4,0x9A};//    0102030405060708090A0B0C0D0E0F10 with seed key which are all 0x11
	unsigned char *CYPKEY;
	unsigned char CIPHERED_KEY[32];
	unsigned char final_result[64];

	switch(KeySel)
	{
	case 0:
		CYPKEY = AES_KEY_X0;	
		break;
	case 1:
		CYPKEY = AES_KEY_X1;
		break;
	case 2:
		CYPKEY = AES_KEY_X2;
		break;
	case 3:
		CYPKEY = AES_KEY_X3;
		break;

	}
	for(i = 0; i < 64; i++)
	{
		tx_data[i] = 0;
		rx_data[i] = 0;
		buf_data[i] = 0x11;
	}

	if(LoadKEY != NULL)
	{
		AES_KEY aes256_ekey,aes256_dkey;


		AES_set_encrypt_key(buf_data, 256, &aes256_ekey);
		AES_set_decrypt_key(buf_data, 256, &aes256_dkey);

		AES_ecb_encrypt(LoadKEY, CIPHERED_KEY, &aes256_ekey, AES_ENCRYPT);
		if(mode == MODE256)		
			AES_ecb_encrypt(LoadKEY+16, CIPHERED_KEY+16, &aes256_ekey, AES_ENCRYPT);		

	}

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       KEYLOAD   TEST                                    ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       WRITE SEED KEY                                   ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 
	////gPrintOut = 0;
#if 0
	{
		//GetSuperWirePermission();
		if(eep_page_write(ADDR_EE_SEED_KEY[0], ADDR_EE_SEED_KEY[1], buf_data, 1) )
			PRINTLOG("\r\nSUCCESS TO WRITE SEEDKEY");
		else
			PRINTLOG("\r\nFAIL TO WRITE SEEDKEY");

	}
	delay_ms(10);

	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");			
	PRINTLOG("\r\n++BEFORE KEY LOAD READ EE_KEY_AES_x");
	switch(KeyAseCtrl)
	{
	case 0:	
		PRINTLOG("%d",KeyAseCtrl );
		eep_page_read(ADDR_EE_KEY_AES_x0[0],ADDR_EE_KEY_AES_x0[1],0,NULL);
		break;
	case 1:
		PRINTLOG("%d",KeyAseCtrl );			
		eep_page_read(ADDR_EE_KEY_AES_x1[0],ADDR_EE_KEY_AES_x1[1],0,NULL);
		break;
	case 2:
		PRINTLOG("%d",KeyAseCtrl );			
		eep_page_read(ADDR_EE_KEY_AES_x2[0],ADDR_EE_KEY_AES_x2[1],0,NULL);
		break;
	case 3:
		PRINTLOG("%d",KeyAseCtrl );			
		eep_page_read(ADDR_EE_KEY_AES_x3[0],ADDR_EE_KEY_AES_x3[1],0,NULL);	
		break;
	}
#endif
#if 0

	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");			
#endif
#if PRINTFMODE
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       KEY LOAD DEMO START                                   ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 
	//g
	//gPrintOut = 1
#if 0	
	PRINTLOG("\r\n KeyAseCtrl: %d KeySel:%d  TextSel:%d,KeySaveSel:%d",	KeyAseCtrl,KeySel,TextSel,KeySaveSel);
#endif
	tx_data[0] = KeyAseCtrl;// EE_KEY_AES_x0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] =  (KeySaveSel<<4)//KL_KeySaveSel
		|(TextSel<<2)
		|(KeySel); //KL_KEYSEL
//	PRINTLOG("RG_KL_CTRL 0x%02x",tx_data[0]);
	tspi_interface(cs, ADDR_NOR_W, RG_KL_CTRL   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	if(TextSel == 2)
	{
		for( i = 0; i < 64; i++)
			tx_data[i] = i;
		WriteRGEBUF(tx_data);
	}

	tx_data[0] = 0x01;// AES_256
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	tx_data[0] = 0x09;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x06;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_us(30);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST2_SYMCIP_OPMODE   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x09;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST2_SYMCIP_OPMODE   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x02;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST3_SYMCIP_KEYLOAD_OPMODE   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,  RG_ACCESS    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 15;
#if 1
	if(TextSel == 0)
	{
		for(i = 0; i < 16; i++)
			tx_data[i] = CYPKEY[j--];


		if(LoadKEY != NULL)
		{
			j = 31;
			for(i = 0; i < 16; i++)
				tx_data[i] = CIPHERED_KEY[j--];
		}
		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400   , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	}
#else
	if(TextSel == 0)
	{
		memset(tx_data,0,64);
		for(i = 16; i < 32; i++)
			tx_data[i] = CYPKEY[j--];
		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400   , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	}

#endif
	//	delay_us(70);
	delay_us(70*2);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W,  	RG_ST3_SYMCIP_KEYLOAD_OPMODE     , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,  RG_ACCESS    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(TextSel == 0)
	{


		if(LoadKEY != NULL)
		{
			if(mode == MODE256)
			{
				j = 15;
				for(i = 0; i < 16; i++)
					tx_data[i] = CIPHERED_KEY[j--];
				tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400   , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);				
			}
		}
		else
		{
			j = 15;
			for(i = 0; i < 16; i++)
				tx_data[i] = CYPKEY[j--];
			tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400   , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
		}
	}
	//	delay_us(100);
	delay_ms(16);


	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST3_SYMCIP_KEYLOAD_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST2_SYMCIP_OPMODE     , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
#if PRINTFMODE
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       KEY LOAD DEMO END                                   ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 

	//gPrintOut = 0;
	delay_ms(16);
	endOP();
	//eep_page_read(ADDR_EE_KEY_AES_x0[0],ADDR_EE_KEY_AES_x0[1],0,final_result);
	j = 31;
	for( i = 0; i < 32; i++)
		KEY_GLOBAL_BUFFER[i] = final_result[j--];
#if 0
	{
		unsigned char final_result[64] = {0,};
		unsigned char compare_data[64] = {0,};
		printk("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");			
		printk("\r\n++AFTER KEY LOAD READ EE_KEY_AES_x");
		switch(KeyAseCtrl)
		{
		case 0:	
			printk("r\n\r\n AESx0 %d",KeyAseCtrl );
			eep_page_read(ADDR_EE_KEY_AES_x0[0],ADDR_EE_KEY_AES_x0[1],0,final_result);
			j = 31;
			for( i = 0; i < 32; i++)
				KEY_GLOBAL_BUFFER[i] = final_result[j--];
			//memset(compare_data,0xaa,64);
			break;
			FillData(1,compare_data);
			if(memcmp(final_result,compare_data,64 != 0) )
				success = 0;
			break;
		case 1:
			printk("%d",KeyAseCtrl );			
			eep_page_read(ADDR_EE_KEY_AES_x1[0],ADDR_EE_KEY_AES_x1[1],0,final_result);
			//memset(compare_data,0xbb,64);
			FillData(2,compare_data);
			if(memcmp(final_result,compare_data,64 != 0) )
				success = 0;
			break;
		case 2:
			printk("%d",KeyAseCtrl );			
			eep_page_read(ADDR_EE_KEY_AES_x2[0],ADDR_EE_KEY_AES_x2[1],0,final_result);
			//memset(compare_data,0xcc,64);
			FillData(3,compare_data);
			if(memcmp(final_result,compare_data,64 != 0) )
				success = 0;
			break;
		case 3:
			printk("%d",KeyAseCtrl );			
			eep_page_read(ADDR_EE_KEY_AES_x3[0],ADDR_EE_KEY_AES_x3[1],0,final_result);	
			//memset(compare_data,0xdd,64);
			FillData(4,compare_data);			
			if(memcmp(final_result,compare_data,64 != 0))
				success = 0;	
			break;
		}
	}
#endif
	//printk("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");			
	delay_ms(10);

	//ReadKEYAES_X();
	return success;
	//ReleasePermision();
	//gPrintOut = 1;	
}

int KeyLoadDemo(int KeyAseCtrl,int TextSel,int KeySel, int KeySaveSel, unsigned char *LoadKEY ,int mode)
//int KeyLoadDemo(int KeyAseCtrl,int TextSel,int KeySel, int KeySaveSel)
{
	int i;
	int j;
	unsigned int inst = 0;
	int pass = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp ;
	unsigned char buf_data[64];
	int success = 1;
	unsigned char AES_KEY_X3[16] = {0x05,0x0C,0xDA,0xDE,0xE1,0x56,0x41,0x13,0xA0,0x3F,0x86,0xA6,0x6E,0xC2,0x47,0xBC};//all 0405060708090A0B0C0D0E0F10111213		
	unsigned char AES_KEY_X2[16] = {0xB8,0x59,0xE9,0x66,0xDE,0xF9,0x7D,0x89,0x3D,0x7C,0x32,0x54,0x12,0x31,0x76,0xE6};//all 030405060708090A0B0C0D0E0F101112	
	unsigned char AES_KEY_X1[16] = {0xA9,0x2F,0x2B,0xE7,0xA9,0x76,0xA1,0x23,0x96,0xCB,0x5A,0xCC,0xE9,0xE4,0xA0,0xBD};//all 02030405060708090A0B0C0D0E0F1011
	unsigned char AES_KEY_X0[16]=  {0x02,0x8D,0xBD,0xE3,0x74,0x58,0x62,0xBF,0xA1,0xD4,0x57,0x37,0x07,0xB7,0xE4,0x9A};//    0102030405060708090A0B0C0D0E0F10 with seed key which are all 0x11
	unsigned char *CYPKEY;
	unsigned char CIPHERED_KEY[32];

	switch(KeySel)
	{
	case 0:
		CYPKEY = AES_KEY_X0;	
		break;
	case 1:
		CYPKEY = AES_KEY_X1;
		break;
	case 2:
		CYPKEY = AES_KEY_X2;
		break;
	case 3:
		CYPKEY = AES_KEY_X3;
		break;

	}
	for(i = 0; i < 64; i++)
	{
		tx_data[i] = 0;
		rx_data[i] = 0;
		buf_data[i] = 0x11;
	}

	if(LoadKEY != NULL)
	{
		AES_KEY aes256_ekey,aes256_dkey;


		AES_set_encrypt_key(buf_data, 256, &aes256_ekey);
		AES_set_decrypt_key(buf_data, 256, &aes256_dkey);

		AES_ecb_encrypt(LoadKEY, CIPHERED_KEY, &aes256_ekey, AES_ENCRYPT);
		if(mode == MODE256)		
			AES_ecb_encrypt(LoadKEY+16, CIPHERED_KEY+16, &aes256_ekey, AES_ENCRYPT);		

	}

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       KEYLOAD   TEST                                    ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 

#if PRINTFMODE_PERMISSION
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       WRITE SEED KEY                                   ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 
	////gPrintOut = 0;
	/*
	{
		//GetSuperWirePermission();
		if(eep_page_write(ADDR_EE_SEED_KEY[0], ADDR_EE_SEED_KEY[1], buf_data, 1) )
			PRINTLOG("\r\nSUCCESS TO WRITE SEEDKEY");
		else
			PRINTLOG("\r\nFAIL TO WRITE SEEDKEY");

	}
	*/
	delay_ms(10);

	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");			
	PRINTLOG("\r\n++BEFORE KEY LOAD READ EE_KEY_AES_x");
	#if 0
	switch(KeyAseCtrl)
	{
	case 0:	
		PRINTLOG("%d",KeyAseCtrl );
		eep_page_read(ADDR_EE_KEY_AES_x0[0],ADDR_EE_KEY_AES_x0[1],0,NULL);
		break;
	case 1:
		PRINTLOG("%d",KeyAseCtrl );			
		eep_page_read(ADDR_EE_KEY_AES_x1[0],ADDR_EE_KEY_AES_x1[1],0,NULL);
		break;
	case 2:
		PRINTLOG("%d",KeyAseCtrl );			
		eep_page_read(ADDR_EE_KEY_AES_x2[0],ADDR_EE_KEY_AES_x2[1],0,NULL);
		break;
	case 3:
		PRINTLOG("%d",KeyAseCtrl );			
		eep_page_read(ADDR_EE_KEY_AES_x3[0],ADDR_EE_KEY_AES_x3[1],0,NULL);	
		break;
	}
	#endif
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");			
#if PRINTFMODE
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       KEY LOAD DEMO START                                   ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 
	//g
	//gPrintOut = 1
	PRINTLOG("\r\n KeyAseCtrl: %d KeySel:%d  TextSel:%d,KeySaveSel:%d",	KeyAseCtrl,KeySel,TextSel,KeySaveSel);
	tx_data[0] = KeyAseCtrl;// EE_KEY_AES_x0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] =  (KeySaveSel<<4)//KL_KeySaveSel
		|(TextSel<<2)
		|(KeySel); //KL_KEYSEL
	PRINTLOG("RG_KL_CTRL 0x%02x",tx_data[0]);
	tspi_interface(cs, ADDR_NOR_W, RG_KL_CTRL   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	/*
	if(TextSel == 2)
	{
	for( i = 0; i < 64; i++)
	tx_data[i] = i;
	WriteRGEBUF(tx_data);
	}
	*/
	tx_data[0] = 0x01;// AES_256
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	tx_data[0] = 0x09;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x06;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_us(30);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST2_SYMCIP_OPMODE   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x09;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST2_SYMCIP_OPMODE   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x02;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST3_SYMCIP_KEYLOAD_OPMODE   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,  RG_ACCESS    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 15;
#if 1
	if(TextSel == 0)
	{
		for(i = 0; i < 16; i++)
			tx_data[i] = CYPKEY[j--];


		if(LoadKEY != NULL)
		{
			j = 31;
			for(i = 0; i < 16; i++)
				tx_data[i] = CIPHERED_KEY[j--];
		}
		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400   , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	}
#else
	if(TextSel == 0)
	{
		memset(tx_data,0,64);
		for(i = 16; i < 32; i++)
			tx_data[i] = CYPKEY[j--];
		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400   , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
	}

#endif
	//	delay_us(70);
	delay_us(70*2);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W,  	RG_ST3_SYMCIP_KEYLOAD_OPMODE     , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,  RG_ACCESS    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(TextSel == 0)
	{


		if(LoadKEY != NULL)
		{
			if(mode == MODE256)
			{
				j = 15;
				for(i = 0; i < 16; i++)
					tx_data[i] = CIPHERED_KEY[j--];
				tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400   , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);				
			}
		}
		else
		{
			j = 15;
			for(i = 0; i < 16; i++)
				tx_data[i] = CYPKEY[j--];
			tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400   , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
		}
	}
	//	delay_us(100);
	delay_ms(16);

	if(TextSel == 2)
	{
		tx_data[0] = 0x01;
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_OKA_OPMODE, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	}
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST3_SYMCIP_KEYLOAD_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST2_SYMCIP_OPMODE     , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

#if PRINTFMODE
	PRINTLOG("\r\n\n");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	PRINTLOG("\r\n==       KEY LOAD DEMO END                                   ==");
	PRINTLOG("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#endif 

	//gPrintOut = 0;
	delay_ms(16);
	endOP();
	{
		unsigned char final_result[64] = {0,};
		unsigned char compare_data[64] = {0,};
		printk("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");			
		printk("\r\n++AFTER KEY LOAD READ EE_KEY_AES_x");
		switch(KeyAseCtrl)
		{
		case 0:	
			printk("%d",KeyAseCtrl );
			eep_page_read(ADDR_EE_KEY_AES_x0[0],ADDR_EE_KEY_AES_x0[1],0,final_result);
			//memset(compare_data,0xaa,64);
			FillData(1,compare_data);
			if(memcmp(final_result,compare_data,64 != 0) )
				success = 0;
			break;
		case 1:
			printk("%d",KeyAseCtrl );		
			printk("\r\n enter read");
			eep_page_read(ADDR_EE_KEY_AES_x1[0],ADDR_EE_KEY_AES_x1[1],0,final_result);
			//memset(compare_data,0xbb,64);
			FillData(2,compare_data);
			if(memcmp(final_result,compare_data,64 != 0) )
				success = 0;
			break;
		case 2:
			printk("%d",KeyAseCtrl );			
			eep_page_read(ADDR_EE_KEY_AES_x2[0],ADDR_EE_KEY_AES_x2[1],0,final_result);
			//memset(compare_data,0xcc,64);
			FillData(3,compare_data);
			if(memcmp(final_result,compare_data,64 != 0) )
				success = 0;
			break;
		case 3:
			printk("%d",KeyAseCtrl );			
			eep_page_read(ADDR_EE_KEY_AES_x3[0],ADDR_EE_KEY_AES_x3[1],0,final_result);	
			//memset(compare_data,0xdd,64);
			FillData(4,compare_data);			
			if(memcmp(final_result,compare_data,64 != 0))
				success = 0;	
			break;
		}
	}
	printk("\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");			
	delay_ms(10);
	endOP();
	//ReadKEYAES_X();
	return success;
	//ReleasePermision();
	//gPrintOut = 1;	
}
void GoStanbyMode()
{
	int i;
	int j;
	unsigned int inst = 0;
	int pass = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp ;
	unsigned char buf_data[64];

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST2_SYMCIP_OPMODE     , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,  RG_ST3_SYMCIP_KEYLOAD_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

}
void SetKEYNormal()
{
	int i;
	int j;
	unsigned int inst = 0;
	int pass = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp ;
	unsigned char buf_data[64];
	unsigned char eep_data[64];
	unsigned char addr[2];
	unsigned char Data[64];

	unsigned char msb = 0xe9;
	unsigned char lsb = 0x00;

	memset(tx_data,0,64);
	for( i=16; i<32; i++)
		//for( i=0; i<16; i++)
	{
		tx_data[i] = 0x11;
	}	


#if USING_KEYLOAD
//	printk("\r\n ================================== SETKEYNORMAL================================== ");
	KEY_SET(tx_data);			
//	printk("\r\n SET AESx0 as 11 \r\n");

#else		

	eep_page_write(msb, lsb, tx_data, 1);

#endif
}
int DirReadAES_KEYx3()
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	int success = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp ;
	unsigned char buf_data[64];
	unsigned char eep_data[64];
	unsigned char addr[2];
	unsigned char Data[64];

	//	SetKEYNormal();

	GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);

	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 1 << 6;
	tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x09;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400		  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	printk("\r\n rx_data");
	printbyte(rx_data,32);	
	memcpy(buf_data,rx_data,32);
	addr[0] = 0xFF;
	addr[1] = 0xFF;	
	PrintBuffer(TYPE_RX,rx_data,addr);
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();

	eep_page_read(0xE9,0xC0, 0, eep_data);
	if(memcmp(buf_data,eep_data,32) == 0)
		printk("\r\n TEST PASS");
	else
	{
		printk("\r\n TEST FAIL");
		success = 0;
	}
	return success;
	/*	printk("\r\n rx_data");
	printbyte(rx_data,32);
	printk("\r\n eep_data");
	printbyte(eep_data,32);	
	*/
	/*	tx_data[0] = 0xE9;
	tx_data[1] = 0xC0;// 0xeb
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB      , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);
	addr[0] = 0xE9;
	addr[1] = 0xC0;
	delay_ms(8);

	addr[0] = 0xE9;
	addr[1] = 0xC0;
	printk("\r\n READ DATA");
	tx_data[0] = 1 << 6;
	tspi_interface(cs, ADDR_NOR_W,  RG_RSCREATE_CTRL     , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	delay_us(10);
	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	endOP();
	PrintBuffer(TYPE_RX,rx_data,addr);
	delay_us(10);
	eep_page_read(0xE9,0xC0, 0, eep_data);
	if(memcmp(rx_data,eep_data,32) == 0)
	printk("\r\n TEST PASS");
	else
	printk("\r\n TEST FAIL");
	*/
#endif
}
void MAKE_RANDOM_SEED_KEY()
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr[2];
	unsigned char buf0xxx[64];
	int TestSize =0 ;
	int success = 1;
	unsigned char msb = 0xe9;
	unsigned char lsb = 0x00;

	//	SetKEYNormal();


	GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);

	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE	  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	addr[0] = 0xEC;
	addr[1] = 0x00;
	tx_data[0] = addr[1];// 0x00
	tx_data[1] = addr[0];// 0xeb

	for( i = 0; i < 64; i++)
		buf0xxx[i] = rand() & 0xFF;

	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);

	tspi_interface(cs, 0x30, addr	   , NULL, NULL, NULL, NULL, buf0xxx, rx_data, 64);
	PrintBuffer(TYPE_TX,buf0xxx,addr);
	delay_ms(8);
	tspi_interface(cs, 0x20, addr	   , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(TYPE_RX,rx_data,addr);
	delay_us(10);
	endOP();
#endif

}
int MakeRanDomKEY()
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr[2];
	unsigned char buf0xxx[64];
	int TestSize =0;
	int success = 1;
	int iResult = 0;
	int HitCnt = 0;
	int MissCnt = 0;

	unsigned char KEY[32];
	unsigned char KEY_REVERSE[32];
	for( i = 0; i < 32; i++)
		KEY[i] = rand() & 0xFF; 	
	j = 15;
	for( i = 0; i < 16; i++)
		KEY_REVERSE[i] = KEY[j--];

	j = 31;
	for( i = 16; i < 32; i++)
		KEY_REVERSE[i] = KEY[j--];
	printk("\r\n MAKE RANDOM KEY on AES KEY0");
	printk("\r\n KEY");
	printbyte(KEY,32);
	KEY_SET(KEY);
	printk("\r\n READ AES KEY 0");
	eep_page_read(0xE9, 0x00, 0, tx_data);
	if(memcmp(KEY_REVERSE,tx_data,32) != 0)
	{	printk("\r\n FAIL-1");
	printk("\r\n KEY_REVERSE");
	printbyte(KEY_REVERSE,32);
	printk("\r\n READ KEY");
	printbyte(tx_data,32);

	success = 0;
	}
	SetKEYNormal();
	return success;
	#endif
}
int MakeOKAKEY()
{
#ifdef COMPARE

	int i,j;
	int success = 1;
	unsigned char Buffer[64];
	unsigned char OKA_KEY[16] = {0x8F,0xFF,0x53,0x2B,0x19,0x3F,0xDC,0x39,0xFD,0xEE,0x2D,0x34,0xC3,0x2C,0xE8,0xD5};
	unsigned char OKA_KEY_REVERSE[16];
	printk("\r\n OKA_KEYLOAD");
	memset(Buffer,0x11,64);
	//eep_page_write(0,0, Buffer,1);
	eep_page_write(0xec,0, Buffer,1);
	

	
	delay_ms(10);
	OKA_KEYLOAD();
	KeyLoadDemo(0,2,0,1,NULL,0);
//	KeyLoadDemo2(0,2,0,1,NULL,0);
	eep_page_read(0xe9,0, 0, Buffer);
	j = 15 ;
	for( i = 0; i < 16; i++)
		OKA_KEY_REVERSE[i] = OKA_KEY[j--];
	SetKEYNormal();
	if(memcmp(Buffer+16,OKA_KEY_REVERSE,16) != 0)
	{
		success = 0;
		printk("\r\n OKA_KEY_MADE");
		printbyte(Buffer+16,16);
		printk("\r\n OKA_KEY_FIXED");
		printbyte(OKA_KEY_REVERSE,16);		
	}
	else
	{

	}

	return success;
#endif
}
int AESx3Read()
{
#ifdef COMPARE
	int i;
	int j;
	unsigned int inst = 0;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr[2];
	unsigned char buf0xxx[64];
	int TestSize =0;
	int success = 1;
	int iResult = 0;
	int HitCnt = 0;
	int MissCnt = 0;
	unsigned char temp;
	addr[0] = ADDR_EE_KEY_AES_x3[0];
	addr[1] = ADDR_EE_KEY_AES_x3[1];					
	GetPermissionByPW(UID_PW_CT,RG_PERM_UID_PASS);
	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	//	SetAddrbyType(type,addr);
	/*
	tx_data[0] = addr[1];// 0x00
	tx_data[1] = addr[0];// 0xeb
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB      , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);
	*/
	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(1,rx_data,addr);
	delay_us(10);
	endOP();
	eep_page_read(0xE9, 0, 0, buf0xxx);
	/*	
	j = 15;
	for( i = 0; i < 32 ; i++)
	tx_data[i] = rx_data[j--];
	memcmp(tx_data,buf)
	*/
	if(memcmp(rx_data,buf0xxx,32) != 0)
		success = 0;

	return success;
#endif
}
void KEYLOAD_TEST_MAIN()
{

#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr[2];
	unsigned char buf0xxx[64];
	int TestSize =0;
	int success = 1;
	int iResult = 0;
	int HitCnt = 0;
	int MissCnt = 0;
	unsigned char temp;
L_KEYLOAD_START:
	while(1)
	{
		temp = 'z' ;
		printk("\r\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  *            KEYLOAD     TEST MAIN                                                  *");
		printk("\r\n  *****************************************************");
		printk("\r\n  * number of iteration     %d                            *",NumOfIterKEYLoad );		
		printk("\r\n  * 0. Set KEY_AES_CTRL      Current :%d                        *",KEY_AES_CTRL);	
		printk("\r\n  * 1. Set KL_TextSel      Current :%d                        *",KL_TextSel);	
		printk("\r\n  * 2. Set KL_KeySel       Current :%d                   *",KL_KeySel);
		printk("\r\n  * 3. Set KL_KeySaveSel    Current :%d                         *",KL_KeySaveSel);		
		printk("\r\n  * 4. TEST demo                                       *");				
		printk("\r\n  * 5. Read KEY_AES_X                                        *");						
		printk("\r\n  * 6. Reset All KEYS");
		printk("\r\n  * 7.-> KEYLOAD 0123 at ontime                           *");
		printk("\r\n  * 8.-> Read KEY_AES_3 width UID_PERMISSION                           *");		
		printk("\r\n  * 9.-> MAKE AES KEY0 by Random                          *");		
		printk("\r\n  * a.-> MAKE OKA KEY                          *");				
		//printk("\r\n  * 9. KEYSET USING GIVEN VALUE                           *");				
		printk("\r\n  * m. return to top menu                                      *");	
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n");
		printk("\r\n");
		printk("\r\n  * Select : ");

		while(temp == 'z')
		{
			temp = _uart_get_char();

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");

			if(temp == 0x0d)
				goto L_KEYLOAD_START;
			if(temp == 'm')
			{
				printk("\r\nm is pressed");

				return;
			}
			MissCnt = 0;
			HitCnt = 0;
			switch ( temp )
			{
			case 'a' :
				for(i = 0; i < NumOfIterKEYLoad;i++)
				{
					printk("\r\n KEYLOAD TEST BEGIN");
					iResult = MakeOKAKEY();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{

						HitCnt++;
					}

				}				
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				break;				
				break;
			case '9' :
				for(i = 0; i < NumOfIterKEYLoad;i++)
				{
					printk("\r\n KEYLOAD TEST BEGIN");
					iResult = MakeRanDomKEY();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{

						HitCnt++;
					}

				}				
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				break;
			case 'i' : 
				printk("\r\n input number of iteration : (4digit)");
				printk("\r\n 0x");
				NumOfIterKEYLoad = get_int();
				NumOfIterKEYLoad =( NumOfIterKEYLoad<<8)| get_int();		 
				break;
#if 0
			case '8':
				for(i = 0; i < NumOfIterKEYLoad;i++)
				{
					printk("\r\n KEYLOAD TEST BEGIN");
					iResult = AESx3Read();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{

						HitCnt++;
					}
				}
				//KeyLoadDemo(0);
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				//KeyLoadDemo(2);
				//KeyLoadDemo(3);
				printk("\r\n KEYLOAD TEST END");				
				break;



#endif

			case '4' : 
				for(i = 0; i < NumOfIterKEYLoad;i++)
				{
					printk("\r\n KEYLOAD TEST BEGIN");
					iResult = KeyLoadDemo(KEY_AES_CTRL,KL_TextSel,KL_KeySel,KL_KeySaveSel,0,0);;
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{

						HitCnt++;
					}
					SetKEYNormal();
				}
				//KeyLoadDemo(0);
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				//KeyLoadDemo(2);
				//KeyLoadDemo(3);
				printk("\r\n KEYLOAD TEST END");				
				break;
			case '7':
				for(i = 0; i < NumOfIterKEYLoad;i++)
				{
					memset(tx_data,0,64);
					eep_page_write(ADDR_EE_KEY_AES_x0[0], ADDR_EE_KEY_AES_x0[1], tx_data, 1);
					eep_page_write(ADDR_EE_KEY_AES_x1[0], ADDR_EE_KEY_AES_x1[1], tx_data, 1);
					eep_page_write(ADDR_EE_KEY_AES_x2[0], ADDR_EE_KEY_AES_x2[1], tx_data, 1);
					eep_page_write(ADDR_EE_KEY_AES_x3[0], ADDR_EE_KEY_AES_x3[1], tx_data, 1);

					iResult = KeyLoadDemo(0,0,0,0,0,0);
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission*4);
						goto L_KEYLOAD_START;
#endif
					}
					else
					{

						HitCnt++;
					}
					iResult = KeyLoadDemo(1,0,1,0,0,0);
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission*4);
						goto L_KEYLOAD_START;
#endif
					}
					else
					{

						HitCnt++;
					}			
					iResult = KeyLoadDemo(2,0,2,0,0,0);;
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission*4);
						goto L_KEYLOAD_START;
#endif
					}
					else
					{

						HitCnt++;
					}			
					iResult = KeyLoadDemo(3,0,3,0,0,0);;
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission*4);
						goto L_KEYLOAD_START;
#endif
					}
					else
					{

						HitCnt++;
					}					

				}				
				SetKEYNormal();
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission*4);
				break;
				/*	
				case '2' :
				printk("\r\n input value (16digit)");					
				printk("\r\n 0x");
				for( i = 0; i < 8; i++)
				{
				temp = 	get_int();
				tx_data[i]  = temp;
				}
				goto L_KEYLOAD_START;
				break; 
				*/
			case '8':
				printk("\r\n DirReadAES_KEYx3 START");
				for(i = 0; i < NumOfIterKEYLoad;i++)
				{
					printk("\r\n KEYLOAD TEST BEGIN");
					iResult = DirReadAES_KEYx3();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;
#if ERROR_EXIT

						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{

						HitCnt++;
					}

				}

				printk("\r\n DirReadAES_KEYx3 END");
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				break;
				/*	
				case '9':
				{
				unsigned char KEYLOAD[32];
				for(i = 0; i < 32; i++)
				KEYLOAD[i] = i;

				//KeyLoadDemo(0,0,0,0,KEYLOAD,MODE256);

				printk("\r\n ================== MODE 128 =====================");
				for(i = 0; i < 32; i++)
				KEYLOAD[i] = i +0x40;					
				KeyLoadDemo(0,0,0,0,KEYLOAD,MODE256);


				}
				break;
				*/
			case '0':
				printk("\r\n input 2digit");
				printk("\r\n 0x");
				KEY_AES_CTRL = get_int();
				break;

			case '1':
				printk("\r\n input 2digit");
				printk("\r\n 0x");
				KL_TextSel = get_int();
				break;
			case '2':
				printk("\r\n input 2digit");
				printk("\r\n 0x");
				KL_KeySel = get_int();
				break;
			case '3':
				printk("\r\n input 2digit");						
				printk("\r\n 0x");
				KL_KeySaveSel = get_int();
				break;
			case '5':
				ReadKEYAES_X();
				break;
			case '6':
				memset(tx_data,0,64);
				eep_page_write(ADDR_EE_KEY_AES_x0[0], ADDR_EE_KEY_AES_x0[1], tx_data, 1);
				eep_page_write(ADDR_EE_KEY_AES_x1[0], ADDR_EE_KEY_AES_x1[1], tx_data, 1);
				eep_page_write(ADDR_EE_KEY_AES_x2[0], ADDR_EE_KEY_AES_x2[1], tx_data, 1);
				eep_page_write(ADDR_EE_KEY_AES_x3[0], ADDR_EE_KEY_AES_x3[1], tx_data, 1);
			default :
				//					temp = 'p'; break;
				break;
			}

		}

	}
	#endif

}

void CommonDecEncWirteRead(unsigned char PageInfo, int AES_CTRL)
{	

	int i;
	int j;
	unsigned int inst = 0;
	int pass = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp ;
	unsigned char buf_data[64];
	unsigned char data[32];
	memset(data,0xaa,32);
	//PRINTLOG("\r\n 1. KEY SETTING");
	//if(eep_page_write(0xE9,0x00,data,1) )
	//	PRINTLOG(" PASS");
	//eep_page_read(0xE9, 0x00,0,NULL);	
	//eep_page_read(0xF1, 0x00,0,NULL);

	tx_data[0] = 0x00;// AES_x0 KEY
	tspi_interface(cs, ADDR_NOR_W,  RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	//tx_data[0] = 0x01;//AES_256
	//printk("\r\n AES CTRL %d",AES_CTRL);
	tx_data[0] =  AES_CTRL;
	tspi_interface(cs, ADDR_NOR_W,  RG_AES_CTRL       , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x9;//SYMCIP MODE
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x4;//AESEncWrite Mode
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = PageInfo;//USER_ZONE_M01
	tspi_interface(cs, ADDR_NOR_W, RG_EE_USER_ZONE_SEL    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 3;// AES_KEY_SET
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE     , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_us(30);

	tx_data[0] = 1;//STAND BLYE
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

}

void GetLowSequence(int index, unsigned char *data)
{
	int i = 0;
	int j = 0;
	if(index <= 120 )
	{
		j = 0;
		for( i = 0; i < 16; i++)
			data[i] = j++ + index;
	}
	if(index > 120 && index <= 240 )
	{
		j = 0;
		for( i = 0; i < 16; i++)
			data[i] = j++ + index;
	}
	if(index > 240)
	{
		index = index -240;
		j = 0;
		for( i = 0; i < 16; i++)
		{
			data[i] = j + index;
			j += 2;
		}
	}
}
void GetCTAES256(int index, unsigned char *CT)
{
	unsigned char KEY[32] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
	unsigned char Data[16];
	AES_KEY aes256_ekey,aes256_dkey;
	AES_set_encrypt_key(KEY, 256, &aes256_ekey);
	AES_set_decrypt_key(KEY, 256, &aes256_dkey);
	GetLowSequence(index,Data);
	//printk("\r\n index %d",index);
	//printk("\r\n data \r\n");
	//printbyte(Data,16);
	AES_ecb_encrypt(Data, CT, &aes256_ekey, AES_ENCRYPT);
}
void GetCTAES128(int index, unsigned char *CT)
{
	unsigned char KEY[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
	unsigned char Data[16];
	AES_KEY aes128_ekey,aes128_dkey;
	AES_set_encrypt_key(KEY, 128, &aes128_ekey);
	AES_set_decrypt_key(KEY, 128, &aes128_dkey);
	GetLowSequence(index,Data);
	//printk("\r\n index %d",index);
	//printk("\r\n data \r\n");
	//printbyte(Data,16);
	AES_ecb_encrypt(Data, CT, &aes128_ekey, AES_ENCRYPT);
}
void GetCTARIA256(int index, unsigned char *CT)
{
#ifdef COMPARE
	unsigned char KEY[32] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
	unsigned char Data[16];
	ARIA_KEY ARIA256_ekey,ARIA256_dkey;
	aria_set_encrypt_key(KEY, 256, &ARIA256_ekey);
	aria_set_decrypt_key(KEY, 256, &ARIA256_dkey);
	GetLowSequence(index,Data);
	//printk("\r\n index %d",index);
	//printk("\r\n data \r\n");
	//printbyte(Data,16);
	aria_encrypt(Data, CT, &ARIA256_ekey);
#endif
}
void GetCTARIA128(int index, unsigned char *CT)
{
#ifdef COMPARE
	unsigned char KEY[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
	unsigned char Data[16];
	ARIA_KEY ARIA128_ekey,ARIA128_dkey;
	aria_set_encrypt_key(KEY, 128, &ARIA128_ekey);
	aria_set_decrypt_key(KEY, 128, &ARIA128_dkey);
	GetLowSequence(index,Data);
	//printk("\r\n index %d",index);
	//printk("\r\n data \r\n");
	//printbyte(Data,16);
	aria_encrypt(Data, CT, &ARIA128_ekey);
#endif
}

int DecWrite(int AES_ARIA)
{
#ifdef COMPARE

	int i;
	int j;
	int k;
	int t;
	unsigned char Page,SubPage,SubFrame;
	unsigned int inst = 0;
	int success = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp ;
	unsigned char buf_data[4][16];
	unsigned char buf_eeprom[64];
	unsigned char buf_temp[16];
	unsigned char ErrorPage[16*4];
	//unsigned char CT[16] = {0x60,0x89,0x9C,0x60,0xFB,0x8A,0x9D,0x2D,0x27,0x70,0xC8,0x24,0x00,0xC6,0x50,0xEA};//PT 0405060708090A0B0C0D0E0F10111213
	unsigned char CT[16];
	int Cnt = 0;
	unsigned char KEY[32] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
	int is256 = (AES_ARIA & 2) >> 1;
	int isAESARIA = (AES_ARIA & 1)? 1: 0 ;
	int cnt_error = 0;
	printk("\r\n memeset before");
	memset(ErrorPage,0,16*4);
	//unsigned char *pCT[16*4*4]; 
	Page = 0;
	SubPage= 0;
	SubFrame = 0;
	printk("\r\n memeset after");
	// WRITE KEY
	//KEY 0102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F10
	START;
	j = 31;
	for(i = 0; i < 32; i++)
		tx_data[i] = KEY[j--];	
#if 0
	KEY_SET(KEY);
#else
	printk("\r\n Write KEY AESX0");	
	eep_page_write(0xe9,0x00,tx_data,1);
#endif


#if 1
	printk("\r\n Clear USER MEM");
	for(Page  = 1; Page  <= 0xF ; Page++)
	{
		for(SubPage = 0; SubPage < 4; SubPage++)
		{


			//for( t = 0; t < 4; t++)
			{
				int PageAddress = 0xF000 + Page * 4* 64 + SubPage*64 ;
				unsigned char MSB = (PageAddress >> 8) & 0xFF;
				unsigned char LSB = PageAddress &0xFF;
				memset(tx_data,0,64);
				eep_page_write(MSB,LSB,tx_data,1);			
			}
		}
	}	
#endif

	for(Page  = 1; Page  <= 0xF ; Page++)
	{
		for(SubPage = 0; SubPage < 4; SubPage++)
		{

			for(SubFrame = 0; SubFrame < 4; SubFrame++)
			{
#if 1
				if(AES_ARIA == 1)// AES 256
				{
					GetCTAES256(Cnt++,CT);
					PRINTLOG("\r\n AES256");
				}
				if(AES_ARIA == 3)// AES 128
				{
					GetCTAES128(Cnt++,CT);
					PRINTLOG("\r\n AES128");
				}
				if(AES_ARIA == 0)// ARIA 256
				{
					GetCTARIA256(Cnt++,CT);
					PRINTLOG("\r\n ARIA256");
				}
				if(AES_ARIA == 2)// ARIA 128
				{
					GetCTARIA128(Cnt++,CT);
					PRINTLOG("\r\n ARIA128");
				}


				PRINTLOG(" DecWrite  Cnt %d", Cnt -1);
#endif				
				CommonDecEncWirteRead(  (SubFrame << 6) | (SubPage <<4 )  | Page , AES_ARIA);//AES_256);
				tx_data[0] = 0xE;
				tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
				j = 15;
				for(i = 0; i < 16; i++)
					tx_data[i] = CT[j--];
				//printk("\r\n CT \r\n");
				//printbyte(CT,16);
				tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);

				delay_ms(9);



				tx_data[0] = 0x1;
				tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
				//delay_ms(9);
				tx_data[0] = 0x1;
				tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
				//delay_ms(9);
				endOP();
			}


		}	
	}
#if 1
#if 0 // CASE 1 KEYLOADë¥??ë² ?í?ë©´ UID PERM?»ì´ì§ê³?AES_CUR??1?´ë??
	//	printk("\r\n -----------------------------SetKEYNormal------------------------------");

#if 1	
	SetKEYNormal();
	LOCK_TEST(32);
#else		
	SetKEYNormal();
	GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
	ReleasePermision();
#endif
#endif
	//SetKEYNormal();
#if 0// CASE 2 PERMISSION???ë² ?»ì´?¤ë©´ ???
	GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
	ReleasePermision();

	success = GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
	ReleasePermision();


	return success;
	if(GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS) )
	{
		printk("\r\n TEST PASS");

	}
	else
	{
		printk("\r\n TEST FAIL");
		success = 0;
	}
	ReleasePermision();	
	printk("\r\n ALL TEST   END");
	return success;

#endif
#endif	
	Cnt = 0;
	for(Page  = 1; Page  <= 0xF ; Page++)
	{
		for(SubPage = 0; SubPage < 4; SubPage++)
		{


			for( t = 0; t < 4; t++)
			{
				int PageAddress = 0xF000 + Page * 4* 64 + SubPage*64 + t*16;
				unsigned char MSB = (PageAddress >> 8) & 0xFF;
				unsigned char LSB = PageAddress &0xFF;
				unsigned char addr[2];
				GetLowSequence(Cnt++,buf_data[t]);
				j = 15;
				if( t == 0 )
					eep_page_read(MSB, LSB,0,buf_eeprom);
				j = 15;
				for( k = 0; k < 16; k++)
					buf_temp[k] = buf_data[t][j--];
				if( memcmp(buf_temp, &buf_eeprom[t*16],16) == 0)
				{
					printk("\r\n Page : %d, SubPage : %d, SubFrame: %d ADDR 0x%04x",Page,SubPage,t,PageAddress);
					printk(" TEST PASS");
				}
				else
				{
					success = 0;
					printk("\r\n TEST FAIL");
					printk("\r\n Page : %d, SubPage : %d, SubFrame: %d ADDR 0x%04x",Page,SubPage,t,PageAddress);
					addr[0]  = 0x12;
					addr[1] = 0x34;
					PrintBuffer(TYPE_RX, &buf_data[0][0], addr);
					addr[0]  = MSB;
					addr[1] = LSB;
					PrintBuffer(TYPE_RX, buf_eeprom, addr);
					if(t == 0)
						ErrorPage[cnt_error++] = Page ;
					//return 0;
				}
			}
		}
	}
	END;
#if 0
	printk("\r\n Try to get UID PERMISSION ");
	printk("\r\n MISS is normal condition");
	printk("\r\n ==========================================");	
	GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
	ReleasePermision();
	printk("\r\n ==========================================");			
#endif	
	printk("\r\n Write KEY AESX0");	
	memset(tx_data,0x11,64);
	eep_page_write(0xe9,0x00,tx_data,1);

	PRINTLOG("\r\n Read Result block");
	for( i = 0; i < cnt_error; i++)
		printk("\r\n ERROR PAGE %d",ErrorPage[i]);
	eep_page_read(0xF0, 00,0,buf_eeprom);
	GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
	ReleasePermision();
	if(success)
		printk("\r\n ALL TEST PASS");
	return success;
#endif
}

void GetUID()
{


}


int ReadEnc(int AES_ARIA)
{

#ifdef COMPARE

	int i;
	int j;
	int k;
	int t;
	unsigned char Page,SubPage,SubFrame;
	unsigned int inst = 0;
	int success = 1;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp ;
	unsigned char buf_data[4][16];
	unsigned char buf_eeprom[64];
	unsigned char buf_temp[16];
	unsigned char addr[2];
	//unsigned char CT[16] = {0x60,0x89,0x9C,0x60,0xFB,0x8A,0x9D,0x2D,0x27,0x70,0xC8,0x24,0x00,0xC6,0x50,0xEA};//PT 0405060708090A0B0C0D0E0F10111213
	unsigned char CT[16];
	int Cnt = 0;
	unsigned char KEY[32] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
	// WRITE KEY
	//KEY 0102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F10
	START;
	j = 31;
	for(i = 0; i < 32; i++)
		tx_data[i] = KEY[j--];

	eep_page_write(0xe9,0x00,tx_data,1);	
	//unsigned char *pCT[16*4*4]; 
	Page = 0;
	SubPage= 0;
	SubFrame = 0;

	//for( i = 0; i < 64; i++)
	//KEY 0102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F10
	for(Page  = 1; Page  <= 0xF ; Page++)
	{
		for(SubPage = 0; SubPage < 4; SubPage++)
		{

			for(SubFrame = 0; SubFrame < 4; SubFrame++)
			{
				GetLowSequence(Cnt,buf_data[SubFrame]);
				if(AES_ARIA == 1)// AES 256
				{
					GetCTAES256(Cnt++,CT);
					PRINTLOG("\r\n AES256");
				}
				if(AES_ARIA == 3)// AES 128
				{
					GetCTAES128(Cnt++,CT);
					PRINTLOG("\r\n AES128");
				}
				if(AES_ARIA == 0)// ARIA 256
				{
					GetCTARIA256(Cnt++,CT);
					PRINTLOG("\r\n ARIA256");
				}
				if(AES_ARIA == 2)// ARIA 128
				{
					GetCTARIA128(Cnt++,CT);
					PRINTLOG("\r\n ARIA128");
				}
				PRINTLOG("\r\n AESReadEnc  Cnt %d", Cnt -1);
				CommonDecEncWirteRead(  (SubFrame << 6) | (SubPage <<4 )  | Page,AES_ARIA);

				tx_data[0] = 0xF;
				tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
				delay_us(30);

				//tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
				tspi_interface(cs, ADDR_NOR_R, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);

				addr[0]  = 0x12;
				addr[1] = 0x34;
				printk("\r\n RG_EEBUF300 \r\n");
				PrintBuffer(TYPE_RX, rx_data, addr);
				tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);
				j = 15;
				for( i = 0; i < 16; i++)
					buf_temp[i] = rx_data[j--];

				if( memcmp(CT,buf_temp,16) != 0 )
				{
					int PageAddress = 0xF000 + Page * 4* 64 + SubPage*64 + SubFrame*16;
					unsigned char MSB = (PageAddress >> 8) & 0xFF;
					unsigned char LSB = PageAddress &0xFF;
					unsigned char DataBuffer[64];
					printk("\r\n FAIL:Compare error page %d subpage %d subFrame %d", Page, SubPage, SubFrame);
					printk("\r\n CT \r\n");
					printbyte(CT,16);
					printk("\r\n rx_data \r\n");					
					printbyte(buf_temp,16);					
					tx_data[0] = 0x1;
					printk("\r\n Sequence");
					printbyte(buf_data[SubFrame],16);

					tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
					tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);					
					endOP();
					eep_page_read(MSB, LSB, 0, DataBuffer);

					return 0;
				}
				else
				{
					Serial.println(" PASS");
				}

				tx_data[0] = 0x1;
				tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
				tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);								


				endOP();
			}
		}	
	}
	SetKEYNormal();
	return 1;
#endif
}

int KeySave(int index,unsigned char *Key,int mode)
{
	unsigned char MSB;
	unsigned char LSB;
	int i;
	int j;
	unsigned int inst = 0;
	int success = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	for(i = 0; i < 64; i++)
	{
		tx_data[i] = 0;
		rx_data[i] = 0;
	}
	MSB = 0xE9;
	switch(index)
	{
	case 0:
		LSB = 0x00;
		break;
	case 1:
		LSB = 0x40;
		break;
	case 2:
		LSB = 0x80;
		break;
	case 3:
		LSB = 0xC0;
		break;
	default:
		PRINTLOG("\r\nWRONG INDEX %s %d",__FILE__,__LINE__);
	}
	printk("\r\nKEY");
	if(mode == 0)
		printbyte(Key,16);
	if(mode == 1)
		printbyte(Key,32);		
	#if 1
	if(mode == 0)// 128
	{
		j = 0;
		for(i = 16; i < 32; i++)
			tx_data[i] =Key[j++];
		
		printk("\r\n tx_data");	
		printbyte(tx_data,32);
					
		KEY_SET(tx_data);

	}
	else //256
	{
		
		for(i = 0; i < 16; i++)
			tx_data[i] = Key[i+16];
		j = 0;
		for(i = 16; i < 32; i++)
			tx_data[i] =Key[j++];
			
		printk("\r\n tx_data");
		printbyte(tx_data,32);
		
		KEY_SET(tx_data);
	}
	#else
	
	if(mode == 0)// 128
	{
		j = 15;
		for(i = 16; i < 32; i++)
			tx_data[i] =Key[j--];
		success = eep_page_write(MSB,LSB,tx_data,1);
	}
	else //256
	{
		j = 31;
		for(i = 0; i < 32; i++)
			tx_data[i] =Key[j--];
		success = eep_page_write(MSB,LSB,tx_data,1);
	}
	#endif


	eep_page_read(0xe9,00,0,rx_data);
	return 1;

}
#if 0
int VerifyARIA256()//0:128 1: 256
{
	int i;
	int j, k;
	int  mode = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	unsigned char ARA_TEST_128_VECTOR_256_KEY[32] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};

	unsigned char ARA_TEST_128_VECTOR_256_PT1[16] = {0x11,0x11,0x11,0x11,0xaa,0xaa,0xaa,0xaa,0x11,0x11,0x11,0x11,0xbb,0xbb,0xbb,0xbb};
	unsigned char ARA_TEST_128_VECTOR_256_CT1[16] = {0x58,0xA8,0x75,0xE6,0x04,0x4A,0xD7,0xFF,0xFA,0x4F,0x58,0x42,0x0F,0x7F,0x44,0x2D};	

	unsigned char ARA_TEST_128_VECTOR_256_PT2[16] = {0x11,0x11,0x11,0x11,0xcc,0xcc,0xcc,0xcc,0x11,0x11,0x11,0x11,0xdd,0xdd,0xdd,0xdd};
	unsigned char ARA_TEST_128_VECTOR_256_CT2[16] = {0x8e,0x19,0x10,0x16,0xf2,0x8e,0x79,0xae,0xfc,0x01,0xe2,0x04,0x77,0x32,0x80,0xd7};	

	unsigned char ARA_TEST_128_VECTOR_256_PT3[16] = {0x22,0x22,0x22,0x22,0xaa,0xaa,0xaa,0xaa,0x22,0x22,0x22,0x22,0xbb,0xbb,0xbb,0xbb};
	unsigned char ARA_TEST_128_VECTOR_256_CT3[16] = {0x01,0x8e,0x5f,0x7a,0x93,0x8e,0xc3,0x07,0x11,0x71,0x99,0x53,0xba,0xe8,0x65,0x42};	

	unsigned char ARA_TEST_128_VECTOR_256_PT4[16] = {0x22,0x22,0x22,0x22,0xcc,0xcc,0xcc,0xcc,0x22,0x22,0x22,0x22,0xdd,0xdd,0xdd,0xdd};
	unsigned char ARA_TEST_128_VECTOR_256_CT4[16] = {0xcd,0x7e,0xbc,0x75,0x24,0x74,0xc1,0xa5,0xf6,0xea,0xaa,0xce,0x2a,0x7e,0x29,0x46};		

	unsigned char ARA_TEST_128_VECTOR_256_PT5[16] = {0x33,0x33,0x33,0x33,0xaa,0xaa,0xaa,0xaa,0x33,0x33,0x33,0x33,0xbb,0xbb,0xbb,0xbb};
	unsigned char ARA_TEST_128_VECTOR_256_CT5[16] = {0x2e,0xe7,0xdf,0xa5,0xaf,0xdb,0x84,0x17,0x7e,0xad,0x95,0xcc,0xd4,0xb4,0xbb,0x6e};		

	unsigned char ARA_TEST_128_VECTOR_256_PT6[16] = {0x33,0x33,0x33,0x33,0xcc,0xcc,0xcc,0xcc,0x33,0x33,0x33,0x33,0xdd,0xdd,0xdd,0xdd};
	unsigned char ARA_TEST_128_VECTOR_256_CT6[16] = {0x1e,0xd1,0x7b,0x95,0x34,0xcf,0xf0,0xa5,0xfc,0x29,0x41,0x42,0x9c,0xfe,0xe2,0xee};		

	unsigned char ARA_TEST_128_VECTOR_256_PT7[16] = {0x44,0x44,0x44,0x44,0xaa,0xaa,0xaa,0xaa,0x44,0x44,0x44,0x44,0xbb,0xbb,0xbb,0xbb};
	unsigned char ARA_TEST_128_VECTOR_256_CT7[16] = {0x49,0xc7,0xad,0xbe,0xb7,0xe9,0xd1,0xb0,0xd2,0xa8,0x53,0x1d,0x94,0x20,0x79,0x59};		


	unsigned char ARA_TEST_128_VECTOR_256_PT8[16] = {0x44,0x44,0x44,0x44,0xaa,0xaa,0xaa,0xaa,0x44,0x44,0x44,0x44,0xbb,0xbb,0xbb,0xbb};
	unsigned char ARA_TEST_128_VECTOR_256_CT8[16] = {0x49,0xc7,0xad,0xbe,0xb7,0xe9,0xd1,0xb0,0xd2,0xa8,0x53,0x1d,0x94,0x20,0x79,0x59};		

	unsigned char ARA_TEST_128_VECTOR_256_PT9[16] = {0x44,0x44,0x44,0x44,0xcc,0xcc,0xcc,0xcc,0x44,0x44,0x44,0x44,0xdd,0xdd,0xdd,0xdd};
	unsigned char ARA_TEST_128_VECTOR_256_CT9[16] = {0x6a,0x27,0xed,0x79,0xf5,0xb1,0xdd,0x13,0xec,0xd6,0x04,0xb0,0x7a,0x48,0x88,0x5a};		

	unsigned char ARA_TEST_128_VECTOR_256_PT10[16] = {0x55,0x55,0x55,0x55,0xaa,0xaa,0xaa,0xaa,0x55,0x55,0x55,0x55,0xbb,0xbb,0xbb,0xbb};
	unsigned char ARA_TEST_128_VECTOR_256_CT10[16] = {0x3a,0xfa,0x06,0x27,0xa0,0xe4,0xe6,0x0a,0x3c,0x70,0x3a,0xf2,0x92,0xf1,0xba,0xa7};		

	unsigned char ARA_TEST_128_VECTOR_256_PT11[16] = {0x55,0x55,0x55,0x55,0xcc,0xcc,0xcc,0xcc,0x55,0x55,0x55,0x55,0xdd,0xdd,0xdd,0xdd};
	unsigned char ARA_TEST_128_VECTOR_256_CT11[16] = {0x7b,0x70,0x2f,0x16,0xc5,0x4a,0xa7,0x4b,0xc7,0x27,0xea,0x95,0xc7,0x46,0x8b,0x00};		


	unsigned char  *P_PT[11];	
	unsigned char  *P_CT[11];	

	unsigned char  *P_PT_Dec[11];	
	unsigned char  *P_CT_Dec[11];	
	unsigned char OUT_CT[16];
	unsigned char OUT_PT[16];	
	int AESMODE =MODE256;
	int success = 1;

	P_PT[0] = ARA_TEST_128_VECTOR_256_PT1;
	P_PT[1] = ARA_TEST_128_VECTOR_256_PT2;
	P_PT[2] = ARA_TEST_128_VECTOR_256_PT3;	
	P_PT[3] = ARA_TEST_128_VECTOR_256_PT4;		
	P_PT[4] = ARA_TEST_128_VECTOR_256_PT5;
	P_PT[5] = ARA_TEST_128_VECTOR_256_PT6;
	P_PT[6] = ARA_TEST_128_VECTOR_256_PT7;	
	P_PT[7] = ARA_TEST_128_VECTOR_256_PT8;		
	P_PT[8] = ARA_TEST_128_VECTOR_256_PT9;
	P_PT[9] = ARA_TEST_128_VECTOR_256_PT10;
	P_PT[10] = ARA_TEST_128_VECTOR_256_PT11;	

	P_CT[0] = ARA_TEST_128_VECTOR_256_CT1;
	P_CT[1] = ARA_TEST_128_VECTOR_256_CT2;
	P_CT[2] = ARA_TEST_128_VECTOR_256_CT3;	
	P_CT[3] = ARA_TEST_128_VECTOR_256_CT4;		
	P_CT[4] = ARA_TEST_128_VECTOR_256_CT5;
	P_CT[5] = ARA_TEST_128_VECTOR_256_CT6;
	P_CT[6] = ARA_TEST_128_VECTOR_256_CT7;	
	P_CT[7] = ARA_TEST_128_VECTOR_256_CT8;		
	P_CT[8] = ARA_TEST_128_VECTOR_256_CT9;
	P_CT[9] = ARA_TEST_128_VECTOR_256_CT10;
	P_CT[10] = ARA_TEST_128_VECTOR_256_CT11;	

	P_PT_Dec[0] = ARA_TEST_128_VECTOR_256_PT1;
	P_PT_Dec[1] = ARA_TEST_128_VECTOR_256_PT2;
	P_PT_Dec[2] = ARA_TEST_128_VECTOR_256_PT3;	
	P_PT_Dec[3] = ARA_TEST_128_VECTOR_256_PT4;		
	P_PT_Dec[4] = ARA_TEST_128_VECTOR_256_PT5;
	P_PT_Dec[5] = ARA_TEST_128_VECTOR_256_PT6;
	P_PT_Dec[6] = ARA_TEST_128_VECTOR_256_PT7;	
	P_PT_Dec[7] = ARA_TEST_128_VECTOR_256_PT8;		
	P_PT_Dec[8] = ARA_TEST_128_VECTOR_256_PT9;
	P_PT_Dec[9] = ARA_TEST_128_VECTOR_256_PT10;
	P_PT_Dec[10] = ARA_TEST_128_VECTOR_256_PT11;	

	P_CT_Dec[0] = ARA_TEST_128_VECTOR_256_CT1;
	P_CT_Dec[1] = ARA_TEST_128_VECTOR_256_CT2;
	P_CT_Dec[2] = ARA_TEST_128_VECTOR_256_CT3;	
	P_CT_Dec[3] = ARA_TEST_128_VECTOR_256_CT4;		
	P_CT_Dec[4] = ARA_TEST_128_VECTOR_256_CT5;
	P_CT_Dec[5] = ARA_TEST_128_VECTOR_256_CT6;
	P_CT_Dec[6] = ARA_TEST_128_VECTOR_256_CT7;	
	P_CT_Dec[7] = ARA_TEST_128_VECTOR_256_CT8;		
	P_CT_Dec[8] = ARA_TEST_128_VECTOR_256_CT9;
	P_CT_Dec[9] = ARA_TEST_128_VECTOR_256_CT10;
	P_CT_Dec[10] = ARA_TEST_128_VECTOR_256_CT11;	

	mode = MODE256;
	if(KeySave(0,ARA_TEST_128_VECTOR_256_KEY,mode) == 0)
		return 2;
	for(k= 0; k< 11; k++)
	{


		tx_data[0] = 0x0;// KEY_0
		tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		{
			tx_data[0] = 0;//ARIA 256
		}
		tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x9;
		tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x2;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		tx_data[0] = 0x3;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		delay_us(30);
		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		tx_data[0] = 0x4;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		////////////////////////////////////////////////////////////////////////////////////////////////////////////
		j = 15;
		for(i = 0; i < 16; i++)
			tx_data[i] = P_PT[k][j--];

		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	


		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
		j = 15;
		for(i = 0; i < 16; i++)
			OUT_CT[i] = rx_data[j--];
		if(memcmp(OUT_CT,P_CT[k],16) != 0 )
		{
			printk("\r\n\r\nError VerifyAES CM_NIST_SP_AES_256_PT1 ENC");
			success = 0;

		}
		else
		{
			printk("\r\n SUCCESSS TO VERIFY ENC 256 %d",k);
		}

		j = 15;
		for(i = 0; i < 16; i++)
			tx_data[i] = P_CT_Dec[k][j--];

		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	


		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		j = 15;
		for(i = 0; i < 16; i++)
			OUT_PT[i] = rx_data[j--];


		if(memcmp(OUT_PT,P_PT_Dec[k],16) != 0 )
		{
			success = 0;
			printk("\r\n\r\nError VerifyAES CM_NIST_SP_AES_256_PT1 DEC");

		}
		else
		{
			printk("\r\n SUCCESSS TO VERIFY DEC 256 %d",k);

		}	

		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

		endOP();
	}

	if(success)
		printk("\r\n TEST SUCCESS");
	else
		printk("\r\n TEST FAIL");
	return 0;


	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		tx_data[i] = OUT_CT[j--];
	//

	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		OUT_PT[i] = rx_data[j--];
	/*
	if(memcmp(OUT_PT,CM_AES_FIPS_PUB_197_PT,16) != 0)
	{
	PRINTLOG("\r\n AES Decoding FAIL");
	}
	else
	{
	PRINTLOG("\r\n AES Decoding PASS");
	}
	*/


	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	return success;
}

int VerifyARIA()
{
	int i;
	int j, k;
	int  mode = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	unsigned char X1213_2_128_KEY[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	unsigned char X1213_2_128_PT1[16] = {0x17,0xc6,0xa3,0xee,0xc4,0x7f,0x7d,0x19,0xa1,0xe8,0x2b,0xb8,0x50,0x4b,0x49,0x20};
	unsigned char X1213_2_128_CT1[16] = {0xE8,0x39,0x8F,0x89,0x73,0x23,0xE7,0xBC,0xC2,0x18,0xC3,0x90,0x36,0x5D,0x69,0xE8};	
	unsigned char X1213_2_128_PT2[16] = {0x31,0x44,0x20,0x2f,0xce,0x12,0x6c,0xe3,0xb5,0xf3,0x83,0x51,0x03,0x87,0x35,0xb5};
	unsigned char X1213_2_128_CT2[16] = {0x63,0xAE,0x8E,0x4C,0x14,0xA2,0xEC,0xE9,0xD9,0x09,0x31,0x9B,0x6F,0x7E,0x3B,0x9E};	
	unsigned char X1213_2_128_PT3[16] = {0x3f,0x78,0x8a,0x07,0xf5,0x45,0x1d,0x5e,0xb4,0xbc,0x7a,0x04,0xa6,0xe5,0x74,0xcb};
	unsigned char X1213_2_128_CT3[16] = {0x25,0x36,0x6D,0x6F,0x3E,0xD0,0x8B,0xC5,0xDA,0x43,0xBE,0x2C,0x08,0x48,0x73,0x6B};	
	unsigned char X1213_2_128_PT4[16] = {0xf4,0xc0,0xe6,0x20,0x39,0x95,0xe2,0x17,0x05,0x0f,0x09,0x76,0xe2,0x2a,0xa2,0xc7};
	unsigned char X1213_2_128_CT4[16] = {0x1D,0x1D,0x7B,0x48,0xB7,0xEC,0xB7,0x0C,0xFA,0x58,0x22,0x19,0xA7,0x98,0x54,0x7C};		



	unsigned char X1213_2_128_PT1_Dec[16] = {0x17,0xc6,0xa3,0xee,0xc4,0x7f,0x7d,0x19,0xa1,0xe8,0x2b,0xb8,0x50,0x4b,0x49,0x20};
	unsigned char X1213_2_128_CT1_Dec[16] = {0xE8,0x39,0x8F,0x89,0x73,0x23,0xE7,0xBC,0xC2,0x18,0xC3,0x90,0x36,0x5D,0x69,0xE8};	
	unsigned char X1213_2_128_PT2_Dec[16] = {0x31,0x44,0x20,0x2f,0xce,0x12,0x6c,0xe3,0xb5,0xf3,0x83,0x51,0x03,0x87,0x35,0xb5};
	unsigned char X1213_2_128_CT2_Dec[16] = {0x63,0xAE,0x8E,0x4C,0x14,0xA2,0xEC,0xE9,0xD9,0x09,0x31,0x9B,0x6F,0x7E,0x3B,0x9E};	
	unsigned char X1213_2_128_PT3_Dec[16] = {0x3f,0x78,0x8a,0x07,0xf5,0x45,0x1d,0x5e,0xb4,0xbc,0x7a,0x04,0xa6,0xe5,0x74,0xcb};
	unsigned char X1213_2_128_CT3_Dec[16] = {0x25,0x36,0x6D,0x6F,0x3E,0xD0,0x8B,0xC5,0xDA,0x43,0xBE,0x2C,0x08,0x48,0x73,0x6B};	
	unsigned char X1213_2_128_PT4_Dec[16] = {0xf4,0xc0,0xe6,0x20,0x39,0x95,0xe2,0x17,0x05,0x0f,0x09,0x76,0xe2,0x2a,0xa2,0xc7};
	unsigned char X1213_2_128_CT4_Dec[16] = {0x1D,0x1D,0x7B,0x48,0xB7,0xEC,0xB7,0x0C,0xFA,0x58,0x22,0x19,0xA7,0x98,0x54,0x7C};		


	/*unsigned char X1213_2_128_KEY_Dec[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char X1213_2_128_PT1_Dec[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
	unsigned char X1213_2_128_CT1_Dec[16] = {0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97};	
	unsigned char X1213_2_128_PT2_Dec[16] = {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
	unsigned char X1213_2_128_CT2_Dec[16] = {0xf5,0xd3,0xd5,0x85,0x03,0xb9,0x69,0x9d,0xe7,0x85,0x89,0x5a,0x96,0xfd,0xba,0xaf};	
	unsigned char X1213_2_128_PT3_Dec[16] = {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
	unsigned char X1213_2_128_CT3_Dec[16] = {0x43,0xb1,0xcd,0x7f,0x59,0x8e,0xce,0x23,0x88,0x1b,0x00,0xe3,0xed,0x03,0x06,0x88};	
	unsigned char X1213_2_128_PT4_Dec[16] = {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char X1213_2_128_CT4_Dec[16] = {0x7b,0x0c,0x78,0x5e,0x27,0xe8,0xad,0x3f,0x82,0x23,0x20,0x71,0x04,0x72,0x5d,0xd4};		*/

	unsigned char  *P_PT[4];	
	unsigned char  *P_CT[4];	

	unsigned char  *P_PT_Dec[4];	
	unsigned char  *P_CT_Dec[4];	
	unsigned char OUT_CT[16];
	unsigned char OUT_PT[16];	
	int AESMODE =MODE128;
	int success = 1;
	printk("\r\n ARIA 128 Verify BEGIN \r\n");
	P_PT[0] = X1213_2_128_PT1;
	P_PT[1] = X1213_2_128_PT2;
	P_PT[2] = X1213_2_128_PT3;	
	P_PT[3] = X1213_2_128_PT4;		

	P_CT[0] = X1213_2_128_CT1;
	P_CT[1] = X1213_2_128_CT2;
	P_CT[2] = X1213_2_128_CT3;	
	P_CT[3] = X1213_2_128_CT4;		

	P_PT_Dec[0] = X1213_2_128_PT1_Dec;
	P_PT_Dec[1] = X1213_2_128_PT2_Dec;
	P_PT_Dec[2] = X1213_2_128_PT3_Dec;	
	P_PT_Dec[3] = X1213_2_128_PT4_Dec;		

	P_CT_Dec[0] = X1213_2_128_CT1_Dec;
	P_CT_Dec[1] = X1213_2_128_CT2_Dec;
	P_CT_Dec[2] = X1213_2_128_CT3_Dec;	
	P_CT_Dec[3] = X1213_2_128_CT4_Dec;	
	mode = MODE128;
	if(KeySave(0,X1213_2_128_KEY,mode) == 0)
		return 2;
	for(k= 0; k< 4; k++)
	{


		tx_data[0] = 0x0;// KEY_0
		tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		{
			tx_data[0] =  0x2;
		}
		tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x9;
		tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x2;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		tx_data[0] = 0x3;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		delay_us(30);
		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		tx_data[0] = 0x4;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		////////////////////////////////////////////////////////////////////////////////////////////////////////////
		j = 15;
		for(i = 0; i < 16; i++)
			tx_data[i] = P_PT[k][j--];

		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	


		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
		j = 15;
		for(i = 0; i < 16; i++)
			OUT_CT[i] = rx_data[j--];
		if(memcmp(OUT_CT,P_CT[k],16) != 0 )
		{
			printk("\r\n\r\nError VerifyAES X1213_2_128_PT1 ENC");
			success = 0;

		}
		else
		{
			printk("\r\n SUCCESSS TO VERIFY ENC %d",k);
		}

		j = 15;
		for(i = 0; i < 16; i++)
			tx_data[i] = P_CT_Dec[k][j--];

		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	


		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		j = 15;
		for(i = 0; i < 16; i++)
			OUT_PT[i] = rx_data[j--];


		if(memcmp(OUT_PT,P_PT_Dec[k],16) != 0 )
		{
			success = 0;
			printk("\r\n\r\nError VerifyAES X1213_2_128_PT1 DEC");

		}
		else
		{
			printk("\r\n SUCCESSS TO VERIFY DEC %d",k);

		}	

		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

		endOP();
	}

	if(success)
		printk("\r\n TEST SUCCESS");
	else
		printk("\r\n TEST FAIL");

	printk("\r\n ARIA 128 Verify END \r\n");

	return 0;


	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		tx_data[i] = OUT_CT[j--];
	//

	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		OUT_PT[i] = rx_data[j--];
	/*
	if(memcmp(OUT_PT,CM_AES_FIPS_PUB_197_PT,16) != 0)
	{
	PRINTLOG("\r\n AES Decoding FAIL");
	}
	else
	{
	PRINTLOG("\r\n AES Decoding PASS");
	}
	*/


	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	return success;
}

int TEST_AES_256()//0:128 1: 256
{
	int i;
	int j, k;
	int  mode = 0;
	int l = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	//unsigned char AES_KH_TEST_128_VECTOR_KEY[16] = {	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	//unsigned char AES_KH_TEST_128_VECTOR_PT0[16] = {	0x17,0xc6,0xa3,0xee,0xc4,0x7f,0x7d,0x19,0xa1,0xe8,0x2b,0xb8,0x50,0x4b,0x49,0x20};
	//unsigned char AES_KH_TEST_128_VECTOR_CT0[16] =	{ 0xe8,0x39,0x8f,0x89,0x73,0x23,0xe7,0xbc,0xc2,0x18,0xc3,0x90,0x36,0x5d,0x69,0xe8};

	//unsigned char AES_KH_TEST_128_VECTOR_PT1[16] = {	0x31,0x44,0x20,0x2f,0xce,0x12,0x6c,0xe3,0xb5,0xf3,0x83,0x51,0x03,0x87,0x35,0xb5};
	//unsigned char AES_KH_TEST_128_VECTOR_CT1[16] = {	0x63,0xae,0x8e,0x4c,0x14,0xa2,0xec,0xe9,0xd9,0x09,0x31,0x9b,0x6f,0x7e,0x3b,0x9e};

	//unsigned char AES_KH_TEST_128_VECTOR_PT2[16] = {	0x3f,0x78,0x8a,0x07,0xf5,0x45,0x1d,0x5e,0xb4,0xbc,0x7a,0x04,0xa6,0xe5,0x74,0xcb};
	//unsigned char AES_KH_TEST_128_VECTOR_CT2[16] = {	0x25,0x36,0x6d,0x6f,0x3e,0xd0,0x8b,0xc5,0xda,0x43,0xbe,0x2c,0x08,0x48,0x73,0x6b};

	//unsigned char AES_KH_TEST_128_VECTOR_PT3[16] = {	0xf4,0xc0,0xe6,0x20,0x39,0x95,0xe2,0x17,0x05,0x0f,0x09,0x76,0xe2,0x2a,0xa2,0xc7};
	//unsigned char AES_KH_TEST_128_VECTOR_CT3[16] = {	0x1d,0x1d,0x7b,0x48,0xb7,0xec,0xb7,0x0c,0xfa,0x58,0x22,0x19,0xa7,0x98,0x54,0x7c};

	unsigned char AES_KH_TEST_256_VECTOR_KEY[32] = {	0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
	unsigned char AES_KH_TEST_256_VECTOR_PT0[16] = {	0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
	unsigned char AES_KH_TEST_256_VECTOR_CT0[16] =	{ 0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8};

	unsigned char AES_KH_TEST_256_VECTOR_PT1[16] = {	0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
	unsigned char AES_KH_TEST_256_VECTOR_CT1[16] = {	0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70};

	unsigned char AES_KH_TEST_256_VECTOR_PT2[16] = {	0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
	unsigned char AES_KH_TEST_256_VECTOR_CT2[16] = {	0xb6,0xed,0x21,0xb9,0x9c,0xa6,0xf4,0xf9,0xf1,0x53,0xe7,0xb1,0xbe,0xaf,0xed,0x1d};

	unsigned char AES_KH_TEST_256_VECTOR_PT3[16] = {	0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AES_KH_TEST_256_VECTOR_CT3[16] = {	0x23,0x30,0x4b,0x7a,0x39,0xf9,0xf3,0xff,0x06,0x7d,0x8d,0x8f,0x9e,0x24,0xec,0xc7};



	unsigned char  *P_PT[4];	
	unsigned char  *P_CT[4];	

	unsigned char  *P_PT_Dec[4];	
	unsigned char  *P_CT_Dec[4];	
	unsigned char OUT_CT[16];
	unsigned char OUT_PT[16];	
	int AESMODE =MODE256;
	int success = 1;

	unsigned int iStart,iEnd;
	unsigned int totalEncode = 0;
	unsigned int totalDecode = 0;
	AT91S_RTTC *pRSTC = (AT91S_RTTC *) 0xFFFFFD20;  
	P_PT[0] = AES_KH_TEST_256_VECTOR_PT0;
	P_PT[1] = AES_KH_TEST_256_VECTOR_PT1;
	P_PT[2] = AES_KH_TEST_256_VECTOR_PT2;	
	P_PT[3] = AES_KH_TEST_256_VECTOR_PT3;		

	P_CT[0] = AES_KH_TEST_256_VECTOR_CT0;
	P_CT[1] = AES_KH_TEST_256_VECTOR_CT1;
	P_CT[2] = AES_KH_TEST_256_VECTOR_CT2;	
	P_CT[3] = AES_KH_TEST_256_VECTOR_CT3;		

	P_PT_Dec[0] = AES_KH_TEST_256_VECTOR_PT0;
	P_PT_Dec[1] = AES_KH_TEST_256_VECTOR_PT1;
	P_PT_Dec[2] = AES_KH_TEST_256_VECTOR_PT2;	
	P_PT_Dec[3] = AES_KH_TEST_256_VECTOR_PT3;		

	P_CT_Dec[0] = AES_KH_TEST_256_VECTOR_CT0;
	P_CT_Dec[1] = AES_KH_TEST_256_VECTOR_CT1;
	P_CT_Dec[2] = AES_KH_TEST_256_VECTOR_CT2;	
	P_CT_Dec[3] = AES_KH_TEST_256_VECTOR_CT3;	
	mode = MODE256;
	if(KeySave(0,AES_KH_TEST_256_VECTOR_KEY,mode) == 0)
		return 2;
	//for(l = 0; l <250; l++)
	{
		//for(k= 0; k< 4; k++)
		{

			tx_data[0] = 0x0;// KEY_0
			tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			{
				tx_data[0] = 0x1;
			}
			tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			tx_data[0] = 0x9;
			tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			tx_data[0] = 0x2;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			tx_data[0] = 0x3;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			delay_us(30);
			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			tx_data[0] = 0x4;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			////////////////////////////////////////////////////////////////////////////////////////////////////////////
			j = 15;
			for(i = 0; i < 16; i++)
				tx_data[i] = P_PT[k][j--];


			AT91F_RTTClearAlarmINT(pRSTC);
			AT91F_RTTClearRttIncINT(pRSTC);
			AT91F_RTTC_CfgPMC();
			AT91F_RTTSetPrescaler(pRSTC,1);
			AT91F_RTTRestart(pRSTC);	
			Delay_ms(1);
			iStart = pRSTC->RTTC_RTVR;

			tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
			Delay_us(10);	


			tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		

			iEnd = pRSTC->RTTC_RTVR;
			totalEncode += iEnd - iStart;
			j = 15;
			for(i = 0; i < 16; i++)
				OUT_CT[i] = rx_data[j--];
			if(memcmp(OUT_CT,P_CT[k],16) != 0 )
			{
				printk("\r\n\r\nError VerifyAES AES_KH_TEST_256_VECTOR_PT0 ENC");
				printk("\r\n OUT_CT \r\n");
				printbyte(OUT_CT,16);

				printk("\r\n P_CT[%d] \r\n",k);
				printbyte(P_CT[k],16);
				success = 0;

			}
			else
			{
				//printk("\r\n SUCCESSS TO VERIFY AES_KH_TEST_256_VECTOR_PT0 ENC %d",k);
			}

			j = 15;
			for(i = 0; i < 16; i++)
				tx_data[i] = P_CT_Dec[k][j--];


			AT91F_RTTClearAlarmINT(pRSTC);
			AT91F_RTTClearRttIncINT(pRSTC);
			AT91F_RTTC_CfgPMC();
			AT91F_RTTSetPrescaler(pRSTC,1);
			AT91F_RTTRestart(pRSTC);	
			Delay_ms(1);
			iStart = pRSTC->RTTC_RTVR;
			tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
			Delay_us(10);	


			tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
			iEnd = pRSTC->RTTC_RTVR;
			totalDecode += iEnd - iStart;
			j = 15;
			for(i = 0; i < 16; i++)
				OUT_PT[i] = rx_data[j--];


			if(memcmp(OUT_PT,P_PT_Dec[k],16) != 0 )
			{
				success = 0;
				printk("\r\n\r\nError VerifyAES AES_KH_TEST_256_VECTOR_PT0 DEC");

			}
			else
			{
				//printk("\r\n SUCCESSS TO VERIFY AES_KH_TEST_256_VECTOR_PT0 DEC %d",k);

			}	

			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

			endOP();
		}
	}

	//PrintTime(totalEncode/1000,AES256ENCODE );
	//PrintTime(totalDecode/1000,AES256DECODE );
	if(success)
		printk("\r\n TEST SUCCESS");
	else
		printk("\r\n TEST FAIL");
	return 0;


	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		tx_data[i] = OUT_CT[j--];
	//

	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		OUT_PT[i] = rx_data[j--];
	/*
	if(memcmp(OUT_PT,CM_AES_FIPS_PUB_197_PT,16) != 0)
	{
	PRINTLOG("\r\n AES Decoding FAIL");
	}
	else
	{
	PRINTLOG("\r\n AES Decoding PASS");
	}
	*/


	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	return success;
}


int TEST_AES_128()//0:128 1: 256
{
	int i;
	int j, k;
	int  mode = 0;
	int l = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	//unsigned char AES_KH_TEST_128_VECTOR_KEY[16] = {	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	//unsigned char AES_KH_TEST_128_VECTOR_PT0[16] = {	0x17,0xc6,0xa3,0xee,0xc4,0x7f,0x7d,0x19,0xa1,0xe8,0x2b,0xb8,0x50,0x4b,0x49,0x20};
	//unsigned char AES_KH_TEST_128_VECTOR_CT0[16] =	{ 0xe8,0x39,0x8f,0x89,0x73,0x23,0xe7,0xbc,0xc2,0x18,0xc3,0x90,0x36,0x5d,0x69,0xe8};

	//unsigned char AES_KH_TEST_128_VECTOR_PT1[16] = {	0x31,0x44,0x20,0x2f,0xce,0x12,0x6c,0xe3,0xb5,0xf3,0x83,0x51,0x03,0x87,0x35,0xb5};
	//unsigned char AES_KH_TEST_128_VECTOR_CT1[16] = {	0x63,0xae,0x8e,0x4c,0x14,0xa2,0xec,0xe9,0xd9,0x09,0x31,0x9b,0x6f,0x7e,0x3b,0x9e};

	//unsigned char AES_KH_TEST_128_VECTOR_PT2[16] = {	0x3f,0x78,0x8a,0x07,0xf5,0x45,0x1d,0x5e,0xb4,0xbc,0x7a,0x04,0xa6,0xe5,0x74,0xcb};
	//unsigned char AES_KH_TEST_128_VECTOR_CT2[16] = {	0x25,0x36,0x6d,0x6f,0x3e,0xd0,0x8b,0xc5,0xda,0x43,0xbe,0x2c,0x08,0x48,0x73,0x6b};

	//unsigned char AES_KH_TEST_128_VECTOR_PT3[16] = {	0xf4,0xc0,0xe6,0x20,0x39,0x95,0xe2,0x17,0x05,0x0f,0x09,0x76,0xe2,0x2a,0xa2,0xc7};
	//unsigned char AES_KH_TEST_128_VECTOR_CT3[16] = {	0x1d,0x1d,0x7b,0x48,0xb7,0xec,0xb7,0x0c,0xfa,0x58,0x22,0x19,0xa7,0x98,0x54,0x7c};

	unsigned char AES_KH_TEST_128_VECTOR_KEY[16] = {	0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char AES_KH_TEST_128_VECTOR_PT0[16] = {	0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
	unsigned char AES_KH_TEST_128_VECTOR_CT0[16] =	{ 0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97};

	unsigned char AES_KH_TEST_128_VECTOR_PT1[16] = {	0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
	unsigned char AES_KH_TEST_128_VECTOR_CT1[16] = {	0xf5,0xd3,0xd5,0x85,0x03,0xb9,0x69,0x9d,0xe7,0x85,0x89,0x5a,0x96,0xfd,0xba,0xaf};

	unsigned char AES_KH_TEST_128_VECTOR_PT2[16] = {	0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
	unsigned char AES_KH_TEST_128_VECTOR_CT2[16] = {	0x43,0xb1,0xcd,0x7f,0x59,0x8e,0xce,0x23,0x88,0x1b,0x00,0xe3,0xed,0x03,0x06,0x88};

	unsigned char AES_KH_TEST_128_VECTOR_PT3[16] = {	0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AES_KH_TEST_128_VECTOR_CT3[16] = {	0x7b,0x0c,0x78,0x5e,0x27,0xe8,0xad,0x3f,0x82,0x23,0x20,0x71,0x04,0x72,0x5d,0xd4};



	unsigned char  *P_PT[4];	
	unsigned char  *P_CT[4];	

	unsigned char  *P_PT_Dec[4];	
	unsigned char  *P_CT_Dec[4];	
	unsigned char OUT_CT[16];
	unsigned char OUT_PT[16];	
	int AESMODE =MODE128;
	int success = 1;

	unsigned int iStart,iEnd;
	unsigned int totalEncode = 0;
	unsigned int totalDecode = 0;
	AT91S_RTTC *pRSTC = (AT91S_RTTC *) 0xFFFFFD20; 

	P_PT[0] = AES_KH_TEST_128_VECTOR_PT0;
	P_PT[1] = AES_KH_TEST_128_VECTOR_PT1;
	P_PT[2] = AES_KH_TEST_128_VECTOR_PT2;	
	P_PT[3] = AES_KH_TEST_128_VECTOR_PT3;		

	P_CT[0] = AES_KH_TEST_128_VECTOR_CT0;
	P_CT[1] = AES_KH_TEST_128_VECTOR_CT1;
	P_CT[2] = AES_KH_TEST_128_VECTOR_CT2;	
	P_CT[3] = AES_KH_TEST_128_VECTOR_CT3;		

	P_PT_Dec[0] = AES_KH_TEST_128_VECTOR_PT0;
	P_PT_Dec[1] = AES_KH_TEST_128_VECTOR_PT1;
	P_PT_Dec[2] = AES_KH_TEST_128_VECTOR_PT2;	
	P_PT_Dec[3] = AES_KH_TEST_128_VECTOR_PT3;		

	P_CT_Dec[0] = AES_KH_TEST_128_VECTOR_CT0;
	P_CT_Dec[1] = AES_KH_TEST_128_VECTOR_CT1;
	P_CT_Dec[2] = AES_KH_TEST_128_VECTOR_CT2;	
	P_CT_Dec[3] = AES_KH_TEST_128_VECTOR_CT3;	
	mode = MODE128;
	if(KeySave(0,AES_KH_TEST_128_VECTOR_KEY,mode) == 0)
		return 2;
	//for(l = 0; l <250; l++)
	{
		//for(k= 0; k< 4; k++)
		{

			tx_data[0] = 0x0;// KEY_0
			tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			{
				tx_data[0] = 0x3;
			}
			tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			tx_data[0] = 0x9;
			tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			tx_data[0] = 0x2;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			tx_data[0] = 0x3;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			delay_us(30);
			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			tx_data[0] = 0x4;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			////////////////////////////////////////////////////////////////////////////////////////////////////////////
			j = 15;
			for(i = 0; i < 16; i++)
				tx_data[i] = P_PT[k][j--];

			AT91F_RTTClearAlarmINT(pRSTC);
			AT91F_RTTClearRttIncINT(pRSTC);
			AT91F_RTTC_CfgPMC();
			AT91F_RTTSetPrescaler(pRSTC,1);
			AT91F_RTTRestart(pRSTC);	
			Delay_ms(1);
			iStart = pRSTC->RTTC_RTVR;
			tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
			Delay_us(10);	


			tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
			iEnd = pRSTC->RTTC_RTVR;
			totalEncode += iEnd - iStart;
			j = 15;
			for(i = 0; i < 16; i++)
				OUT_CT[i] = rx_data[j--];
			if(memcmp(OUT_CT,P_CT[k],16) != 0 )
			{
				printk("\r\n\r\nError VerifyAES AES_KH_TEST_128_VECTOR_PT0 ENC");
				printk("\r\n OUT_CT \r\n");
				printbyte(OUT_CT,16);

				printk("\r\n P_CT[%d] \r\n",k);
				printbyte(P_CT[k],16);
				success = 0;

			}
			else
			{
				//printk("\r\n SUCCESSS TO VERIFY AES_KH_TEST_128_VECTOR_PT0 ENC %d",k);
			}

			j = 15;
			for(i = 0; i < 16; i++)
				tx_data[i] = P_CT_Dec[k][j--];



			AT91F_RTTClearAlarmINT(pRSTC);
			AT91F_RTTClearRttIncINT(pRSTC);
			AT91F_RTTC_CfgPMC();
			AT91F_RTTSetPrescaler(pRSTC,1);
			AT91F_RTTRestart(pRSTC);	
			Delay_ms(1);
			iStart = pRSTC->RTTC_RTVR;

			tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
			Delay_us(10);	


			tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	

			iEnd = pRSTC->RTTC_RTVR;
			totalDecode += iEnd - iStart;
			j = 15;
			for(i = 0; i < 16; i++)
				OUT_PT[i] = rx_data[j--];


			if(memcmp(OUT_PT,P_PT_Dec[k],16) != 0 )
			{
				success = 0;
				printk("\r\n\r\nError VerifyAES AES_KH_TEST_128_VECTOR_PT0 DEC");

			}
			else
			{
				//printk("\r\n SUCCESSS TO VERIFY AES_KH_TEST_128_VECTOR_PT0 DEC %d",k);

			}	

			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

			endOP();
		}
	}
	//PrintTime(totalEncode/1000,AES128ENCODE );
	//PrintTime(totalDecode/1000,AES128DECODE );
	if(success)
		printk("\r\n TEST SUCCESS");
	else
		printk("\r\n TEST FAIL");
	return 0;


	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		tx_data[i] = OUT_CT[j--];
	//

	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		OUT_PT[i] = rx_data[j--];
	/*
	if(memcmp(OUT_PT,CM_AES_FIPS_PUB_197_PT,16) != 0)
	{
	PRINTLOG("\r\n AES Decoding FAIL");
	}
	else
	{
	PRINTLOG("\r\n AES Decoding PASS");
	}
	*/


	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	return success;
}

int TEST_ARIA_128()//0:128 1: 256
{
	int i;
	int j, k;
	int  mode = 0;
	int l = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	unsigned char ARIA_KH_TEST_128_VECTOR_KEY[16] = {	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	unsigned char ARIA_KH_TEST_128_VECTOR_PT0[16] = {	0x17,0xc6,0xa3,0xee,0xc4,0x7f,0x7d,0x19,0xa1,0xe8,0x2b,0xb8,0x50,0x4b,0x49,0x20};
	unsigned char ARIA_KH_TEST_128_VECTOR_CT0[16] =	{ 0xe8,0x39,0x8f,0x89,0x73,0x23,0xe7,0xbc,0xc2,0x18,0xc3,0x90,0x36,0x5d,0x69,0xe8};

	unsigned char ARIA_KH_TEST_128_VECTOR_PT1[16] = {	0x31,0x44,0x20,0x2f,0xce,0x12,0x6c,0xe3,0xb5,0xf3,0x83,0x51,0x03,0x87,0x35,0xb5};
	unsigned char ARIA_KH_TEST_128_VECTOR_CT1[16] = {	0x63,0xae,0x8e,0x4c,0x14,0xa2,0xec,0xe9,0xd9,0x09,0x31,0x9b,0x6f,0x7e,0x3b,0x9e};

	unsigned char ARIA_KH_TEST_128_VECTOR_PT2[16] = {	0x3f,0x78,0x8a,0x07,0xf5,0x45,0x1d,0x5e,0xb4,0xbc,0x7a,0x04,0xa6,0xe5,0x74,0xcb};
	unsigned char ARIA_KH_TEST_128_VECTOR_CT2[16] = {	0x25,0x36,0x6d,0x6f,0x3e,0xd0,0x8b,0xc5,0xda,0x43,0xbe,0x2c,0x08,0x48,0x73,0x6b};

	unsigned char ARIA_KH_TEST_128_VECTOR_PT3[16] = {	0xf4,0xc0,0xe6,0x20,0x39,0x95,0xe2,0x17,0x05,0x0f,0x09,0x76,0xe2,0x2a,0xa2,0xc7};
	unsigned char ARIA_KH_TEST_128_VECTOR_CT3[16] = {	0x1d,0x1d,0x7b,0x48,0xb7,0xec,0xb7,0x0c,0xfa,0x58,0x22,0x19,0xa7,0x98,0x54,0x7c};




	unsigned char  *P_PT[4];	
	unsigned char  *P_CT[4];	

	unsigned char  *P_PT_Dec[4];	
	unsigned char  *P_CT_Dec[4];	
	unsigned char OUT_CT[16];
	unsigned char OUT_PT[16];	
	int ARIAMODE =MODE128;
	int success = 1;
	unsigned int iStart,iEnd;
	unsigned int totalEncode = 0;
	unsigned int totalDecode = 0;
	AT91S_RTTC *pRSTC = (AT91S_RTTC *) 0xFFFFFD20;  


	P_PT[0] = ARIA_KH_TEST_128_VECTOR_PT0;
	P_PT[1] = ARIA_KH_TEST_128_VECTOR_PT1;
	P_PT[2] = ARIA_KH_TEST_128_VECTOR_PT2;	
	P_PT[3] = ARIA_KH_TEST_128_VECTOR_PT3;		

	P_CT[0] = ARIA_KH_TEST_128_VECTOR_CT0;
	P_CT[1] = ARIA_KH_TEST_128_VECTOR_CT1;
	P_CT[2] = ARIA_KH_TEST_128_VECTOR_CT2;	
	P_CT[3] = ARIA_KH_TEST_128_VECTOR_CT3;		

	P_PT_Dec[0] = ARIA_KH_TEST_128_VECTOR_PT0;
	P_PT_Dec[1] = ARIA_KH_TEST_128_VECTOR_PT1;
	P_PT_Dec[2] = ARIA_KH_TEST_128_VECTOR_PT2;	
	P_PT_Dec[3] = ARIA_KH_TEST_128_VECTOR_PT3;		

	P_CT_Dec[0] = ARIA_KH_TEST_128_VECTOR_CT0;
	P_CT_Dec[1] = ARIA_KH_TEST_128_VECTOR_CT1;
	P_CT_Dec[2] = ARIA_KH_TEST_128_VECTOR_CT2;	
	P_CT_Dec[3] = ARIA_KH_TEST_128_VECTOR_CT3;	
	mode = MODE128;
	if(KeySave(0,ARIA_KH_TEST_128_VECTOR_KEY,mode) == 0)
		return 2;
	//for(l = 0; l <250; l++)
	{
		//for(k= 0; k< 4; k++)
		{

			tx_data[0] = 0x0;// KEY_0
			tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			{
				tx_data[0] = 0x02;
			}
			tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			tx_data[0] = 0x9;
			tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			tx_data[0] = 0x2;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			tx_data[0] = 0x3;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			delay_us(30);
			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			tx_data[0] = 0x4;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			////////////////////////////////////////////////////////////////////////////////////////////////////////////
			j = 15;
			for(i = 0; i < 16; i++)
				tx_data[i] = P_PT[k][j--];
			AT91F_RTTClearAlarmINT(pRSTC);
			AT91F_RTTClearRttIncINT(pRSTC);
			AT91F_RTTC_CfgPMC();
			AT91F_RTTSetPrescaler(pRSTC,1);
			AT91F_RTTRestart(pRSTC);	
			Delay_ms(1);
			iStart = pRSTC->RTTC_RTVR;
			tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
			Delay_us(10);	


			tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
			iEnd = pRSTC->RTTC_RTVR;
			totalEncode += iEnd - iStart;
			j = 15;
			for(i = 0; i < 16; i++)
				OUT_CT[i] = rx_data[j--];
			if(memcmp(OUT_CT,P_CT[k],16) != 0 )
			{
				printk("\r\n\r\nError VerifyAES ARIA_KH_TEST_128_VECTOR_PT0 ENC");
				printk("\r\n OUT_CT \r\n");
				printbyte(OUT_CT,16);

				printk("\r\n P_CT[%d] \r\n",k);
				printbyte(P_CT[k],16);
				success = 0;

			}
			else
			{
				//printk("\r\n SUCCESSS TO VERIFY ARIA_KH_TEST_128_VECTOR_PT0 ENC %d",k);
			}

			j = 15;
			for(i = 0; i < 16; i++)
				tx_data[i] = P_CT_Dec[k][j--];

			AT91F_RTTClearAlarmINT(pRSTC);
			AT91F_RTTClearRttIncINT(pRSTC);
			AT91F_RTTC_CfgPMC();
			AT91F_RTTSetPrescaler(pRSTC,1);
			AT91F_RTTRestart(pRSTC);	
			Delay_ms(1);
			iStart = pRSTC->RTTC_RTVR;

			tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
			Delay_us(10);	


			tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
			j = 15;
			iEnd = pRSTC->RTTC_RTVR;
			totalDecode += iEnd - iStart;
			for(i = 0; i < 16; i++)
				OUT_PT[i] = rx_data[j--];




			if(memcmp(OUT_PT,P_PT_Dec[k],16) != 0 )
			{
				success = 0;
				printk("\r\n\r\nError VerifyARIA ARIA_KH_TEST_128_VECTOR_PT0 DEC");

			}
			else
			{
				//	printk("\r\n SUCCESSS TO VERIFY ARIA_KH_TEST_128_VECTOR_PT0 DEC %d",k);

			}	

			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

			endOP();
		}
	}
	//PrintTime(totalEncode/1000,ARIA128ENCODE );
	//PrintTime(totalDecode/1000,ARIA128DECODE );
	if(success)
		printk("\r\n TEST SUCCESS");
	else
		printk("\r\n TEST FAIL");
	return 0;


	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		tx_data[i] = OUT_CT[j--];
	//

	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		OUT_PT[i] = rx_data[j--];
	/*
	if(memcmp(OUT_PT,CM_AES_FIPS_PUB_197_PT,16) != 0)
	{
	PRINTLOG("\r\n AES Decoding FAIL");
	}
	else
	{
	PRINTLOG("\r\n AES Decoding PASS");
	}
	*/


	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	return success;
}


int TEST_ARIA_256()//0:128 1: 256
{
	int i;
	int j, k;
	int  mode = 0;
	int l = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	unsigned char ARIA_KH_TEST_256_VECTOR_KEY[32] = {	0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	unsigned char ARIA_KH_TEST_256_VECTOR_PT0[16] = {	0x11,0x11,0x11,0x11,0xaa,0xaa,0xaa,0xaa,0x11,0x11,0x11,0x11,0xbb,0xbb,0xbb,0xbb};
	unsigned char ARIA_KH_TEST_256_VECTOR_CT0[16] =	{ 0x58,0xa8,0x75,0xe6,0x04,0x4a,0xd7,0xff,0xfa,0x4f,0x58,0x42,0x0f,0x7f,0x44,0x2d};

	unsigned char ARIA_KH_TEST_256_VECTOR_PT1[16] = {	0x11,0x11,0x11,0x11,0xcc,0xcc,0xcc,0xcc,0x11,0x11,0x11,0x11,0xdd,0xdd,0xdd,0xdd};
	unsigned char ARIA_KH_TEST_256_VECTOR_CT1[16] = {	0x8e,0x19,0x10,0x16,0xf2,0x8e,0x79,0xae,0xfc,0x01,0xe2,0x04,0x77,0x32,0x80,0xd7};

	unsigned char ARIA_KH_TEST_256_VECTOR_PT2[16] = {	0x22,0x22,0x22,0x22,0xaa,0xaa,0xaa,0xaa,0x22,0x22,0x22,0x22,0xbb,0xbb,0xbb,0xbb};
	unsigned char ARIA_KH_TEST_256_VECTOR_CT2[16] = {	0x01,0x8e,0x5f,0x7a,0x93,0x8e,0xc3,0x07,0x11,0x71,0x99,0x53,0xba,0xe8,0x65,0x42};

	unsigned char ARIA_KH_TEST_256_VECTOR_PT3[16] = {	0x22,0x22,0x22,0x22,0xcc,0xcc,0xcc,0xcc,0x22,0x22,0x22,0x22,0xdd,0xdd,0xdd,0xdd};
	unsigned char ARIA_KH_TEST_256_VECTOR_CT3[16] = {	0xcd,0x7e,0xbc,0x75,0x24,0x74,0xc1,0xa5,0xf6,0xea,0xaa,0xce,0x2a,0x7e,0x29,0x46};




	unsigned char  *P_PT[4];	
	unsigned char  *P_CT[4];	

	unsigned char  *P_PT_Dec[4];	
	unsigned char  *P_CT_Dec[4];	
	unsigned char OUT_CT[16];
	unsigned char OUT_PT[16];	
	int ARIAMODE =MODE256;
	int success = 1;
	unsigned int iStart,iEnd;
	unsigned int totalEncode = 0;
	unsigned int totalDecode = 0;
	AT91S_RTTC *pRSTC = (AT91S_RTTC *) 0xFFFFFD20;  



	P_PT[0] = ARIA_KH_TEST_256_VECTOR_PT0;
	P_PT[1] = ARIA_KH_TEST_256_VECTOR_PT1;
	P_PT[2] = ARIA_KH_TEST_256_VECTOR_PT2;	
	P_PT[3] = ARIA_KH_TEST_256_VECTOR_PT3;		

	P_CT[0] = ARIA_KH_TEST_256_VECTOR_CT0;
	P_CT[1] = ARIA_KH_TEST_256_VECTOR_CT1;
	P_CT[2] = ARIA_KH_TEST_256_VECTOR_CT2;	
	P_CT[3] = ARIA_KH_TEST_256_VECTOR_CT3;		

	P_PT_Dec[0] = ARIA_KH_TEST_256_VECTOR_PT0;
	P_PT_Dec[1] = ARIA_KH_TEST_256_VECTOR_PT1;
	P_PT_Dec[2] = ARIA_KH_TEST_256_VECTOR_PT2;	
	P_PT_Dec[3] = ARIA_KH_TEST_256_VECTOR_PT3;		

	P_CT_Dec[0] = ARIA_KH_TEST_256_VECTOR_CT0;
	P_CT_Dec[1] = ARIA_KH_TEST_256_VECTOR_CT1;
	P_CT_Dec[2] = ARIA_KH_TEST_256_VECTOR_CT2;	
	P_CT_Dec[3] = ARIA_KH_TEST_256_VECTOR_CT3;	
	mode = MODE256;
	if(KeySave(0,ARIA_KH_TEST_256_VECTOR_KEY,mode) == 0)
		return 2;
	//for(l = 0; l <250; l++)
	{
		//for(k= 0; k< 4; k++)
		{

			tx_data[0] = 0x0;// KEY_0
			tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			{
				tx_data[0] = 0x0;
			}
			tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			tx_data[0] = 0x9;
			tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
			tx_data[0] = 0x2;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			tx_data[0] = 0x3;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			delay_us(30);
			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			tx_data[0] = 0x4;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
			////////////////////////////////////////////////////////////////////////////////////////////////////////////
			j = 15;
			for(i = 0; i < 16; i++)
				tx_data[i] = P_PT[k][j--];
			AT91F_RTTClearAlarmINT(pRSTC);
			AT91F_RTTClearRttIncINT(pRSTC);
			AT91F_RTTC_CfgPMC();
			AT91F_RTTSetPrescaler(pRSTC,1);
			AT91F_RTTRestart(pRSTC);	
			Delay_ms(1);
			iStart = pRSTC->RTTC_RTVR;

			tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
			delay_us(2);	


			tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
			iEnd = pRSTC->RTTC_RTVR;
			totalEncode += iEnd - iStart;


			j = 15;
			for(i = 0; i < 16; i++)
				OUT_CT[i] = rx_data[j--];
			if(memcmp(OUT_CT,P_CT[k],16) != 0 )
			{
				printk("\r\n\r\nError VerifyAES ARIA_KH_TEST_256_VECTOR_PT0 ENC");
				printk("\r\n OUT_CT \r\n");
				printbyte(OUT_CT,16);

				printk("\r\n P_CT[%d] \r\n",k);
				printbyte(P_CT[k],16);
				success = 0;

			}
			else
			{
				//printk("\r\n SUCCESSS TO VERIFY ARIA_KH_TEST_256_VECTOR_PT0 ENC %d",k);
			}

			j = 15;
			for(i = 0; i < 16; i++)
				tx_data[i] = P_CT_Dec[k][j--];
			AT91F_RTTClearAlarmINT(pRSTC);
			AT91F_RTTClearRttIncINT(pRSTC);
			AT91F_RTTC_CfgPMC();
			AT91F_RTTSetPrescaler(pRSTC,1);
			AT91F_RTTRestart(pRSTC);	
			Delay_ms(1);
			iStart = pRSTC->RTTC_RTVR;
			tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
			delay_us(2);	


			tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
			iEnd = pRSTC->RTTC_RTVR;
			totalDecode += iEnd - iStart;
			j = 15;
			for(i = 0; i < 16; i++)
				OUT_PT[i] = rx_data[j--];


			if(memcmp(OUT_PT,P_PT_Dec[k],16) != 0 )
			{
				success = 0;
				printk("\r\n\r\nError VerifyARIA ARIA_KH_TEST_256_VECTOR_PT0 DEC");

			}
			else
			{
				//printk("\r\n SUCCESSS TO VERIFY ARIA_KH_TEST_256_VECTOR_PT0 DEC %d",k);

			}	

			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

			tx_data[0] = 0x1;	
			tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

			endOP();
		}
	}
	//PrintTime(totalEncode/1000,ARIA256ENCODE );
	//PrintTime(totalDecode/1000,ARIA256DECODE );
	if(success)
		printk("\r\n TEST SUCCESS");
	else
		printk("\r\n TEST FAIL");
	return 0;


	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		tx_data[i] = OUT_CT[j--];
	//

	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		OUT_PT[i] = rx_data[j--];
	/*
	if(memcmp(OUT_PT,CM_AES_FIPS_PUB_197_PT,16) != 0)
	{
	PRINTLOG("\r\n AES Decoding FAIL");
	}
	else
	{
	PRINTLOG("\r\n AES Decoding PASS");
	}
	*/


	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	return success;
}
#endif
#if 0
int VerifyAES()//0:128 1: 256
{
	int i;
	int j, k;
	int  mode = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	unsigned char CM_NIST_SP_AES_128_KEY[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char CM_NIST_SP_AES_128_PT1[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
	unsigned char CM_NIST_SP_AES_128_CT1[16] = {0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97};	
	unsigned char CM_NIST_SP_AES_128_PT2[16] = {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
	unsigned char CM_NIST_SP_AES_128_CT2[16] = {0xf5,0xd3,0xd5,0x85,0x03,0xb9,0x69,0x9d,0xe7,0x85,0x89,0x5a,0x96,0xfd,0xba,0xaf};	
	unsigned char CM_NIST_SP_AES_128_PT3[16] = {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
	unsigned char CM_NIST_SP_AES_128_CT3[16] = {0x43,0xb1,0xcd,0x7f,0x59,0x8e,0xce,0x23,0x88,0x1b,0x00,0xe3,0xed,0x03,0x06,0x88};	
	unsigned char CM_NIST_SP_AES_128_PT4[16] = {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char CM_NIST_SP_AES_128_CT4[16] = {0x7b,0x0c,0x78,0x5e,0x27,0xe8,0xad,0x3f,0x82,0x23,0x20,0x71,0x04,0x72,0x5d,0xd4};		


	unsigned char CM_NIST_SP_AES_128_KEY_Dec[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char CM_NIST_SP_AES_128_PT1_Dec[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
	unsigned char CM_NIST_SP_AES_128_CT1_Dec[16] = {0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97};	
	unsigned char CM_NIST_SP_AES_128_PT2_Dec[16] = {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
	unsigned char CM_NIST_SP_AES_128_CT2_Dec[16] = {0xf5,0xd3,0xd5,0x85,0x03,0xb9,0x69,0x9d,0xe7,0x85,0x89,0x5a,0x96,0xfd,0xba,0xaf};	
	unsigned char CM_NIST_SP_AES_128_PT3_Dec[16] = {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
	unsigned char CM_NIST_SP_AES_128_CT3_Dec[16] = {0x43,0xb1,0xcd,0x7f,0x59,0x8e,0xce,0x23,0x88,0x1b,0x00,0xe3,0xed,0x03,0x06,0x88};	
	unsigned char CM_NIST_SP_AES_128_PT4_Dec[16] = {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char CM_NIST_SP_AES_128_CT4_Dec[16] = {0x7b,0x0c,0x78,0x5e,0x27,0xe8,0xad,0x3f,0x82,0x23,0x20,0x71,0x04,0x72,0x5d,0xd4};		

	unsigned char  *P_PT[4];	
	unsigned char  *P_CT[4];	

	unsigned char  *P_PT_Dec[4];	
	unsigned char  *P_CT_Dec[4];	
	unsigned char OUT_CT[16];
	unsigned char OUT_PT[16];	
	int AESMODE =MODE128;
	int success = 1;

	P_PT[0] = CM_NIST_SP_AES_128_PT1;
	P_PT[1] = CM_NIST_SP_AES_128_PT2;
	P_PT[2] = CM_NIST_SP_AES_128_PT3;	
	P_PT[3] = CM_NIST_SP_AES_128_PT4;		

	P_CT[0] = CM_NIST_SP_AES_128_CT1;
	P_CT[1] = CM_NIST_SP_AES_128_CT2;
	P_CT[2] = CM_NIST_SP_AES_128_CT3;	
	P_CT[3] = CM_NIST_SP_AES_128_CT4;		

	P_PT_Dec[0] = CM_NIST_SP_AES_128_PT1_Dec;
	P_PT_Dec[1] = CM_NIST_SP_AES_128_PT2_Dec;
	P_PT_Dec[2] = CM_NIST_SP_AES_128_PT3_Dec;	
	P_PT_Dec[3] = CM_NIST_SP_AES_128_PT4_Dec;		

	P_CT_Dec[0] = CM_NIST_SP_AES_128_CT1_Dec;
	P_CT_Dec[1] = CM_NIST_SP_AES_128_CT2_Dec;
	P_CT_Dec[2] = CM_NIST_SP_AES_128_CT3_Dec;	
	P_CT_Dec[3] = CM_NIST_SP_AES_128_CT4_Dec;	
	mode = MODE128;
	if(KeySave(0,CM_NIST_SP_AES_128_KEY,mode) == 0)
		return 2;
	for(k= 0; k< 4; k++)
	{

		tx_data[0] = 0x0;// KEY_0
		tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		{
			tx_data[0] = 0x3;
		}
		tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x9;
		tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x2;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		tx_data[0] = 0x3;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		delay_us(30);
		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		tx_data[0] = 0x4;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		////////////////////////////////////////////////////////////////////////////////////////////////////////////
		j = 15;
		for(i = 0; i < 16; i++)
			tx_data[i] = P_PT[k][j--];

		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	


		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
		j = 15;
		for(i = 0; i < 16; i++)
			OUT_CT[i] = rx_data[j--];
		if(memcmp(OUT_CT,P_CT[k],16) != 0 )
		{
			printk("\r\n\r\nError VerifyAES CM_NIST_SP_AES_128_PT1 ENC");
			success = 0;

		}
		else
		{
			printk("\r\n SUCCESSS TO VERIFY ENC %d",k);
		}

		j = 15;
		for(i = 0; i < 16; i++)
			tx_data[i] = P_CT_Dec[k][j--];

		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	


		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		j = 15;
		for(i = 0; i < 16; i++)
			OUT_PT[i] = rx_data[j--];


		if(memcmp(OUT_PT,P_PT_Dec[k],16) != 0 )
		{
			success = 0;
			printk("\r\n\r\nError VerifyAES CM_NIST_SP_AES_128_PT1 DEC");

		}
		else
		{
			printk("\r\n SUCCESSS TO VERIFY DEC %d",k);

		}	

		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

		endOP();
	}

	if(success)
		printk("\r\n TEST SUCCESS");
	else
		printk("\r\n TEST FAIL");
	return 0;


	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		tx_data[i] = OUT_CT[j--];
	//

	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		OUT_PT[i] = rx_data[j--];
	/*
	if(memcmp(OUT_PT,CM_AES_FIPS_PUB_197_PT,16) != 0)
	{
	PRINTLOG("\r\n AES Decoding FAIL");
	}
	else
	{
	PRINTLOG("\r\n AES Decoding PASS");
	}
	*/


	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	return success;
}

int VerifyAES256()//0:128 1: 256
{
	int i;
	int j, k;
	int  mode = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	unsigned char CM_NIST_SP_AES_256_KEY[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
	unsigned char CM_NIST_SP_AES_256_PT1[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
	unsigned char CM_NIST_SP_AES_256_CT1[16] = {0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8};	
	unsigned char CM_NIST_SP_AES_256_PT2[16] = {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
	unsigned char CM_NIST_SP_AES_256_CT2[16] = {0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70};	
	unsigned char CM_NIST_SP_AES_256_PT3[16] = {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
	unsigned char CM_NIST_SP_AES_256_CT3[16] = {0xb6,0xed,0x21,0xb9,0x9c,0xa6,0xf4,0xf9,0xf1,0x53,0xe7,0xb1,0xbe,0xaf,0xed,0x1d};	
	unsigned char CM_NIST_SP_AES_256_PT4[16] = {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char CM_NIST_SP_AES_256_CT4[16] = {0x23,0x30,0x4b,0x7a,0x39,0xf9,0xf3,0xff,0x06,0x7d,0x8d,0x8f,0x9e,0x24,0xec,0xc7};		



	unsigned char CM_NIST_SP_AES_256_PT1_Dec[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
	unsigned char CM_NIST_SP_AES_256_CT1_Dec[16] = {0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8};	
	unsigned char CM_NIST_SP_AES_256_PT2_Dec[16] = {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
	unsigned char CM_NIST_SP_AES_256_CT2_Dec[16] = {0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70};	
	unsigned char CM_NIST_SP_AES_256_PT3_Dec[16] = {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
	unsigned char CM_NIST_SP_AES_256_CT3_Dec[16] = {0xb6,0xed,0x21,0xb9,0x9c,0xa6,0xf4,0xf9,0xf1,0x53,0xe7,0xb1,0xbe,0xaf,0xed,0x1d};	
	unsigned char CM_NIST_SP_AES_256_PT4_Dec[16] = {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char CM_NIST_SP_AES_256_CT4_Dec[16] = {0x23,0x30,0x4b,0x7a,0x39,0xf9,0xf3,0xff,0x06,0x7d,0x8d,0x8f,0x9e,0x24,0xec,0xc7};		

	unsigned char  *P_PT[4];	
	unsigned char  *P_CT[4];	

	unsigned char  *P_PT_Dec[4];	
	unsigned char  *P_CT_Dec[4];	
	unsigned char OUT_CT[16];
	unsigned char OUT_PT[16];	
	int AESMODE =MODE256;
	int success = 1;

	P_PT[0] = CM_NIST_SP_AES_256_PT1;
	P_PT[1] = CM_NIST_SP_AES_256_PT2;
	P_PT[2] = CM_NIST_SP_AES_256_PT3;	
	P_PT[3] = CM_NIST_SP_AES_256_PT4;		

	P_CT[0] = CM_NIST_SP_AES_256_CT1;
	P_CT[1] = CM_NIST_SP_AES_256_CT2;
	P_CT[2] = CM_NIST_SP_AES_256_CT3;	
	P_CT[3] = CM_NIST_SP_AES_256_CT4;		

	P_PT_Dec[0] = CM_NIST_SP_AES_256_PT1_Dec;
	P_PT_Dec[1] = CM_NIST_SP_AES_256_PT2_Dec;
	P_PT_Dec[2] = CM_NIST_SP_AES_256_PT3_Dec;	
	P_PT_Dec[3] = CM_NIST_SP_AES_256_PT4_Dec;		

	P_CT_Dec[0] = CM_NIST_SP_AES_256_CT1_Dec;
	P_CT_Dec[1] = CM_NIST_SP_AES_256_CT2_Dec;
	P_CT_Dec[2] = CM_NIST_SP_AES_256_CT3_Dec;	
	P_CT_Dec[3] = CM_NIST_SP_AES_256_CT4_Dec;	
	for(k= 0; k< 4; k++)
	{
		mode = MODE256;
		if(KeySave(0,CM_NIST_SP_AES_256_KEY,mode) == 0)
			return 2;
		tx_data[0] = 0x0;// KEY_0
		tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		{
			tx_data[0] = 1;//AES 256
		}
		tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x9;
		tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x2;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		tx_data[0] = 0x3;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		delay_us(30);
		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		tx_data[0] = 0x4;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
		////////////////////////////////////////////////////////////////////////////////////////////////////////////
		j = 15;
		for(i = 0; i < 16; i++)
			tx_data[i] = P_PT[k][j--];

		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	


		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
		j = 15;
		for(i = 0; i < 16; i++)
			OUT_CT[i] = rx_data[j--];
		if(memcmp(OUT_CT,P_CT[k],16) != 0 )
		{
			printk("\r\n\r\nError VerifyAES CM_NIST_SP_AES_256_PT1 ENC");
			success = 0;

		}
		else
		{
			printk("\r\n SUCCESSS TO VERIFY ENC 256 %d",k);
		}

		j = 15;
		for(i = 0; i < 16; i++)
			tx_data[i] = P_CT_Dec[k][j--];

		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	


		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		j = 15;
		for(i = 0; i < 16; i++)
			OUT_PT[i] = rx_data[j--];


		if(memcmp(OUT_PT,P_PT_Dec[k],16) != 0 )
		{
			success = 0;
			printk("\r\n\r\nError VerifyAES CM_NIST_SP_AES_256_PT1 DEC");

		}
		else
		{
			printk("\r\n SUCCESSS TO VERIFY DEC 256 %d",k);

		}	

		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

		tx_data[0] = 0x1;	
		tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

		endOP();
	}

	if(success)
		printk("\r\n TEST SUCCESS");
	else
		printk("\r\n TEST FAIL");
	return 0;


	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		tx_data[i] = OUT_CT[j--];
	//

	//	j = 15;
	//	for(i = 0; i < 16; i++)
	//		OUT_PT[i] = rx_data[j--];
	/*
	if(memcmp(OUT_PT,CM_AES_FIPS_PUB_197_PT,16) != 0)
	{
	PRINTLOG("\r\n AES Decoding FAIL");
	}
	else
	{
	PRINTLOG("\r\n AES Decoding PASS");
	}
	*/


	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	return success;
}
#endif
#define DEBUG_AES_ARIA 0
int g_KeyloadFailCnt = 0;
int AES(int  mode,int aes_aria)
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	static unsigned char CM_AES_FIPS_PUB_197_KEY[32] ={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
	static unsigned char CM_AES_FIPS_PUB_197_PT[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	static unsigned char CM_AES_FIPS_PUB_197_CT[16] = {0x8E,0xA2,0xB7,0xCA,0x51,0x67,0x45,0xBF,0xEA,0xFC,0x49,0x90,0x4B,0x49,0x60,0x89};
	unsigned char OUT_CT[16];	
	unsigned char OUT_PT[16];		   
	unsigned char SW_OUT_CT[16];	
	unsigned char SW_OUT_PT[16];
	unsigned char KEY_BUFFER[32];
	unsigned char MADE_KEY[64];
	int AESMODE =MODE128;
	int success = 1;

	AES_KEY aes256_ekey,aes256_dkey;
	ARIA_KEY e_key, d_key;
	
	int Repeat = 0;
	int FlagSuccess = 1;
	int isFisrt = 1;
	memset(KEY_BUFFER,0,32);
			for(i = 0; i < 32; i++)
			{
				CM_AES_FIPS_PUB_197_KEY[i] = rand()&0xFF;
					
			}
			for(i = 0; i < 16; i++)
			{
				CM_AES_FIPS_PUB_197_PT[i] = rand()&0xFF;
			}
			if(MODE128 == mode) {
				for(i = 16; i < 32; i++)
					{
						CM_AES_FIPS_PUB_197_KEY[i] = 0;
							
					}
			}
			success = 1;
			memset(KEY_BUFFER,0,32);	
			if(MODE256 == mode)
			{
				memcpy(KEY_BUFFER,CM_AES_FIPS_PUB_197_KEY+16,16);
				memcpy(KEY_BUFFER+16,CM_AES_FIPS_PUB_197_KEY,16);		
				printk("\r\n KEY");
				printbyte_enc(CM_AES_FIPS_PUB_197_KEY,32);
				KEY_SET(KEY_BUFFER);
			}
			if(MODE128 == mode)
			{
				printk("\r\n KEY");
				printbyte_enc(CM_AES_FIPS_PUB_197_KEY,16);
				memcpy(KEY_BUFFER+16,CM_AES_FIPS_PUB_197_KEY,16);
				KEY_SET(KEY_BUFFER);

			}


	for(i = 0; i < 16; i++)
	{
		CM_AES_FIPS_PUB_197_PT[i] = rand()&0xFF;
	}
	printk("\r\n PT");
	printbyte(CM_AES_FIPS_PUB_197_PT,16);
	if(aes_aria == 0) {
		if(mode == MODE256)
		{
			AES_set_encrypt_key(CM_AES_FIPS_PUB_197_KEY, 256, &aes256_ekey);
			AES_set_decrypt_key(CM_AES_FIPS_PUB_197_KEY, 256, &aes256_dkey);
		}
		else
		{
			AES_set_encrypt_key(CM_AES_FIPS_PUB_197_KEY, 128, &aes256_ekey);
			AES_set_decrypt_key(CM_AES_FIPS_PUB_197_KEY, 128, &aes256_dkey);
		}	
	}
	else {
		
	    if(mode == MODE256)
		{
			aria_set_encrypt_key(CM_AES_FIPS_PUB_197_KEY, 256, &e_key);   
			aria_set_decrypt_key(CM_AES_FIPS_PUB_197_KEY, 256, &d_key);
			printk("\r\n KEY");
			printbyte_enc(CM_AES_FIPS_PUB_197_KEY,32);		

			memcpy(KEY_BUFFER,CM_AES_FIPS_PUB_197_KEY+16,16);
			memcpy(KEY_BUFFER+16,CM_AES_FIPS_PUB_197_KEY,16);		
			KEY_SET(KEY_BUFFER);
		}
		else
		{
			aria_set_encrypt_key(CM_AES_FIPS_PUB_197_KEY, 128, &e_key);   
			aria_set_decrypt_key(CM_AES_FIPS_PUB_197_KEY, 128, &d_key);	
			printk("\r\n KEY");
			printbyte_enc(CM_AES_FIPS_PUB_197_KEY,16);
			memcpy(KEY_BUFFER+16,CM_AES_FIPS_PUB_197_KEY,16);
			KEY_SET(KEY_BUFFER);			
		}
	}

	tx_data[0] = 0x0;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(aes_aria == 0)
	{
		if(mode == MODE256)
		{
			tx_data[0] = 0x1;// AES_256
		}
		else
		{
			tx_data[0] = 0x3;
		}
	}
	if(aes_aria == 1)
	{
		if(mode == MODE256)
		{
			tx_data[0] = 0x0;// ARIA_256
		}
		else
		{
			tx_data[0] = 0x2;
		}
	}	
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA
	printk("\r\n RG_ST2 MODE START");
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
#endif	
	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA	
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 03: %02x",rx_data[0]);	
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	//ReadStatusRegister();
#endif
	delay_us(30);
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA	
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 01: %02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	//ReadStatusRegister();
#endif
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA	
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 04: %02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	//ReadStatusRegister();
#endif
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	j = 15;
	for(i = 0; i < 16; i++)
		tx_data[i] = CM_AES_FIPS_PUB_197_PT[j--];

	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(20);	


	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	j = 15;
	for(i = 0; i < 16; i++)
		OUT_CT[i] = rx_data[j--];
	/*
	if(memcmp(OUT_CT,CM_AES_FIPS_PUB_197_CT,16) != 0)
	{
	PRINTLOG("\r\n AES Encoding FAIL");
	}
	else
	{
	PRINTLOG("\r\n AES Encoding PASS");
	}
	*/
	if(aes_aria == 0) {
		AES_ecb_encrypt(CM_AES_FIPS_PUB_197_PT, SW_OUT_CT, &aes256_ekey, AES_ENCRYPT);
	}
	else {
		aria_encrypt(CM_AES_FIPS_PUB_197_PT, SW_OUT_CT, &e_key);
	}
		
	//	PRINTLOG("\r\n OUT_CT :");
	//	printbyte_enc(OUT_CT,16);
	//	PRINTLOG("\r\n SW_OUT_CT :");
	//	printbyte_enc(SW_OUT_CT,16);
	if(memcmp(SW_OUT_CT,OUT_CT,16) != 0)
	{
		////ReadStatusRegister();
		printk("\r\n PT");
		printbyte_enc(CM_AES_FIPS_PUB_197_PT,16);
		PRINTLOG("\r\n OUT_CT :");
		printbyte_enc(OUT_CT,16);
		PRINTLOG("\r\n SW_OUT_CT :");
		printbyte_enc(SW_OUT_CT,16);
		PRINTLOG("\r\n FAIL AES ENCODING ");
		success = 0;
	}
	else
	{
		PRINTLOG("\r\n PASS AES ENCODING");
	}
	if(mode == 1)
		PRINTLOG("256");
	else
		PRINTLOG("128");
	
	if(aes_aria == 0)
		printk("\r\n AES");
	else
		printk("\r\n ARIA");


	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	j = 15;
	for(i = 0; i < 16; i++)
		tx_data[i] = OUT_CT[j--];

	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(20);	


	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	j = 15;
	for(i = 0; i < 16; i++)
		OUT_PT[i] = rx_data[j--];
	/*
	if(memcmp(OUT_PT,CM_AES_FIPS_PUB_197_PT,16) != 0)
	{
	PRINTLOG("\r\n AES Decoding FAIL");
	}
	else
	{
	PRINTLOG("\r\n AES Decoding PASS");
	}
	*/
	if(aes_aria == 0) {
		AES_ecb_encrypt(SW_OUT_CT, SW_OUT_PT, &aes256_dkey, AES_DECRYPT);
	}
	else {
		aria_encrypt(SW_OUT_CT, SW_OUT_PT, &d_key);
	}

	//	PRINTLOG("\r\n OUT_PT :");
	//	printbyte_enc(OUT_PT,16);
	//	PRINTLOG("\r\n SW_OUT_PT :");
	//	printbyte_enc(SW_OUT_PT,16);

	if(memcmp(SW_OUT_PT,OUT_PT,16) != 0)
	{

		PRINTLOG("\r\n OUT_PT :");
		printbyte_enc(OUT_PT,16);
		PRINTLOG("\r\n SW_OUT_PT :");
		printbyte_enc(SW_OUT_PT,16);
		PRINTLOG("\r\n FAIL AES DECODING");
		success = 0;
	}
	else
	{
		PRINTLOG("\r\n PASS AES DECODING");
	}
	if(mode == 1)
		PRINTLOG("256");
	else
		PRINTLOG("128");
	if(aes_aria == 0)
		printk("\r\n AES");
	else
		printk("\r\n ARIA");

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();


	printk("\n\n---------------------------------------------\n");
	printk("KEY");
	if(mode == 1)
		printbyte_enc(CM_AES_FIPS_PUB_197_KEY,32);
	else
		printbyte_enc(CM_AES_FIPS_PUB_197_KEY,16);
	printk("\n");


	printk("\nPT(Plain Text)");
	printbyte_enc(CM_AES_FIPS_PUB_197_PT,16);

	printk("\n\nEncryption....\n");
	printk("\nCT(Cipher Text)\n");
	PRINTLOG("\nOUT_CT :");
	printbyte_enc(OUT_CT,16);
	PRINTLOG("\nSW_OUT_CT :");
	printbyte_enc(SW_OUT_CT,16);

	
	printk("\n\nDecryption....\n");
	PRINTLOG("\n OUT_PT :");
	printbyte_enc(OUT_PT,16);
	PRINTLOG("\n SW_OUT_PT :");
	printbyte_enc(SW_OUT_PT,16);
	printk("\n\n---------------------------------------------\n");

	return success;
#endif 	
}



#if 0
int AES_WITH_KEY(int     mode,int index)
{
	int i;
	int j;
	unsigned int inst = 0;
	unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	static unsigned char CM_AES_FIPS_PUB_197_PT[16];

	unsigned char OUT_CT[16];	
	unsigned char OUT_PT[16];		   
	unsigned char SW_OUT_CT[16];	




	memset(tx_data,0x22,64);
	memset(CM_AES_FIPS_PUB_197_PT,0x11,16);
	memset(rx_data,0,64);
	eep_page_write(0xE9,0x40,rx_data,1);
	eep_page_write(0xE9,0x80,rx_data,1);
	eep_page_write(0xE9,0xC0,rx_data,1);
	
	if(mode == MODE128)
		hexstr2bytes("713A3D71DE770768BD7AA2EAC7771986", SW_OUT_CT);
	else 
		hexstr2bytes("2DCC4A9BDA4068391E0A50F23D55BD3C",SW_OUT_CT );
		
	switch(index)
	{
		case 1:
			addr[0] = 0xE9;
			addr[1] = 0x40;
			break;
		case 2:
			addr[0] = 0xE9;
			addr[1] = 0x80;			
			break;
		case 3:
			addr[0] = 0xE9;
			addr[1] = 0xC0;			
		break;
		default: printk("\r\n error address");
	}



	eep_page_write(addr[0],addr[1],tx_data,1);	
	ReadKEYAES_X();	
	printk("\r\n index %d",index);
	tx_data[0] = index;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(mode == MODE256)
	{
		tx_data[0] = 0x0;// AES_256
	}
	else
	{
		tx_data[0] = 0x2;
	}
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA
	printk("\r\n RG_ST2 MODE START");
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
#endif	
	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA	
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 03: %02x",rx_data[0]);	
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	ReadStatusRegister();
#endif
	delay_us(30);
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA	
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	
	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 01: %02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	ReadStatusRegister();
#endif
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA	
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 04: %02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	ReadStatusRegister();
#endif
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	j = 15;
	for(i = 0; i < 16; i++)
		tx_data[i] = CM_AES_FIPS_PUB_197_PT[j--];

	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(20);	


	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	j = 15;
	for(i = 0; i < 16; i++)
		OUT_CT[i] = rx_data[j--];
	if(mode == MODE128)
		printk("\r\n MODE128 ");
	else
		printk("\r\n MODE256 ");
	
	printk("\r\n OUT_CT index %d", index);
	printbyte(OUT_CT,16);
	if(memcmp(SW_OUT_CT,OUT_CT,16) != 0)
	{

		PRINTLOG("\r\n OUT_CT :");
		printbyte_enc(OUT_CT,16);
		PRINTLOG("\r\n SW_OUT_CT :");
		printbyte_enc(SW_OUT_CT,16);
		PRINTLOG("\r\n FAIL AES ENCODING");
	}
	else
	{
		PRINTLOG("\r\n PASS AES ENCODING");
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	j = 15;
	for(i = 0; i < 16; i++)
		tx_data[i] = OUT_CT[j--];

	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(20);	


	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	j = 15;
	for(i = 0; i < 16; i++)
		OUT_PT[i] = rx_data[j--];

	if(memcmp(CM_AES_FIPS_PUB_197_PT,OUT_PT,16) != 0)
	{

		PRINTLOG("\r\n OUT_PT :");
		printbyte_enc(OUT_PT,16);
		PRINTLOG("\r\n CM_AES_FIPS_PUB_197_PT :");
		printbyte_enc(CM_AES_FIPS_PUB_197_PT,16);
		PRINTLOG("\r\n FAIL AES DECODING");
	}
	else
	{
		PRINTLOG("\r\n PASS AES DECODING");
	}
	
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();


}
#endif

void DummyAES()

{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	static unsigned char CM_AES_FIPS_PUB_197_KEY[32] ={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
	static unsigned char CM_AES_FIPS_PUB_197_PT[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	static unsigned char CM_AES_FIPS_PUB_197_CT[16] = {0x8E,0xA2,0xB7,0xCA,0x51,0x67,0x45,0xBF,0xEA,0xFC,0x49,0x90,0x4B,0x49,0x60,0x89};
	unsigned char OUT_CT[16];	
	unsigned char OUT_PT[16];		   
	unsigned char SW_OUT_CT[16];	
	unsigned char SW_OUT_PT[16];
	unsigned char KEY_BUFFER[32];
	unsigned char MADE_KEY[64];
	int AESMODE =MODE128;
	int success = 1;
	AES_KEY aes256_ekey,aes256_dkey;
	int Repeat = 0;
	int FlagSuccess = 1;
	int isFisrt = 1;
	memset(KEY_BUFFER,0,32);

	tx_data[0] = 0x0;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL	   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	{
		tx_data[0] = 0x1;// AES_256
	}

	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL		, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE	  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA
	printk("\r\n RG_ST2 MODE START");
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
#endif	
	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA	
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 03: %02x",rx_data[0]);	
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	ReadStatusRegister();
#endif
	delay_us(30);
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA	
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	
	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 01: %02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	ReadStatusRegister();
#endif
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
#if DEBUG_AES_ARIA	
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 04: %02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	ReadStatusRegister();
#endif
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	j = 15;
	for(i = 0; i < 16; i++)
		tx_data[i] = CM_AES_FIPS_PUB_197_PT[j--];

	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300		, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(20);	


	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320		, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	j = 15;
	for(i = 0; i < 16; i++)
		OUT_CT[i] = rx_data[j--];
	/*
	if(memcmp(OUT_CT,CM_AES_FIPS_PUB_197_CT,16) != 0)
	{
	PRINTLOG("\r\n AES Encoding FAIL");
	}
	else
	{
	PRINTLOG("\r\n AES Encoding PASS");
	}
	*/
	j = 15;
	for(i = 0; i < 16; i++)
		tx_data[i] = OUT_CT[j--];

	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400		, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(20);	


	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420		, NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	j = 15;
	for(i = 0; i < 16; i++)
		OUT_PT[i] = rx_data[j--];

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE 	 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
#endif	

}



int ARIA(int mode)

{
#ifdef COMPARE

	int i;
	int j;
	int success = 1;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	static unsigned char ARIA_KEY0[32] ={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
	static unsigned char ARIA_PT[16] = {0x11 ,0x11 ,0x11 ,0x11 ,0xaa ,0xaa ,0xaa ,0xaa ,0x11 ,0x11 ,0x11 ,0x11 ,0xbb ,0xbb ,0xbb ,0xbb};
	static unsigned char ARIA_CT[16] = {0x58 ,0xa8 ,0x75 ,0xe6 ,0x04 ,0x4a ,0xd7 ,0xff ,0xfa ,0x4f ,0x58 ,0x42 ,0x0f ,0x7f ,0x44 ,0x2d};
	unsigned char OUT_CT[16];	
	unsigned char OUT_PT[16];		   
	unsigned char SW_OUT_CT[16];	
	unsigned char SW_OUT_PT[16];	
	unsigned char KEY_BUFFER[64];
	ARIA_KEY e_key, d_key;
	int Repeat = 0;
	int FlagSuccess = 1;
	int isFisrt = 1;
	if( 1 == Aria256 || 1 == Aria128 )
	{
		for ( i=0; i<16; i++)	
		{       
			ARIA_KEY0[i] =i;// rand()&0xFF;       	
			ARIA_KEY0[i+16] = i;//rand()&0xFF;       	
			ARIA_PT[i]  = rand()&0xFF;
		}	   
		printk("\r\n =========================== START ARIA =====================");
		//	printk("\r\n PT");
		//	printbyte_enc(ARIA_PT,16);
		memset(KEY_BUFFER,0,32);

		if(mode == MODE256)
		{
			aria_set_encrypt_key(ARIA_KEY0, 256, &e_key);   
			aria_set_decrypt_key(ARIA_KEY0, 256, &d_key);
			printk("\r\n KEY");
			printbyte_enc(ARIA_KEY0,32);		

			memcpy(KEY_BUFFER,ARIA_KEY0+16,16);
			memcpy(KEY_BUFFER+16,ARIA_KEY0,16);		
			KEY_SET(KEY_BUFFER);
			Aria256  = 0;
		}
		else
		{
			aria_set_encrypt_key(ARIA_KEY0, 128, &e_key);   
			aria_set_decrypt_key(ARIA_KEY0, 128, &d_key);	
			printk("\r\n KEY");
			printbyte_enc(ARIA_KEY0,16);
			memcpy(KEY_BUFFER+16,ARIA_KEY0,16);
			KEY_SET(KEY_BUFFER);			
			Aria128 = 0;
		}

		/*
		if(memcmp(KEY_GLOBAL_BUFFER,ARIA_KEY0,32) != 0 )
		{
				printk("\r\n KEYLOAD_KEY");
				printbyte(KEY_GLOBAL_BUFFER,32);

				printk("\r\n SW KEY");
				printbyte(ARIA_KEY0,32);
		}	
		else
		{
			printk("\r\n KEY WAS MADE, TEST PASS");
		}
		*/
		AriaIsFirst = 0;
	}
	L_START_ARIA:
	printk("\r\n START OF ARIA  REPEAT %d",Repeat);

	tx_data[0] = 0x0;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(mode == MODE256)
	{
		tx_data[0] = 0x0;// ARIA_256
	}
	else
	{
		tx_data[0] = 0x2;
	}
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	#if DEBUG_AES_ARIA	
	printk("\r\n RG_ST2 MODE START");
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	#endif


	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	#if DEBUG_AES_ARIA
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 03: %02x",rx_data[0]);	
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	ReadStatusRegister();	
	#endif
	delay_us(30);
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	#if DEBUG_AES_ARIA	
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 01: %02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);	
	#endif
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	#if DEBUG_AES_ARIA	
	tspi_interface(cs, ADDR_NOR_R, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	printk("\r\n READ RG_ST2_SYMCIP_OPMODE expected 04: %02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);	
	#endif
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	j = 15;
	for(i = 0; i < 16; i++)
		tx_data[i] = ARIA_PT[j--];

	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(20);	


	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	j = 15;
	for(i = 0; i < 16; i++)
		OUT_CT[i] = rx_data[j--];
	//	PRINTLOG("\r\n OUT_CT:");
	//	printbyte_enc(OUT_CT,16);

	aria_encrypt(ARIA_PT, SW_OUT_CT, &e_key);

	//	PRINTLOG("\r\n SW_OUT_CT:");
	//	printbyte_enc(SW_OUT_CT,16);
#ifdef TEST_MODE
	if(memcmp(OUT_CT,SW_OUT_CT,16) != 0)
	{

		printk("\r\n PT");
		printbyte_enc(ARIA_PT,16);		
		PRINTLOG("\r\n OUT_CT:");
		printbyte_enc(OUT_CT,16);



		PRINTLOG("\r\n SW_OUT_CT:");
		printbyte_enc(SW_OUT_CT,16);	
		printbyte_enc(ARIA_PT,16);
		PRINTLOG("\r\nFAIL ARIA ENCODING ");
		success = 0;
		if( 1 == isFisrt)
		{
			FlagSuccess =0;
			isFisrt = 0;
		}				
	}
	else
	{
		PRINTLOG("\r\nPASS ARIA ENCODING ");
	}
	if(mode == 1)
		PRINTLOG("256");
	else
		PRINTLOG("128");
#endif
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	j = 15;
	for(i = 0; i < 16; i++)
		tx_data[i] = SW_OUT_CT[j--];

	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(20);	


	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	j = 15;
	for(i = 0; i < 16; i++)
		OUT_PT[i] = rx_data[j--];


	aria_encrypt(SW_OUT_CT, SW_OUT_PT, &d_key);


	//	PRINTLOG("\r\n SW_OUT_PT:");
	//	printbyte_enc(SW_OUT_PT,16);

	//	PRINTLOG("\r\n OUT_PT:");
	//	printbyte_enc(OUT_PT,16);
#ifdef TEST_MODE
	if(memcmp(OUT_PT,SW_OUT_PT,16) != 0)
	{

		PRINTLOG("\r\n SW_OUT_PT:");
		printbyte_enc(SW_OUT_PT,16);

		PRINTLOG("\r\n OUT_PT:");
		printbyte_enc(OUT_PT,16);
		PRINTLOG("\r\n FAIL ARIA DECODING");
		success = 0;
		if( 1 == isFisrt)
		{
			FlagSuccess =0;
			isFisrt = 0;
		}
		
	}
	else
	{
		PRINTLOG("\r\n PASS ARIA DECODING");
	}
	if(mode == 1)
		PRINTLOG("256");
	else
		PRINTLOG("128");
#endif
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	if(MODE128 == mode)
	{
			printk("\r\n ARIA_128_TEST");
			printk("\r\n KEY");
			printbyte(ARIA_KEY0,16);
	}
	else
	{
			printk("\r\n ARIA_256_TEST");	
			printk("\r\n KEY");
			printbyte(ARIA_KEY0,32);
	}


	printk("\r\n ==================================================");
	printk("\r\n Encrypt");
	printk("\r\n PT(PlainText)");
	printbyte_enc(ARIA_PT, 16);
	printk("\r\n Expected CT(CipherText)");	
	printbyte_enc(SW_OUT_CT, 16);	
	printk("\r\n Result CT(CipherText)");	
	printbyte_enc(SW_OUT_CT, 16);		
	printk("\r\n ==================================================");
	
	printk("\r\n ==================================================");
	printk("\r\n Decrypt");
	printk("\r\n CT(CipherText)");
	printbyte_enc(SW_OUT_CT, 16);
	printk("\r\n Expected PT(PlainText)");	
	printbyte_enc(SW_OUT_PT, 16);	
	printk("\r\n Result PT(PlainText)");	
	printbyte_enc(SW_OUT_PT, 16);		
	printk("\r\n ==================================================");
	

#endif
	return 1;

}
void AES256Enc()
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char CM_AES_FIPS_PUB_197_KEY[32] ={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
	unsigned char CM_AES_FIPS_PUB_197_PT[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	unsigned char CM_AES_FIPS_PUB_197_CT[16] = {0x8E,0xA2,0xB7,0xCA,0x51,0x67,0x45,0xBF,0xEA,0xFC,0x49,0x90,0x4B,0x49,0x60,0x89};
	unsigned char OUT_CT[16];	
	unsigned char OUT_PT[16];		   
	KeySave(0,CM_AES_FIPS_PUB_197_KEY,MODE256);
	tx_data[0] = 0x0;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x1;// AES_256
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	j = 15;
	for(i = 0; i < 16; i++)
		tx_data[i] = CM_AES_FIPS_PUB_197_PT[j--];

	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(2);	


	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	j = 15;
	for(i = 0; i < 16; i++)
		OUT_CT[i] = rx_data[j--];

	if(memcmp(OUT_CT,CM_AES_FIPS_PUB_197_CT,16) != 0)
	{
		PRINTLOG("\r\n AES Encoding FAIL");
	}
	else
	{
		PRINTLOG("\r\n AES Encoding PASS");
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	j = 15;
	for(i = 0; i < 16; i++)
		tx_data[i] = CM_AES_FIPS_PUB_197_CT[j--];

	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(2);	


	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	j = 15;
	for(i = 0; i < 16; i++)
		OUT_PT[i] = rx_data[j--];

	if(memcmp(OUT_PT,CM_AES_FIPS_PUB_197_PT,16) != 0)
	{
		PRINTLOG("\r\n AES Decoding FAIL");
	}
	else
	{
		PRINTLOG("\r\n AES Decoding PASS");
	}
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
#endif	
}
void SetAddrbyType(int type, unsigned char *addr)
{
	switch(type)
	{
	case A_EE_CONFIG_NW:
		addr[0] = 0xeb;
		addr[1] = 0x40;			
		break;
	case A_EE_CONFIG_FAC:
		addr[0] = 0xeb;
		addr[1] = 0x80;					
		break;
	case A_EE_CONFIG_UID:
		addr[0] = 0xeb;
		addr[1] = 0xc0;					
		break;
	case A_EE_SEED_KEY:
		addr[0] = 0xec;
		addr[1] = 0x00;					
		break;
	case A_EE_CONFIG_USER:
		addr[0] = 0xec;
		addr[1] = 0x40;					
		break;
	case A_EE_CONFIG_LOCK:
		addr[0] = 0xec;
		addr[1] = 0x80;					
		break;
	case A_EE_MEM_TEST:
		addr[0] = 0xec;
		addr[1] = 0xc0;					
		break;
	case A_EE_MIDR:
		addr[0] = 0xed;
		addr[1] = 0x00;					
		break;
	default:
		PRINTLOG("\r\n wrong config type ");
		break;
	}

}
void PrintBuffer(int type, unsigned char *data, unsigned char *addr)
{
	int Byte_num = 64;
	int i = 0;
	printk("\r\n ---------------------------------------------");
	printk("\r\n addr = 0x%02x%02x", addr[0],addr[1]);
	if ( type == TYPE_TX) {
		printk("\r\n spi_tx_data    :"); for ( i=0; i<Byte_num; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) printk("\n                 "); printk(" 0x%02x", data[i]); } }
	else {
		printk("\r\n spi_rx_data    :"); for ( i=0; i<Byte_num; i++ ){ if ( ( i !=0 ) & ( i % 16 == 0 ) ) printk("\n                 "); printk(" 0x%02x", data[i]); } }

}
#define COMPARE_SIZE 64
int WriteAndReadConfigArea(int type,int CompareType)
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr[2];
	unsigned char buf0xxx[64];
	int TestSize =0 ;
	int success = 1;
	memset(buf0xxx,0,64);
	switch(type)
	{
	case A_EE_CONFIG_NW:
		//		PRINTLOG("\r\nTEST A_EE_CONFIG_NW");
		TestSize = 6;
		buf0xxx[0] = 0xaa;
		buf0xxx[1] = 0xaa;		
		buf0xxx[2] = 0xaa;		
		buf0xxx[3] = 0xaa;		
		buf0xxx[4] = 0x0F;				
		buf0xxx[5] = 0x30;						
		break;
	case A_EE_CONFIG_FAC:
		//	PRINTLOG("\r\nTEST A_EE_CONFIG_FAC");
		TestSize = 10;		
		buf0xxx[0] = 0xaa;
		buf0xxx[1] = 0xaa;		
		buf0xxx[2] = 0xaa;		
		buf0xxx[3] = 0xaa;		
		buf0xxx[4] = 0xaa;
		buf0xxx[5] = 0xaa;		
		buf0xxx[6] = 0xaa;		
		buf0xxx[7] = 0xaa;		
		buf0xxx[8] = 0xbb;		
		buf0xxx[9] = 0xbb;				
		break;
	case A_EE_CONFIG_UID:
		TestSize = 10;
		buf0xxx[0] = 0x88;
		buf0xxx[1] = 0x88;		
		buf0xxx[2] = 0x88;		
		buf0xxx[3] = 0x88;		
		buf0xxx[4] = 0x44;
		buf0xxx[5] = 0x44;		
		buf0xxx[6] = 0x88;		
		buf0xxx[7] = 0x88;		
		buf0xxx[8] = 0x88;		
		buf0xxx[9] = 0x88;		
		//PRINTLOG("\r\nTEST A_EE_CONFIG_UID");
		break;
	case A_EE_SEED_KEY:
		//PRINTLOG("\r\nTEST A_EE_SEED_KEY");
		TestSize = 16;
		buf0xxx[0] = 0x11;
		buf0xxx[1] = 0x11;		
		buf0xxx[2] = 0x22;		
		buf0xxx[3] = 0x22;		
		buf0xxx[4] = 0x33;
		buf0xxx[5] = 0x33;		
		buf0xxx[6] = 0x44;		
		buf0xxx[7] = 0x44;		
		buf0xxx[8] = 0x55;		
		buf0xxx[9] = 0x55;	
		buf0xxx[10] = 0x66;			
		buf0xxx[11] = 0x66;					
		buf0xxx[12] = 0x77;							
		buf0xxx[13] = 0x77;									
		buf0xxx[14] = 0x88;											
		buf0xxx[15] = 0x88;													
		break;
	case A_EE_CONFIG_USER:
		//PRINTLOG("\r\nTEST A_EE_CONFIG_USER");
		TestSize = 1;
		break;
	case A_EE_CONFIG_LOCK:
		//PRINTLOG("\r\nTEST A_EE_CONFIG_LOCK");
		TestSize = 19;
		buf0xxx[0] = 0x11;
		buf0xxx[1] = 0x11;		
		buf0xxx[2] = 0x22;		
		buf0xxx[3] = 0x22;		
		buf0xxx[4] = 0x33;
		buf0xxx[5] = 0x33;		
		buf0xxx[6] = 0x44;		
		buf0xxx[7] = 0x44;		
		buf0xxx[8] = 0x55;		
		buf0xxx[9] = 0x55;	
		buf0xxx[10] = 0x66;			
		buf0xxx[11] = 0x66;					
		buf0xxx[12] = 0x77;							
		buf0xxx[13] = 0x77;									
		buf0xxx[14] = 0x88;											
		buf0xxx[15] = 0x88;			
		buf0xxx[16] = 0x99;					
		buf0xxx[17] = 0x99;							
		buf0xxx[18] = 0xaa;									
		break;
	case A_EE_MEM_TEST:
		//PRINTLOG("\r\nTEST A_EE_MEM_TEST");
		memset(buf0xxx,0xFF,TestSize);
		TestSize = 64;
		break;
	case A_EE_MIDR:
		//PRINTLOG("\r\nTEST A_EE_MIDR");
		TestSize = 33;
		buf0xxx[0] = 0x11;
		buf0xxx[1] = 0x11;		
		buf0xxx[2] = 0x22;		
		buf0xxx[3] = 0x22;		
		buf0xxx[4] = 0x33;
		buf0xxx[5] = 0x33;		
		buf0xxx[6] = 0x44;		
		buf0xxx[7] = 0x44;		
		buf0xxx[8] = 0x55;		
		buf0xxx[9] = 0x55;	
		buf0xxx[10] = 0x66;			
		buf0xxx[11] = 0x66;					
		buf0xxx[12] = 0x77;							
		buf0xxx[13] = 0x77;									
		buf0xxx[14] = 0x88;											
		buf0xxx[15] = 0x88;			
		buf0xxx[16] = 0x99;					
		buf0xxx[17] = 0x99;							
		buf0xxx[18] = 0xaa;				
		buf0xxx[19] = 0xaa;				
		buf0xxx[20] = 0xbb;			
		buf0xxx[21] = 0xbb;					
		buf0xxx[22] = 0xcc;							
		buf0xxx[23] = 0xcc;									
		buf0xxx[24] = 0xdd;											
		buf0xxx[25] = 0xdd;			
		buf0xxx[26] = 0xee;					
		buf0xxx[27] = 0xee;							
		buf0xxx[28] = 0xff;				
		buf0xxx[29] = 0xff;				
		buf0xxx[30] = 0xaa;					
		buf0xxx[31] = 0xaa;							
		buf0xxx[32] = 0x00;				


		break;
	default:
		PRINTLOG("\r\n wrong config type ");
		break;
	}
	memset(tx_data,0,64);
	memset(rx_data,0,64);	

	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	SetAddrbyType(type,addr);
	tx_data[0] = addr[1];// 0x00
	tx_data[1] = addr[0];// 0xeb
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB      , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);

	tspi_interface(cs, 0x30, addr      , NULL, NULL, NULL, NULL, buf0xxx, rx_data, 64);
	PrintBuffer(TYPE_TX,buf0xxx,addr);
	delay_ms(8);
	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(TYPE_RX,rx_data,addr);
	delay_us(10);
	if(CompareType == 0 )
	{
		if(memcmp(buf0xxx,rx_data,TestSize) != 0 )
		{
			PRINTLOG("\r\n HIT to write miss on  cfg page with out permission");
		}
		else
		{
			PRINTLOG("\r\n  MISS to write miss on cfg page with out permission");
			success = 0;
		}
		/*
		if(memcmp(buf0xxx,rx_data,COMPARE_SIZE) == 0 )
		{
		PRINTLOG("\r\n 2. HIT to read buffer as 0x%02x",buf0xxx[0]);
		}
		else
		{
		PRINTLOG("\r\n 2. MISS to read buffer as 0x%02x",buf0xxx[0]);
		}
		*/
	}
	else
	{
		if(memcmp(buf0xxx,rx_data,TestSize) == 0 )
		{
			PRINTLOG("\r\n  HIT to write success on cfg page with  permission");
		}
		else
		{
			PRINTLOG("\r\n  MISS to write success on cfg page with  permission");
			success = 0;
		}
	}
	return success;
#endif	
}

int SetCFG_CONFIG_LOCK()
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr[2];
	unsigned char buf0xxx[64];
	int TestSize;
	int type = A_EE_CONFIG_LOCK;
	int CompareType = 0;
	unsigned char bufAll0[64];
	int success = 1;
	PRINTLOG("\r\nTEST A_EE_CONFIG_LOCK");
	TestSize = 19;
	buf0xxx[0] = 0x11;
	buf0xxx[1] = 0x11;		
	buf0xxx[2] = 0x22;		
	buf0xxx[3] = 0x22;		
	buf0xxx[4] = 0x33;
	buf0xxx[5] = 0x33;		
	buf0xxx[6] = 0x44;		
	buf0xxx[7] = 0x44;		
	buf0xxx[8] = 0x55;		
	buf0xxx[9] = 0x55;	
	buf0xxx[10] = 0x66;			
	buf0xxx[11] = 0x66;					
	buf0xxx[12] = 0x77;							
	buf0xxx[13] = 0x77;									
	buf0xxx[14] = 0x88;											
	buf0xxx[15] = 0x88;			
	buf0xxx[16] = 0x99;					
	buf0xxx[17] = 0x99;							
	buf0xxx[18] = 0xaa;	

	START;
	memset(tx_data,0,64);
	memset(rx_data,0,64);	
	CompareType = 0;
	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	SetAddrbyType(type,addr);
	tx_data[0] = addr[1];// 0x00
	tx_data[1] = addr[0];// 0xeb
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB      , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);

	tspi_interface(cs, 0x30, addr      , NULL, NULL, NULL, NULL, buf0xxx, rx_data, 64);
	PrintBuffer(TYPE_TX,buf0xxx,addr);
	delay_ms(8);
	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(TYPE_RX,rx_data,addr);
	delay_us(10);
	if(CompareType == 0 )
	{
		if(memcmp(buf0xxx,rx_data,TestSize) != 0 )
		{
			PRINTLOG("\r\n HIT to write miss on  cfg page with out permission");
		}
		else
		{
			PRINTLOG("\r\n  MISS to write miss on cfg page with out permission");
			success = 0;
		}
	}
	CompareType = 1;
	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	SetAddrbyType(type,addr);
	tx_data[0] = addr[1];// 0x00
	tx_data[1] = addr[0];// 0xeb
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB      , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);

	tspi_interface(cs, 0x30, addr      , NULL, NULL, NULL, NULL, buf0xxx, rx_data, 64);
	PrintBuffer(TYPE_TX,buf0xxx,addr);
	delay_ms(8);
	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(TYPE_RX,rx_data,addr);
	delay_us(10);

	if(CompareType == 1)
	{
		if(memcmp(buf0xxx,rx_data,TestSize) == 0 )
		{
			PRINTLOG("\r\n  HIT to write success on cfg page with  permission");
		}
		else
		{
			PRINTLOG("\r\n  MISS to write success on cfg page with  permission");
			success = 0;
		}
	}

	CompareType = 2;
	memset(bufAll0,0,64);
	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	SetAddrbyType(type,addr);
	tx_data[0] = addr[1];// 0x00
	tx_data[1] = addr[0];// 0xeb
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB      , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);

	tspi_interface(cs, 0x30, addr      , NULL, NULL, NULL, NULL, bufAll0, rx_data, 64);
	PrintBuffer(TYPE_TX,buf0xxx,addr);
	delay_ms(8);
	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(TYPE_RX,rx_data,addr);
	delay_us(10);

	if(CompareType == 2)
	{
		if(memcmp(buf0xxx,rx_data,TestSize) == 0 )
		{
			PRINTLOG("\r\n  HIT to write miss on cfg page with  permission");
		}
		else
		{
			PRINTLOG("\r\n  MISS to write miss on cfg page with  permission");
			success = 0;
		}
	}
	END;
	PrintPASSFAIL(success);
	return success;
#endif
}
//int WriteAndReadConfigArea(int type,int CompareType)
//{
//	int i;
//	int j;
//	unsigned int inst = 0;
//	unsigned char tx_data[64];
//	unsigned char rx_data[64];
//	unsigned char addr[2];
//	unsigned char buf0xxx[64];
//	int TestSize =0 ;
//	int success = 1;
//	memset(buf0xxx,0,64);
//	switch(type)
//	{
//	case A_EE_CONFIG_NW:
//		//		PRINTLOG("\r\nTEST A_EE_CONFIG_NW");
//		TestSize = 6;
//		buf0xxx[0] = 0xaa;
//		buf0xxx[1] = 0xaa;		
//		buf0xxx[2] = 0xaa;		
//		buf0xxx[3] = 0xaa;		
//		buf0xxx[4] = 0x0F;				
//		buf0xxx[5] = 0x30;						
//		break;
//	case A_EE_CONFIG_FAC:
//		//	PRINTLOG("\r\nTEST A_EE_CONFIG_FAC");
//		TestSize = 10;		
//		buf0xxx[0] = 0xaa;
//		buf0xxx[1] = 0xaa;		
//		buf0xxx[2] = 0xaa;		
//		buf0xxx[3] = 0xaa;		
//		buf0xxx[4] = 0xaa;
//		buf0xxx[5] = 0xaa;		
//		buf0xxx[6] = 0xaa;		
//		buf0xxx[7] = 0xaa;		
//		buf0xxx[8] = 0xbb;		
//		buf0xxx[9] = 0xbb;				
//		break;
//	case A_EE_CONFIG_UID:
//		TestSize = 10;
//		buf0xxx[0] = 0x88;
//		buf0xxx[1] = 0x88;		
//		buf0xxx[2] = 0x88;		
//		buf0xxx[3] = 0x88;		
//		buf0xxx[4] = 0x44;
//		buf0xxx[5] = 0x44;		
//		buf0xxx[6] = 0x88;		
//		buf0xxx[7] = 0x88;		
//		buf0xxx[8] = 0x88;		
//		buf0xxx[9] = 0x88;		
//		//PRINTLOG("\r\nTEST A_EE_CONFIG_UID");
//		break;
//	case A_EE_SEED_KEY:
//		//PRINTLOG("\r\nTEST A_EE_SEED_KEY");
//		TestSize = 16;
//		buf0xxx[0] = 0x11;
//		buf0xxx[1] = 0x11;		
//		buf0xxx[2] = 0x22;		
//		buf0xxx[3] = 0x22;		
//		buf0xxx[4] = 0x33;
//		buf0xxx[5] = 0x33;		
//		buf0xxx[6] = 0x44;		
//		buf0xxx[7] = 0x44;		
//		buf0xxx[8] = 0x55;		
//		buf0xxx[9] = 0x55;	
//		buf0xxx[10] = 0x66;			
//		buf0xxx[11] = 0x66;					
//		buf0xxx[12] = 0x77;							
//		buf0xxx[13] = 0x77;									
//		buf0xxx[14] = 0x88;											
//		buf0xxx[15] = 0x88;													
//		break;
//	case A_EE_CONFIG_USER:
//		//PRINTLOG("\r\nTEST A_EE_CONFIG_USER");
//		TestSize = 1;
//		break;
//	case A_EE_CONFIG_LOCK:
//		//PRINTLOG("\r\nTEST A_EE_CONFIG_LOCK");
//		TestSize = 19;
//		buf0xxx[0] = 0x11;
//		buf0xxx[1] = 0x11;		
//		buf0xxx[2] = 0x22;		
//		buf0xxx[3] = 0x22;		
//		buf0xxx[4] = 0x33;
//		buf0xxx[5] = 0x33;		
//		buf0xxx[6] = 0x44;		
//		buf0xxx[7] = 0x44;		
//		buf0xxx[8] = 0x55;		
//		buf0xxx[9] = 0x55;	
//		buf0xxx[10] = 0x66;			
//		buf0xxx[11] = 0x66;					
//		buf0xxx[12] = 0x77;							
//		buf0xxx[13] = 0x77;									
//		buf0xxx[14] = 0x88;											
//		buf0xxx[15] = 0x88;			
//		buf0xxx[16] = 0x99;					
//		buf0xxx[17] = 0x99;							
//		buf0xxx[18] = 0xaa;									
//		break;
//	case A_EE_MEM_TEST:
//		//PRINTLOG("\r\nTEST A_EE_MEM_TEST");
//		memset(buf0xxx,0xFF,TestSize);
//		TestSize = 64;
//		break;
//	case A_EE_MIDR:
//		//PRINTLOG("\r\nTEST A_EE_MIDR");
//		TestSize = 33;
//		buf0xxx[0] = 0x11;
//		buf0xxx[1] = 0x11;		
//		buf0xxx[2] = 0x22;		
//		buf0xxx[3] = 0x22;		
//		buf0xxx[4] = 0x33;
//		buf0xxx[5] = 0x33;		
//		buf0xxx[6] = 0x44;		
//		buf0xxx[7] = 0x44;		
//		buf0xxx[8] = 0x55;		
//		buf0xxx[9] = 0x55;	
//		buf0xxx[10] = 0x66;			
//		buf0xxx[11] = 0x66;					
//		buf0xxx[12] = 0x77;							
//		buf0xxx[13] = 0x77;									
//		buf0xxx[14] = 0x88;											
//		buf0xxx[15] = 0x88;			
//		buf0xxx[16] = 0x99;					
//		buf0xxx[17] = 0x99;							
//		buf0xxx[18] = 0xaa;				
//		buf0xxx[19] = 0xaa;				
//		buf0xxx[20] = 0xbb;			
//		buf0xxx[21] = 0xbb;					
//		buf0xxx[22] = 0xcc;							
//		buf0xxx[23] = 0xcc;									
//		buf0xxx[24] = 0xdd;											
//		buf0xxx[25] = 0xdd;			
//		buf0xxx[26] = 0xee;					
//		buf0xxx[27] = 0xee;							
//		buf0xxx[28] = 0xff;				
//		buf0xxx[29] = 0xff;				
//		buf0xxx[30] = 0xaa;					
//		buf0xxx[31] = 0xaa;							
//		buf0xxx[32] = 0x00;				
//
//
//		break;
//	default:
//		PRINTLOG("\r\n wrong config type ");
//		break;
//	}
//	START;
//	memset(tx_data,0,64);
//	memset(rx_data,0,64);	
//
//	tx_data[0] = 0x7;
//	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
//	SetAddrbyType(type,addr);
//	tx_data[0] = addr[1];// 0x00
//	tx_data[1] = addr[0];// 0xeb
//	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB      , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
//	tx_data[0] = 0;
//	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
//	delay_ms(1);
//
//	tspi_interface(cs, 0x30, addr      , NULL, NULL, NULL, NULL, buf0xxx, rx_data, 64);
//	PrintBuffer(TYPE_TX,buf0xxx,addr);
//	delay_ms(8);
//	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
//	PrintBuffer(TYPE_RX,rx_data,addr);
//	delay_us(10);
//	if(CompareType == 0 )
//	{
//		if(memcmp(buf0xxx,rx_data,TestSize) != 0 )
//		{
//			PRINTLOG("\r\n HIT to write miss on  cfg page with out permission");
//		}
//		else
//		{
//			PRINTLOG("\r\n  MISS to write miss on cfg page with out permission");
//			success = 0;
//		}
//		/*
//		if(memcmp(buf0xxx,rx_data,COMPARE_SIZE) == 0 )
//		{
//		PRINTLOG("\r\n 2. HIT to read buffer as 0x%02x",buf0xxx[0]);
//		}
//		else
//		{
//		PRINTLOG("\r\n 2. MISS to read buffer as 0x%02x",buf0xxx[0]);
//		}
//		*/
//	}
//	else
//	{
//		if(memcmp(buf0xxx,rx_data,TestSize) == 0 )
//		{
//			PRINTLOG("\r\n  HIT to write success on cfg page with  permission");
//		}
//		else
//		{
//			PRINTLOG("\r\n  MISS to write success on cfg page with  permission");
//			success = 0;
//		}
//	}
//	PrintPASSFAIL(success);
//}

int SetCFG_A_EE_CONFIG_USER(void)
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr[2];
	unsigned char buf0xxx[64];
	int TestSize =0 ;
	int success = 1;
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	printk("\r\n\r\n\r\n\r\n");
	printk("\r\nTEST EE_CONFIG_USER");
	START;
	// 0. Initialize CONFIG AREA as 0xcd
	memset(tx_data,0xab,64);
	SetAddrbyType(A_EE_CONFIG_USER,addr);
	eep_page_write(addr[0],addr[1],tx_data,1);// clear cfg area to check writing data

	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = addr[1];// 0x00
	tx_data[1] = addr[0];// 0xeb
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB      , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);

	delay_ms(1);
	memset(tx_data,0xFF,1);
	tspi_interface(cs, 0x30, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(0,tx_data,addr);
	delay_ms(8);
	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(1,rx_data,addr);
	endOP();
	delay_ms(1);

	if(rx_data[0] == 0xab)	
	{
		PRINTLOG("\r\n HIT to write miss on  cfg page with out permission");
	}
	else
	{
		PRINTLOG("\r\n  MISS to write miss on cfg page with out permission");
		success = 0;
	}

	//  2. read without permission
	memset(tx_data,0xab,64);
	tx_data[0] =0xcd;
	eep_page_write(addr[0], addr[1], tx_data,1);
	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	SetAddrbyType(A_EE_CONFIG_USER,addr);
	tx_data[0] = addr[1];// 0x00
	tx_data[1] = addr[0];// 0xeb
	//tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB      , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	//tx_data[0] = 0;
	//tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	//delay_ms(1);
	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(1,rx_data,addr);
	delay_ms(1);
	endOP();
	if(rx_data[0] == 0xcd )
	{
		PRINTLOG("\r\n  HIT to write success on cfg page with  permission");
	}
	else
	{
		PRINTLOG("\r\n  MISS to write success on cfg page with  permission");
		success = 0;
	}
	END;
	PrintPASSFAIL(success);
#endif
}
int SetCFG_NOPERM(int type)
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr[2];
	unsigned char buf0xxx[64];
	int TestSize =0 ;
	int success = 1;

	memset(tx_data,0xcd,64);
	memset(rx_data,0,64);	
	PRINTLOG("\r\n\r\n\r\n\r\n");
	switch(type)
	{
	case A_EE_CONFIG_NW:
		printk("\r\nTEST A_EE_CONFIG_NW");
		TestSize = 6;
		memset(buf0xxx,0x17,64);
		break;
	case A_EE_CONFIG_FAC:
		printk("\r\nTEST A_EE_CONFIG_FAC");
		TestSize = 10;		
		break;
	case A_EE_CONFIG_UID:
		TestSize = 11;
		printk("\r\nTEST A_EE_CONFIG_UID");
		break;
	case A_EE_SEED_KEY:
		printk("\r\nTEST A_EE_SEED_KEY");
		TestSize = 16;
		break;
	case A_EE_CONFIG_USER:
		printk("\r\nTEST A_EE_CONFIG_USER");
		TestSize = 1;
		break;
	case A_EE_CONFIG_LOCK:
		printk("\r\nTEST A_EE_CONFIG_LOCK");
		TestSize = 19;
		break;
	case A_EE_MEM_TEST:
		printk("\r\nTEST A_EE_MEM_TEST");
		TestSize = 64;
		break;
	case A_EE_MIDR:
		printk("\r\nTEST A_EE_MIDR");
		TestSize = 33;
		break;
	default:
		printk("\r\n wrong config type ");
		break;
	}
	START;
	SetAddrbyType(type,addr);
	eep_page_write(addr[0],addr[1],tx_data,1);// clear cfg area to check writing data
	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = addr[1];// 0x00
	tx_data[1] = addr[0];// 0xeb
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB      , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);
	memset(tx_data,0xFF,COMPARE_SIZE);
	tspi_interface(cs, 0x30, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(0,tx_data,addr);
	delay_ms(8);
	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(1,rx_data,addr);
	delay_us(10);
	if(memcmp(tx_data,rx_data,TestSize) == 0 )
	{
		PRINTLOG("\r\n  HIT to write miss on  cfg page with out permission");
	}
	else
	{
		PRINTLOG("\r\n  MISS to write miss on cfg page with out permission");
		success = 0;
	}
	endOP();

	if(CheckEEBUF() == 0)
		success = 0;
	endOP();
	END;
	PrintPASSFAIL(success);
#endif	
}
int CheckEEBUF(void)
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	int success =  1;
	int success_clear40 = 1;
	int success_clear03 = 1;	
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr[2];
	memset(tx_data,0,64);
	memset(rx_data,0,64);	
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	for(i = 0 ; i < 64; i++)
	{
		if(rx_data[i] != 0x40)
		{
			success = 0;
			success_clear40 = 0;
		}
	}
	if(success_clear40 == 1)
	{
		PRINTLOG("\r\n  HIT to clear RG_EEBUF as 0x40");
	}
	else
	{
		PRINTLOG("\r\n  MISS to clear RG_EEBUF");
	}

	tx_data[0] = 0x6;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	for(i = 0 ; i < 64; i++)
	{
		if(rx_data[i] != 0x03)
		{
			success = 0;
			success_clear03 = 0;

		}
	}
	if(success_clear03 == 1)
	{
		PRINTLOG("\r\n  HIT to clear RG_EEBUF as 0x03");
	}
	else
	{
		PRINTLOG("\r\n  MISS to clear RG_EEBUF as 0x03");
	}
	return success;
#endif	
}
int SetCFG(int type)
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	int success =  1;
	int success_clear40 = 1;
	int success_clear03 = 1;	
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr[2];
	int TestSize =0;
	memset(tx_data,0xFF,64);
	memset(rx_data,0,64);	
	PRINTLOG("\r\n\r\n\r\n\r\n");
	switch(type)
	{
	case A_EE_CONFIG_NW:
		printk("\r\nTEST A_EE_CONFIG_NW");
		TestSize = 6;

		break;
	case A_EE_CONFIG_FAC:
		printk("\r\nTEST A_EE_CONFIG_FAC");
		TestSize = 10;		
		break;
	case A_EE_CONFIG_UID:
		TestSize = 11;
		printk("\r\nTEST A_EE_CONFIG_UID");
		break;
	case A_EE_SEED_KEY:
		printk("\r\nTEST A_EE_SEED_KEY");
		TestSize = 32;
		break;
	case A_EE_CONFIG_USER:
		printk("\r\nTEST A_EE_CONFIG_USER");
		TestSize = 1;
		break;
	case A_EE_CONFIG_LOCK:
		printk("\r\nTEST A_EE_CONFIG_LOCK");
		TestSize = 19;
		break;
	case A_EE_MEM_TEST:
		printk("\r\nTEST A_EE_MEM_TEST");
		TestSize = 64;
		break;
	case A_EE_MIDR:
		printk("\r\nTEST A_EE_MIDR");
		TestSize = 33;
		break;
	default:
		printk("\r\n wrong config type ");
		break;
	}
	START;
	SetAddrbyType(type,addr);
	//	eep_page_read(addr[0],addr[1],0);
	eep_page_write(addr[0],addr[1],tx_data,1);// clear cfg area to check writing data
	if(WriteAndReadConfigArea(type,0) == 0 )
		success = 0;
	Delay_us(10);
	endOP();
	if(type == A_EE_CONFIG_UID ||type ==A_EE_SEED_KEY || type == A_EE_CONFIG_LOCK || type == A_EE_MIDR)
	{
		GetPermissionByPW(UID_PW_CT,RG_PERM_UID_PASS);
	}
	else
	{
		GetPermissionByPW(SUPER_PW_CT,RG_PERM_SUPER_PASS);
	}
	if(WriteAndReadConfigArea(type,1) == 0)
		success = 0;
	Delay_us(10);
	endOP();
	if(CheckEEBUF() == 0)
		success = 0;
	Delay_us(10);
	endOP();
	ReleasePermision();
	END;
	PrintPASSFAIL(success);
	return success;
#endif	
}
unsigned int IterMemBKUP = 1;
int WR_IterMemBKUP()
{
#ifdef COMPARE

	int i;
	int j;
	unsigned int inst = 0;
	int success =  1;

	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char addr[2];
	//SetKEYNormal();

	memset(tx_data,0,64);
	memset(rx_data,0,64);	
	eep_page_write(A_EE_MEM_BKUP_RSFLAG[0],A_EE_MEM_BKUP_RSFLAG[1],tx_data,1);

	printk("\r\n BEFORE SAVE_KEY_REVERSE");
	SAVE_KEY_REVERSE(RG_PERM_UID_PASS);	
	printk("\r\n AFTER SAVE_KEY_REVERSE");
	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	PRINTLOG("\r\n WRITE AND READ A_EE_MEM_BKUP_RSFLAG WITHOUT PERMISSION");
	memset(tx_data,0xAA,64);
	PrintBuffer(TYPE_TX, tx_data, A_EE_MEM_BKUP_RSFLAG);
	tspi_interface(cs, 0x30, A_EE_MEM_BKUP_RSFLAG      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	tspi_interface(cs, 0x20, A_EE_MEM_BKUP_RSFLAG      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	delay_us(10);
	PrintBuffer(TYPE_RX, rx_data, A_EE_MEM_BKUP_RSFLAG);
	endOP();
	GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
	tx_data[0] = 0x7;
	PRINTLOG("\r\n ENTER WR_IterMemBKUP");
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] =A_EE_MEM_BKUP_RSFLAG[1];
	tx_data[1] =A_EE_MEM_BKUP_RSFLAG[0];
	tspi_interface(cs, ADDR_NOR_W, RG_EET_BYOB_ADDR_LSB      , NULL, NULL, NULL, NULL, tx_data, rx_data, 2);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_EE_CFG_RD_RG_EEBUF_ST      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	delay_ms(1);
	memset(tx_data,0xAA,64);
	PrintBuffer(TYPE_TX, tx_data, A_EE_MEM_BKUP_RSFLAG);
	tspi_interface(cs, 0x30, A_EE_MEM_BKUP_RSFLAG      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	delay_ms(8);
	tspi_interface(cs, 0x20, A_EE_MEM_BKUP_RSFLAG      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	delay_us(10);
	PrintBuffer(TYPE_RX, rx_data, A_EE_MEM_BKUP_RSFLAG);
	PRINTLOG("\r\n TEST EE_MEM_BKUP_RSFLAG");
	if(rx_data[1] == 0xAA)
		PrintPASSFAIL(1);
	else
		PrintPASSFAIL(0);
	endOP();
	ReleasePermision();
	return success;
#endif
}
void PrintHITMISS(int success)
{
	if(success)
		printk("HIT");
	else
		printk("MISS");
}
void PrintPASSFAIL(int success)
{
	printk("\r\n ***********************************************");
	if(success)
		printk("\r\nTEST PASS");
	else
		printk("\r\nTEST FAIL");
}

void BackUPRSFLAG(int TYPE, int EE_MEM_BKUP_NOTUSE_f, int EE_MEM_BKUP_RSFLAG_f)
{
#ifdef COMPARE

	unsigned char msb = 0;
	unsigned char lsb = 0;
	int BackupCnt = 0;
	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char BKUP_ADDR = 0;;
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	if(TYPE == BKUP_EE_SUPER_PASS )
	{
		msb = ADDR_SUPER_PW[0];
		lsb = ADDR_SUPER_PW[1];
		BKUP_ADDR = 0x10;
		for(i = 0; i < 64; i++)
			tx_data[i] = i;


	}
	if(TYPE == BKUP_EE_DETOUR_PASS )
	{
		msb = ADDR_DETOUR_PW[0];
		lsb = ADDR_DETOUR_PW[1];
		BKUP_ADDR = 0x11;		
		j = 1;
		for( i = 0 ; i < 64; i++)
			tx_data[i] = j++;

	}
	if(TYPE == BKUP_EE_DESTORY0_PASS )
	{
		msb = ADDR_DESTORY0_PW[0];
		lsb = ADDR_DESTORY0_PW[1];
		BKUP_ADDR = 0x12;				
		j = 2;
		for( i = 0 ; i < 64; i++)
			tx_data[i] = j++;
	}
	if(TYPE == BKUP_EE_DESTORY1_PASS )
	{
		msb = ADDR_DESTORY1_PW[0];
		lsb = ADDR_DESTORY1_PW[1];
		BKUP_ADDR = 0x13;			
		j = 3;
		for( i = 0 ; i < 64; i++)
			tx_data[i] = j++;

	}
	if(TYPE == BKUP_EE_EEPROM_PASS )
	{
		msb = ADDR_EEPROM_PW[0];
		lsb = ADDR_EEPROM_PW[1];
		BKUP_ADDR = 0x14;			
		j = 4;
		for( i = 0 ; i < 64; i++)
			tx_data[i] = j++;

	}
	if(TYPE == BKUP_EE_UID_PASS )
	{
		msb = ADDR_UID_PW[0];
		lsb = ADDR_UID_PW[1];

		BKUP_ADDR = 0x15;				
		j = 5;
		for( i = 0 ; i < 64; i++)
			tx_data[i] = j++;
	}

	if(TYPE == BKUP_EE_SUPER_PASS_CNT )
	{
		msb = ADDR_SUPER_PW_CNT_PAGE[0];
		lsb = ADDR_SUPER_PW_CNT_PAGE[1];
		j = 6;
		for( i = 0 ; i < 64; i++)
			tx_data[i] = j++;
		BKUP_ADDR = 0x18;		
	}
	if(TYPE == BKUP_EE_DETOUR_PASS_CNT )
	{
		msb = ADDR_DETOUR_PW_CNT_PAGE[0];
		lsb = ADDR_DETOUR_PW_CNT_PAGE[1];
		j = 7;
		for( i = 0 ; i < 64; i++)
			tx_data[i] = j++;

		BKUP_ADDR = 0x19;			
	}
	if(TYPE == BKUP_EE_DESTORY0_PASS_CNT )
	{
		msb = ADDR_DESTORY0_PW_CNT_PAGE[0];
		lsb = ADDR_DESTORY0_PW_CNT_PAGE[1];
		j = 8;
		for( i = 0 ; i < 64; i++)
			tx_data[i] = j++;

		BKUP_ADDR = 0x1a;		
	}
	if(TYPE == BKUP_EE_DESTORY1_PASS_CNT )
	{
		msb = ADDR_DESTORY1_PW_CNT_PAGE[0];
		lsb = ADDR_DESTORY1_PW_CNT_PAGE[1];
		j = 9;
		for( i = 0 ; i < 64; i++)
			tx_data[i] = j++;

		BKUP_ADDR = 0x1b;			
	}
	if(TYPE == BKUP_EE_EEPROM_PASS_CNT )
	{
		msb = ADDR_EEPROM_PW_CNT_PAGE[0];
		lsb = ADDR_EEPROM_PW_CNT_PAGE[1];
		j = 10;
		for( i = 0 ; i < 64; i++)
			tx_data[i] = j++;
		BKUP_ADDR = 0x1c;		
	}
	if(TYPE == BKUP_EE_UID_PASS_CNT )
	{
		msb = ADDR_UID_PW_CNT_PAGE[0];
		lsb = ADDR_UID_PW_CNT_PAGE[1];
		BKUP_ADDR = 0x1d;		
		j = 11;
		for( i = 0 ; i < 64; i++)
			tx_data[i] = j++;
	}
	success = eep_page_write(msb,lsb,rx_data,1);// initailize area to be backuped  as 0 
	PRINTLOG("\r\n 1. initailize area to be backuped  as 0 ");
	PrintHITMISS(success);	
	success = eep_page_write(ADDR_EE_MEM_BKUP[0],ADDR_EE_MEM_BKUP[1],tx_data,1);// initailize backup area as 0xXX	
	PRINTLOG("\r\n 2. initailize backup area as 0xXX	");
	PrintHITMISS(success);	   
	memset(tx_data,0,64);
	tx_data[0] = BKUP_ADDR | ( EE_MEM_BKUP_RSFLAG_f<<7);
	tx_data[1] = EE_MEM_BKUP_NOTUSE_f ;		
	success = eep_page_write(EE_MEM_BKUP_RSFLAG[0],EE_MEM_BKUP_RSFLAG[1],tx_data,1);
	PRINTLOG("\r\n 3. Set 	EE_MEM_BKUP_RSFLAG:%d EE_MEM_BKUP_NOTUSE:%d  ",EE_MEM_BKUP_RSFLAG_f,EE_MEM_BKUP_NOTUSE_f);	
	PrintHITMISS(success);	   
#endif

}

int GetFlag(int type)
{	
	int flag = 0;
	if(type == F_EE_MEM_BKUP_RSFLAG)
	{
		PRINTLOG("\r\n input EE_MEM_BKUP_RSFLAG (2digit)");	
	}
	else
	{
		PRINTLOG("\r\n input  EE_MEM_BKUP_NOTUSE (2digit)");
	}
	PRINTLOG("   :0x");
	flag = get_int();
	return flag;

}
void EE_MEM_BKUP_RSFLAG_MENU(void)
{
#ifdef COMPARE

	int i;
	unsigned int inst = 0;
	int pass = 1;
	int j = 0;
	int EE_MEM_BKUP_RSFLAG_f = 0;
	int EE_MEM_BKUP_NOTUSE_f = 0;	
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char temp ;
	int iResult = 0;
	unsigned char MIDRCNT0[8];
	unsigned char MIDRCNT1[8];
	unsigned char MIDR_INDEX0;
L_MIDR_START:
	while(1)
	{
		printk("\r\n  *****************************************************");
		printk("\r\n  *            EE_MEM_BKUP_RSFLAG     TEST MAIN                                                  *");
		printk("\r\n  *****************************************************");
		printk("\r\n  *  i.NUMBER OF ITERANTION %d",IterMemBKUP);
		printk("\r\n  * 0. WRTIE AND READ  EE_MEM_BKUP_RSFLAG PAGE");
		printk("\r\n  * 1. back up EE_SUPER_PW");
		printk("\r\n  * 2. back up EE_DETOUR_PW");
		printk("\r\n  * 3. back up EE_DESTORY0_PW");
		printk("\r\n  * 4. back up EE_DESTORY1_PW");
		printk("\r\n  * 5. back up EE_EEPROM_PW");
		printk("\r\n  * 6. back up EE_UID_PW");
		printk("\r\n  * 7. back up EE_SUPER_PW_CNT");
		printk("\r\n  * 8. back up EE_DETOUR_PW_CNT");
		printk("\r\n  * 9. back up EE_DESTORY0_PW_CNT");
		printk("\r\n  * a. back up EE_DESTORY1_PW_CNT");
		printk("\r\n  * b. back up EE_EEPROM_PW_CNT");
		printk("\r\n  * c. back up BKUP_EE_UID_PASS_CNT");		
		printk("\r\n  * m. return to top menu");
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n");

		PRINTLOG("\r\n");
		PRINTLOG("\r\n  * Select : ");

		while(1)
		{
			temp = _uart_get_char();

			if ( temp != 'z' ) PRINTLOG("%c\n", temp);
			PRINTLOG("\r\n");

			if(temp == 0x0d)
				goto L_MIDR_START;
			if(temp == 'm')
			{
				PRINTLOG("\r\nm is pressed");
				return;
			}
			if(temp != '0' )
			{
				EE_MEM_BKUP_NOTUSE_f = GetFlag(F_EE_MEM_BKUP_NOTUSE);
				EE_MEM_BKUP_RSFLAG_f = GetFlag(F_EE_MEM_BKUP_RSFLAG);

			}


			switch ( temp )
			{
			case 'i' : 
				PRINTLOG("\r\n input number of iteration : (4digit)");
				PRINTLOG("\r\n 0x");
				IterMemBKUP = get_int();
				IterMemBKUP =( IterMemBKUP<<8)| get_int();		 
				break;

			case '0' : 
				WR_IterMemBKUP();
				goto L_MIDR_START;
				break;
			case 'm':
				return;
				break;
			case '1' :
				BackUPRSFLAG(BKUP_EE_SUPER_PASS,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 
			case '2' :
				BackUPRSFLAG(BKUP_EE_DETOUR_PASS,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 				
			case '3' :
				BackUPRSFLAG(BKUP_EE_DESTORY0_PASS,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 
			case '4' :
				BackUPRSFLAG(BKUP_EE_DESTORY1_PASS,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 
			case '5' :
				BackUPRSFLAG(BKUP_EE_EEPROM_PASS,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 
			case '6' :
				BackUPRSFLAG(BKUP_EE_UID_PASS,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 
			case '7' :
				BackUPRSFLAG(BKUP_EE_SUPER_PASS_CNT,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 
			case '8' :
				BackUPRSFLAG(BKUP_EE_DETOUR_PASS_CNT,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 
			case '9' :
				BackUPRSFLAG(BKUP_EE_DESTORY0_PASS_CNT,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 
			case 'a' :
				BackUPRSFLAG(BKUP_EE_DESTORY1_PASS_CNT,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 
			case 'b' :
				BackUPRSFLAG(BKUP_EE_EEPROM_PASS_CNT,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 
			case 'c' :
				BackUPRSFLAG(BKUP_EE_UID_PASS_CNT,EE_MEM_BKUP_NOTUSE_f,EE_MEM_BKUP_RSFLAG_f);
				goto L_MIDR_START;
				break; 				

			default :
				goto L_MIDR_START;	
				break;
			}

		}
	}

#endif
}
int NumOfIterCFG = 1;
void EE_CFG_MENU()
{
#ifdef COMPARE

	int i;
	int HitCnt,MissCnt;
	unsigned char temp;
	int lSuccess = 1;
	while(1)
	{
		printk("\r\n\n");
L_Start_block:
		printk("\r\n  **************************************************");
		printk("\r\n  *                 EE_CFG_MENU                    *");
		printk("\r\n  **************************************************");
		printk("\r\n  * number of iteration     %d                     *",NumOfIterCFG );	
		printk("\r\n  * 1. EE_CONFIG_NW                                *");
		printk("\r\n  * 2. A_EE_CONFIG_FAC                             *");
		printk("\r\n  * 3. A_EE_CONFIG_UID                             *");
		printk("\r\n  * 4. A_EE_SEED_KEY                               *");
		printk("\r\n  * 5. EE_CONFIG_USER                              *");
		printk("\r\n  * 6. A_EE_CONFIG_LOCK                            *");
		printk("\r\n  * 7. A_EE_MEM_TEST                               *");
		printk("\r\n  * 8. A_EE_MIDR                                   *");
		printk("\r\n  * 9. TEST ALL                                    *");
		printk("\r\n  * m. return top menu                             *");

		printk("\r\n");

		printk("\r\n");
		printk("\r\n  * Select : ");

		/*
		A_EE_CONFIG_NW =0,
		A_EE_CONFIG_FAC,
		A_EE_CONFIG_UID,
		A_EE_SEED_KEY,
		A_EE_CONFIG_USER,
		A_EE_CONFIG_LOCK,
		A_EE_MEM_TEST,
		A_EE_MIDR
		*/

		//while (1)
		{
			temp = _uart_get_char() ;
			if(temp == 0x0d)
				goto L_Start_block;
			if ( temp != 'z' ) printk("%c", temp);
			MissCnt = 0;
			HitCnt = 0;
			switch ( temp )
			{
			
			case 'i' : 
				printk("\r\n input number of iteration : (4digit)");
				printk("\r\n 0x");
				NumOfIterCFG = get_int();
				NumOfIterCFG =( NumOfIterCFG<<8)| get_int();		 
				break;


			case '1':
				for(i = 0; i < NumOfIterCFG; i++)
					if(SetCFG(A_EE_CONFIG_NW) == 0)
						lSuccess = 0;
				break;
			case '9' : 
				for(i = 0; i < NumOfIterCFG; i++)
				{

					if(SetCFG(A_EE_CONFIG_NW) == 0)
						lSuccess = 0;
					if(SetCFG(A_EE_CONFIG_FAC) == 0)
						lSuccess = 0;
					if(SetCFG(A_EE_CONFIG_UID) == 0)
						lSuccess = 0;
					if(SetCFG(A_EE_SEED_KEY) == 0)
						lSuccess = 0;
					if(SetCFG_CONFIG_LOCK() == 0)
						lSuccess = 0;
					if(SetCFG_NOPERM(A_EE_MEM_TEST) == 0)
						lSuccess = 0;
					if(SetCFG(A_EE_MIDR) == 0)
						lSuccess = 0;
					//				SetCFG_NOPERM(A_EE_CONFIG_USER);			//TV070005 to ask why it add A_EE_CONFIG_USER to h3f
					if(SetCFG_A_EE_CONFIG_USER() == 0)
						lSuccess = 0;

					if(lSuccess == 1)
						HitCnt++;
					else
						MissCnt++;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterCFG);
				break;				
			case 'm':
				return;				
			default:
				break;
			}


		}
	}
	#endif
}
void MCU_SHA256_EXE(unsigned char *txdata, unsigned char *exdata, unsigned int ByteNo)
{

	int i = 0;
	shs256_init_mcu_frm();

	//printk("\r\n sha_in :"); for ( i=0; i<64; i++ ) { if ( i%32 == 0 ) printk("\r\n      "); printk(" %02X", txdata[i]); }
	for (i=0;i<ByteNo;i++) shs256_process_mcu_frm( txdata[i]);

	shs256_hash_mcu_frm( exdata);  


}


int SHAAUTH_FROM_MCU()
{
#ifdef COMPARE

	unsigned char GID[4] = {0x01,0x02,0x03,0x04};
	unsigned char AuthText[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	unsigned char GID_EEPROM_DATA[64];
	unsigned char SHA1_INPUT[20];
	unsigned char SHA1_OUT[32];

	unsigned char AuthMsgMCU[32];

	unsigned char Input[3] = {'a','b','c'};	
	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char BKUP_ADDR = 0;
	int iResult = 0;
	unsigned char addr[2] = {0xeb,0x40} ;
	
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	GetPermissionByPW(SUPER_PW_CT,RG_PERM_SUPER_PASS);
	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(TYPE_RX,rx_data,addr);
	delay_us(10);
	ReleasePermision();


	//
	/*
	for(i = 0; i <= 63; i++)
	{
	GID_EEPROM_DATA[i] = i + 1;
	}
	GID_EEPROM_DATA[0] = 4;
	GID_EEPROM_DATA[1] = 3;
	GID_EEPROM_DATA[2] = 2;
	GID_EEPROM_DATA[3] = 1;
	*/
	//eep_page_read(0xEB,0x40,0,GID_EEPROM_DATA);
	GID[0] = rx_data[3];//GID_EEPROM_DATA[3];
	GID[1] = rx_data[2];//GID_EEPROM_DATA[2];
	GID[2] = rx_data[1];//GID_EEPROM_DATA[1];
	GID[3] = rx_data[0];//GID_EEPROM_DATA[0];	


//	eep_page_write(0xEB,0x40,GID_EEPROM_DATA,1);
	memcpy(SHA1_INPUT,GID,4);
	memcpy(&SHA1_INPUT[4],AuthText,16);	

	//GetSuperWirePermission()	;

	MCU_SHA256_EXE(SHA1_INPUT,SHA1_OUT,20);
	printk("\r\n SHA1_OUT \r\n");
	printbyte(SHA1_OUT,32);
	//printk("SHA RESULT");
	//printbyte(SHA1_OUT,32);

	MCU_SHA256_EXE(SHA1_OUT,AuthMsgMCU,256/8);
	tx_data[0] = 0x09;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE       , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W, RG_SHAAUTH_CTRL       , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x0a;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

#if 1

#if 0
	printk("\r\n start from index 0\r\n");
	j = 15;
	for(i = 0; i < 16; i++)
	{
		tx_data[i] = AuthText[j--];
	}
	j = 31;
	for(i = 16; i < 48; i++)
	{
		tx_data[i] = AuthMsgMCU[j--];
	}
	printk("\r\n AuthMsgMCU \r\n");
	printbyte(AuthMsgMCU,32);
	printk("\r\n TX DATA \r\n");

	printbyte(tx_data,16);
	printbyte(tx_data+16,16);
	printbyte(tx_data+16+16,16);
	printbyte(tx_data+16+16+16,16);
#endif
	printk("\r\n start from index 0\r\n");
	j = 15;
	for(i = 16; i < 32; i++)
	{
		tx_data[i] = AuthText[j--];
	}
	j = 31;
	for(i = 32; i < 64; i++)
	{
		tx_data[i] = AuthMsgMCU[j--];
	}

	//j = 15;
	//for(i = 16; i < 32; i++)
	//{
	//	tx_data[i] = AuthText[j--];
	//}
	//j = 31;
	//for(i = 32; i < 64; i++)
	//{
	//	tx_data[i] = AuthMsgMCU[j--];
	//}
	//printk("\r\n AuthMsgMCU \r\n");
	//printbyte(AuthMsgMCU,32);
#else
	j = 0;
	for(i = 16; i < 32; i++)
	{
		tx_data[i] = AuthText[j++];
	}
	j = 0;
	for(i = 32; i < 64; i++)
	{
		tx_data[i] = AuthMsgMCU[j++];
	}

	printk("\r\n TX DATA \r\n");

	printbyte(tx_data,16);
	printbyte(tx_data+16,16);
	printbyte(tx_data+16+16,16);
	printbyte(tx_data+16+16+16,16);
#endif
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF100      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_R, RG_ACCESS        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(50);
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF100      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	printk("\r\n RG_EEBUF100\r\n");
	printbyte(rx_data,64);

	tspi_interface(cs, ADDR_NOR_R,RG_MCUAuthResult        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(rx_data[0] == 0 )
	{
		printk("\r\n SHA AUTH FAIL");
		success = 0;
	}
	else
	{
		printk("\r\n SHA AUTH PASS");

	}
#if 0
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_SHAAuth_CMP_DP         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tspi_interface(cs, ADDR_NOR_R,RG_MCUAuthResult        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(rx_data[0] == 0 )
	{
		printk("\r\n SHA AUTH FAIL");
		success = 0;
	}
	else
	{
		printk("\r\n SHA AUTH PASS");	

	}
#endif
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	return success;
#endif
}


int SHAAUTH_FROM_DORCA()
{
#ifdef COMPARE
	unsigned char GID[4];
	unsigned char AuthRand[16];
	unsigned char GID_EEPROM_DATA[64];
	unsigned char SHA1_INPUT[20];
	unsigned char SHA1_OUT[32];
	unsigned char AuthMsgDevice[32];
	unsigned char AuthMsgMCU[32];
	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char BKUP_ADDR = 0;
	int iResult = 0;
	unsigned char addr[2] = {0xeb,0x40} ;
	GetPermissionByPW(SUPER_PW_CT,RG_PERM_SUPER_PASS);
	tx_data[0] = 0x7;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tspi_interface(cs, 0x20, addr      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	PrintBuffer(TYPE_RX,rx_data,addr);
	delay_us(10);
	ReleasePermision();


	//temporalry code to confirm writing spi2
	/*tspi_interface(cs, ADDR_NOR_R, RG_EETEST_BYOB_ADDR_LSB        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	return;*/
	//
	/*
	for(i = 0; i <= 63; i++)
	{
	GID_EEPROM_DATA[i] = i + 1;
	}
	GID_EEPROM_DATA[0] = 4;
	GID_EEPROM_DATA[1] = 3;
	GID_EEPROM_DATA[2] = 2;
	GID_EEPROM_DATA[3] = 1;
	*/
	//eep_page_read(0xEB,0x40,0,GID_EEPROM_DATA);
	GID[0] = rx_data[3];//GID_EEPROM_DATA[3];
	GID[1] = rx_data[2];//GID_EEPROM_DATA[2];
	GID[2] = rx_data[1];//GID_EEPROM_DATA[1];
	GID[3] = rx_data[0];//GID_EEPROM_DATA[0];	

	tx_data[0] = 0x09;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE       , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x0a;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_SHAAUTH_CTRL        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	tx_data[0] = 0x04;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_RND_OPMODE        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R, RG_ACCESS        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(50);


	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
	printk("\r\n RG_EEBUF300\r\n");
	printbyte(rx_data,64);
#if 1		
	j = 31;
	for(i = 0; i < 32;i++)
		AuthMsgDevice[i] = rx_data[j--];
	j = 47;
	for(i = 0; i < 16;i++)
		AuthRand[i] = rx_data[j--];
#else

#endif
	for( i = 0; i < 4 ; i++)
		SHA1_INPUT[i] = GID[i];
	j = 0;
	for( i = 4; i < 20 ; i++)
		SHA1_INPUT[i] = AuthRand[j++];	
	printk("\r\n FIXED VER");
	MCU_SHA256_EXE(SHA1_INPUT,SHA1_OUT,20);

	MCU_SHA256_EXE(SHA1_OUT,AuthMsgMCU,256/8);

	if( memcmp(AuthMsgDevice,AuthMsgMCU,256/8) == 0)
		printk("\r\n SHA_AUTH PASS");
	else
	{
		printk("\r\n SHA_AUTH FAIL");
		success = 0;
	}
	printk("\r\n AuthMsgDevice\r\n");
	printbyte(AuthMsgDevice,32);
	printk("\r\n AuthMsgMCU\r\n");
	printbyte(AuthMsgMCU,32);	
	printk("\r\n AuthRand\r\n");
	printbyte(AuthRand,16);	

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_RND_OPMODE        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W, RG_SHAAUTH_CTRL        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W, RG_ACCESS        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	return success;
#endif
}

void SHAAUTH_Menu()
{
#ifdef COMPARE

	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	int HitCnt,MissCnt;
	while(1)
	{
		temp = 'z' ;
		printk("\r\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  *            RG_SLEEP_TIMER  TEST MAIN                                  *");
		printk("\r\n  *****************************************************");
		printk("\r\n  * number of iteration 	%d						  *",NumOfIterSHA );		
		printk("\r\n  * i. Input number of iteration					  *");		
		printk("\r\n  * 1. SHAAUTH_FROM_MCU                                                    *");	
		printk("\r\n  * 2. SHAAUTH_FROM_DORCA                                                            *");
		printk("\r\n  * m. return to top menu                                                         *");	
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n");

		printk("\r\n");
		printk("\r\n  * Select : ");
		while(temp == 'z')
		{
			HitCnt = 0;
			MissCnt = 0;
			temp = _uart_get_char();

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");

			if(temp == 'm')
			{
				printk("\r\nm is pressed");
				return;
			}

			switch ( temp )
			{
			case 'i' : 
				printk("\r\n input number of iteration : (4digit)");
				printk("\r\n 0x");
				NumOfIterSHA = get_int();
				NumOfIterSHA =( NumOfIterSHA<<8)| get_int();		 
				break;

			case '1' : 
				for(i = 0; i < NumOfIterSHA;i++)
				{
					//	iResult = OKA_Test();
					START;
					iResult = SHAAUTH_FROM_MCU();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,HitCnt + MissCnt );
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;

				}
				PrintCnt(HitCnt,MissCnt,HitCnt + MissCnt );				
				break ;

			case '2' :
				for(i = 0; i < NumOfIterSHA;i++)
				{
					//	iResult = OKA_Test();
					START;
					iResult = SHAAUTH_FROM_DORCA();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,HitCnt + MissCnt );
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;

				}			
				PrintCnt(HitCnt,MissCnt,HitCnt + MissCnt );				
				break ;

			default : temp = 'z'; break;
			}
		}
	}
#endif
}


int RSCreate34(void)
{
#ifdef COMPARE

	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int iResult = 0;
	unsigned char PT_SHA256_1FRM_ANS[32];
	unsigned char PT_SHA256_2FRM_ANS[32];
	unsigned char RSx2[64];
	unsigned char RSx3[64];
	unsigned char temp[32];
	for( i = 0; i < 32; i++)
		PT_SHA256_1FRM_ANS[i] = rand() & 0xFF;
	for( i = 0; i < 32; i++)
		PT_SHA256_2FRM_ANS[i] = rand() & 0xFF;
	/// set to RSCREATE_WR_EEP state for RS_x2
	tx_data[0] = 0x09;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x07;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	//set to RSCreate
	tx_data[0] = 0x08;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x07;
	tspi_interface(cs, ADDR_NOR_W,RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 31;
	for( i = 0;i < 32; i++)
	{
		tx_data[i] = PT_SHA256_1FRM_ANS[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF500         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	tx_data[0] = 0x20;
	tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x04;
	tspi_interface(cs, ADDR_NOR_W,RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(8);
	//Write time to EEPROM
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	/// set to RSCREATE_WR_EEP state for RS_x3

	tx_data[0] = 0x07;
	tspi_interface(cs, ADDR_NOR_W,RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 31;
	for( i = 0;i < 32; i++)
	{
		tx_data[i] = PT_SHA256_2FRM_ANS[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF500         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	tx_data[0] = 0x30;
	tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x04;
	tspi_interface(cs, ADDR_NOR_W,RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(8);
	//Write time to EEPROM
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
	Delay_us(50);
	eep_page_read(0xea,0x80,0,RSx2);
	eep_page_read(0xea,0xC0,0,RSx3);
	j = 31;
	for(i = 0 ; i < 32; i++)
	{
		temp[i] = RSx2[j--];
	}
	if( memcmp(temp,PT_SHA256_1FRM_ANS,32) == 0)
		printk("\r\n RSx2 PASS");
	else
	{
		printk("\r\n RSx2 FAIL");
		printk("\r\n RSx2\r\n");
		printbyte(temp,32);
		printk("\r\n PT_SHA256_1FRM_ANS\r\n");
		printbyte(PT_SHA256_1FRM_ANS,32);
		success = 0;
	}

	j = 31;
	for(i = 0 ; i < 32; i++)
	{
		temp[i] = RSx3[j--];
	}
	if( memcmp(temp,PT_SHA256_2FRM_ANS,32) == 0)
		printk("\r\n RSx3 PASS");
	else
	{
		printk("\r\n RSx3 FAIL");
		printk("\r\n RSx3\r\n");
		printbyte(temp,32);
		printk("\r\n PT_SHA256_2FRM_ANS\r\n");
		printbyte(PT_SHA256_2FRM_ANS,32);
		success = 0;
	}
#endif
}
int IsRsCorrect(unsigned char *Rand1,unsigned char *RS_Input,int RSNum)
{
#ifdef COMPARE

	unsigned char KEY[32];
	unsigned char Data[16];
	unsigned char Data1[16];
	unsigned char RS[32];
	unsigned int success = 1;
	AES_KEY aes256_ekey,aes256_dkey;
	memcpy(KEY,Rand1,32);
	memcpy(Data,Rand1,16);
	memcpy(Data1,Rand1+16,16);
	AES_set_encrypt_key(KEY, 256, &aes256_ekey);
	AES_set_decrypt_key(KEY, 256, &aes256_dkey);

	//printk("\r\n index %d",index);
	//printk("\r\n data \r\n");
	//printbyte(Data,16);
	AES_ecb_encrypt(Data, RS, &aes256_ekey, AES_ENCRYPT);
	AES_ecb_encrypt(Data1, RS+16, &aes256_ekey, AES_ENCRYPT);
	if(memcmp(RS,RS_Input,32) != 0)
	{
		printk("\r\n RS%d confirm FAIL",RSNum);
		printk("\r\n RS%d \r\n",RSNum);
		printbyte(RS,32);
		success = 0;
		printk("\r\n RS%d_Input \r\n",RSNum);
		printbyte(RS_Input,32);
	}
	else
	{
		printk("\r\n RS%d is correct",RSNum);
	}
	return success;
#endif
}
#if 0
void RSDirectReadData(unsigned char *RS[4])
{
	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int k = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	
	tx_data[0] = 0x09;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	for(i = 0; i < 4; i++)
	{
		tx_data[0] = 0x00 + (i << 4);
		tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x09;
		tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		memset(tx_data,0,32);
		memcpy(RS[i],rx_data,32);
		printk("\r\n RSx%d",i);
		printbyte(rx_data,16);
		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);		
	}
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	endOP();

}
#endif
void RSDirectReadData(unsigned char *RS[4])
{
#ifdef COMPARE

	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int k = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	for(i = 0; i < 4; i++)
	{	
	tx_data[0] = 0x09;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


		tx_data[0] = 0x00 + (i << 4);
		tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x09;
		tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		memset(tx_data,0,32);
		memcpy(RS[i],rx_data,32);
		printk("\r\n RSx%d",i);
		printbyte(rx_data,16);
		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);		
	
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	endOP();
	}
#endif
}

int RSDirectRead(void)
{
#ifdef COMPARE

	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int k = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char RS[4][64];
	unsigned char RS2[4][64];
	unsigned char *pRS[4];
	//	SetKEYNormal();
	tspi_interface(cs, ADDR_NOR_R, RG_PERM_GET_CTRL1 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		
	printk("\r\n GetPermResult 0x%02x",rx_data[0]);

	for( i= 0; i < 4; i++)
	{
		eep_page_read(0xea,i *0x40,0,&RS[i][0]);
		pRS[i] = &RS2[i][0];
	}
	//Reset RGE BUFFER
	eep_page_read(0xe8, 0x40,0,tx_data);
	Aes256 = 1;
	Aes128 = 0;
	DummyAES();
	//SetKEYNormal();
	//with out permssion, try to read RS
	printk("\r\n PHASE 1, with out permission");
	RSDirectReadData(pRS);
	for( i = 0; i < 4; i++)
	{
		if(memcmp(pRS[i], &RS[i][0] ,32) == 0)
		{
			printk("\r\n RSDirectRead FAIL, value was read");
			printk("\r\n pRS[%d]\r\n",i);
			printbyte(pRS[i],32);

			printk("\r\n &RS[%d][0]\r\n",i);
			printbyte(&RS[i][0],32);

			success = 0;
		}
	}
	GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
	RSDirectReadData(pRS);
	printk("\r\n PHASE 2, with permission");
	for( i = 0; i < 4; i++)
	{
		if( i == 1 || i == 3 )
		{
			if(memcmp(pRS[i], &RS[i][0] ,32) != 0)
			{
				printk("\r\n RSDirectRead FAIL, RS1,RS3 value were not read");
				printk("\r\n pRS[%d]\r\n",i);
				printbyte(pRS[i],32);

				printk("\r\n &RS[%d][0]\r\n",i);
				printbyte(&RS[i][0],32);
				success = 0;
			}
		}
		else
		{
			if(memcmp(pRS[i], &RS[i][0] ,32) == 0)
			{
				printk("\r\n RSDirectRead FAIL, RS2,RS4  value were  read");
				printk("\r\n pRS[%d]\r\n",i);
				printbyte(pRS[i],32);

				printk("\r\n &RS[%d][0]\r\n",i);
				printbyte(&RS[i][0],32);
				success = 0;
			}

		}
	}
	memset(RS,0,sizeof(RS));
	ReleasePermision();
	eep_page_read(0xe8, 0x40,0,tx_data);

	memset(tx_data,0,64);
	if(success)
		printk("\r\n TEST PASS");
	else
		printk("\r\n TEST FAIL");
	return success;
#endif
	// wo uid permission
}
int RSSHARead(void)
{
#ifdef COMPARE

	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int k = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char RS_RD_RND[4];
	unsigned char RS_RND_DATA[4];
	unsigned char Dummy_15BYTE[15];
	unsigned char Trail;
	unsigned char LEN[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xB8};
	unsigned char RS[32];
	unsigned char INPUT_SHA[55];
	unsigned char SHA_OUT[32];
	unsigned char DORCA_SHA_OUT[32];

	//  to be removed
	memset(RS_RD_RND,0,4);
	memset(RS_RND_DATA,0,4);
	/*
	for( i = 0; i < 4; i++)
	{
		RS_RD_RND[i] = rand() & 0xFF;
		RS_RND_DATA[i] = rand() & 0xFF;
	}
	*/
	memset(Dummy_15BYTE,0,15);
	//
	//for( k = 0; k < 4; k++)
	k = 0;
	{
		eep_page_read(0xea,0x00 + k * 0x40,0,rx_data);
		//		GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
		//		ReleasePermision();

		//		GetSuperWirePermission(); //{{ SPSHIN

		memset(INPUT_SHA,0,55);
		memcpy(INPUT_SHA,RS,32);
		j = 31;
		for( i = 0 ; i < 32; i++)
			INPUT_SHA[i] = rx_data[j--];
		//	printk("\r\n INPUT_SHA");
		//	printbyte(INPUT_SHA,32);

		memcpy(INPUT_SHA+32,RS_RD_RND,4);
		memcpy(INPUT_SHA+32+4,RS_RND_DATA,4);
		memcpy(INPUT_SHA+32+8,Dummy_15BYTE,15);

		Trail = 0x80;

		MCU_SHA256_EXE(INPUT_SHA, SHA_OUT, 55);
		//
		tx_data[0] = 0x00 + (k << 4);
		tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x09;
		printk("\r\n OPMODE ");
		tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x08;
		printk("\r\n OPMODE ");		
		tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		j = 7;
		for(i = 0; i <8; i++)
			tx_data[i] = LEN[j--];
		tx_data[8]	= Trail;
		j = 14;
		for(i = 9; i < 24; i++)
			tx_data[i] = Dummy_15BYTE[j--];
		j = 3;
		for(i = 24; i < 28; i++)
			tx_data[i] = RS_RND_DATA[j--];		
		j = 3;
		for(i = 28; i < 32; i++)
			tx_data[i] = RS_RD_RND[j--];		

		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		Delay_us(100);
		tspi_interface(cs, ADDR_NOR_R,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		Delay_us(100);
		printk("\r\n delay 100us");
		tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		j = 31;
		for( i = 0; i < 32; i++)
			DORCA_SHA_OUT[i] = rx_data[j--];

		if(memcmp(DORCA_SHA_OUT,SHA_OUT,32) != 0)
		{
			printk("\r\n RSSHAREAD FAIL ");
			printk("\r\n DORCA_SHA_OUT \r\n");
			printbyte(DORCA_SHA_OUT,32);
			success = 0;
			printk("\r\n SHA_OUT \r\n");
			printbyte(SHA_OUT,32);
		}
		else
			{
			printk("\r\n RSSHAREAD PASS ");
			printk("\r\n DORCA_SHA_OUT \r\n");
			printbyte(DORCA_SHA_OUT,32);
			//success = 0;
			printk("\r\n SHA_OUT \r\n");
			printbyte(SHA_OUT,32);

			}

		tx_data[0] = 0x01;
		printk("\r\n OPMODE ");		
		tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		endOP();
		//		GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
		//		ReleasePermision();
		//ReadStatusRegister();
		//
	}
	k = 1	;
	{
		eep_page_read(0xea,0x00 + k * 0x40,0,rx_data);
		//		GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
		//		ReleasePermision();

		//		GetSuperWirePermission(); //{{ SPSHIN

		memset(INPUT_SHA,0,55);
		memcpy(INPUT_SHA,RS,32);
		j = 31;
		for( i = 0 ; i < 32; i++)
			INPUT_SHA[i] = rx_data[j--];
		//	printk("\r\n INPUT_SHA");
		//	printbyte(INPUT_SHA,32);

		memcpy(INPUT_SHA+32,RS_RD_RND,4);
		memcpy(INPUT_SHA+32+4,RS_RND_DATA,4);
		memcpy(INPUT_SHA+32+8,Dummy_15BYTE,15);

		Trail = 0x80;

		MCU_SHA256_EXE(INPUT_SHA, SHA_OUT, 55);
		//
		tx_data[0] = 0x00 + (k << 4);
		tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x09;
		printk("\r\n OPMODE ");
		tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE 		, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x08;
		printk("\r\n OPMODE "); 	
		tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		j = 7;
		for(i = 0; i <8; i++)
			tx_data[i] = LEN[j--];
		tx_data[8]	= Trail;
		j = 14;
		for(i = 9; i < 24; i++)
			tx_data[i] = Dummy_15BYTE[j--];
		j = 3;
		for(i = 24; i < 28; i++)
			tx_data[i] = RS_RND_DATA[j--];		
		j = 3;
		for(i = 28; i < 32; i++)
			tx_data[i] = RS_RD_RND[j--];		

		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400		  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		Delay_us(100);
		tspi_interface(cs, ADDR_NOR_R,RG_ACCESS 		, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		Delay_us(100);
		printk("\r\n delay 100us");
		tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400		  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		j = 31;
		for( i = 0; i < 32; i++)
			DORCA_SHA_OUT[i] = rx_data[j--];

		if(memcmp(DORCA_SHA_OUT,SHA_OUT,32) != 0)
		{
			printk("\r\n RSSHAREAD FAIL ");
			printk("\r\n DORCA_SHA_OUT \r\n");
			printbyte(DORCA_SHA_OUT,32);
			success = 0;
			printk("\r\n SHA_OUT \r\n");
			printbyte(SHA_OUT,32);
		}
		else
			{
			printk("\r\n RSSHAREAD PASS ");
			printk("\r\n DORCA_SHA_OUT \r\n");
			printbyte(DORCA_SHA_OUT,32);
			//success = 0;
			printk("\r\n SHA_OUT \r\n");
			printbyte(SHA_OUT,32);

			}

		tx_data[0] = 0x01;
		printk("\r\n OPMODE "); 	
		tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		endOP();
		//		GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
		//		ReleasePermision();
		//ReadStatusRegister();
		//
	}


	k = 2;
	{
		eep_page_read(0xea,0x00 + k * 0x40,0,rx_data);
		//		GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
		//		ReleasePermision();

		//		GetSuperWirePermission(); //{{ SPSHIN

		memset(INPUT_SHA,0,55);
		memcpy(INPUT_SHA,RS,32);
		j = 31;
		for( i = 0 ; i < 32; i++)
			INPUT_SHA[i] = rx_data[j--];
		//	printk("\r\n INPUT_SHA");
		//	printbyte(INPUT_SHA,32);

		memcpy(INPUT_SHA+32,RS_RD_RND,4);
		memcpy(INPUT_SHA+32+4,RS_RND_DATA,4);
		memcpy(INPUT_SHA+32+8,Dummy_15BYTE,15);

		Trail = 0x80;

		MCU_SHA256_EXE(INPUT_SHA, SHA_OUT, 55);
		//
		tx_data[0] = 0x00 + (k << 4);
		tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x09;
		printk("\r\n OPMODE ");
		tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE 		, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x08;
		printk("\r\n OPMODE "); 	
		tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		j = 7;
		for(i = 0; i <8; i++)
			tx_data[i] = LEN[j--];
		tx_data[8]	= Trail;
		j = 14;
		for(i = 9; i < 24; i++)
			tx_data[i] = Dummy_15BYTE[j--];
		j = 3;
		for(i = 24; i < 28; i++)
			tx_data[i] = RS_RND_DATA[j--];		
		j = 3;
		for(i = 28; i < 32; i++)
			tx_data[i] = RS_RD_RND[j--];		

		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400		  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		Delay_us(100);
		tspi_interface(cs, ADDR_NOR_R,RG_ACCESS 		, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		Delay_us(100);
		printk("\r\n delay 100us");
		tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400		  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		j = 31;
		for( i = 0; i < 32; i++)
			DORCA_SHA_OUT[i] = rx_data[j--];

		if(memcmp(DORCA_SHA_OUT,SHA_OUT,32) != 0)
		{
			printk("\r\n RSSHAREAD FAIL ");
			printk("\r\n DORCA_SHA_OUT \r\n");
			printbyte(DORCA_SHA_OUT,32);
			success = 0;
			printk("\r\n SHA_OUT \r\n");
			printbyte(SHA_OUT,32);
		}
		else
			{
			printk("\r\n RSSHAREAD PASS ");
			printk("\r\n DORCA_SHA_OUT \r\n");
			printbyte(DORCA_SHA_OUT,32);
			//success = 0;
			printk("\r\n SHA_OUT \r\n");
			printbyte(SHA_OUT,32);

			}

		tx_data[0] = 0x01;
		printk("\r\n OPMODE "); 	
		tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		endOP();
		//		GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
		//		ReleasePermision();
		//ReadStatusRegister();
		//
	}

	k = 3	;
	{
		eep_page_read(0xea,0x00 + k * 0x40,0,rx_data);
		//		GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
		//		ReleasePermision();

		//		GetSuperWirePermission(); //{{ SPSHIN

		memset(INPUT_SHA,0,55);
		memcpy(INPUT_SHA,RS,32);
		j = 31;
		for( i = 0 ; i < 32; i++)
			INPUT_SHA[i] = rx_data[j--];
		//	printk("\r\n INPUT_SHA");
		//	printbyte(INPUT_SHA,32);

		memcpy(INPUT_SHA+32,RS_RD_RND,4);
		memcpy(INPUT_SHA+32+4,RS_RND_DATA,4);
		memcpy(INPUT_SHA+32+8,Dummy_15BYTE,15);

		Trail = 0x80;

		MCU_SHA256_EXE(INPUT_SHA, SHA_OUT, 55);
		//
		tx_data[0] = 0x00 + (k << 4);
		tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x09;
		printk("\r\n OPMODE ");
		tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE 		, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tx_data[0] = 0x08;
		printk("\r\n OPMODE "); 	
		tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		j = 7;
		for(i = 0; i <8; i++)
			tx_data[i] = LEN[j--];
		tx_data[8]	= Trail;
		j = 14;
		for(i = 9; i < 24; i++)
			tx_data[i] = Dummy_15BYTE[j--];
		j = 3;
		for(i = 24; i < 28; i++)
			tx_data[i] = RS_RND_DATA[j--];		
		j = 3;
		for(i = 28; i < 32; i++)
			tx_data[i] = RS_RD_RND[j--];		

		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400		  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		Delay_us(100);
		tspi_interface(cs, ADDR_NOR_R,RG_ACCESS 		, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		Delay_us(100);
		printk("\r\n delay 100us");
		tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400		  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
		j = 31;
		for( i = 0; i < 32; i++)
			DORCA_SHA_OUT[i] = rx_data[j--];

		if(memcmp(DORCA_SHA_OUT,SHA_OUT,32) != 0)
		{
			printk("\r\n RSSHAREAD FAIL ");
			printk("\r\n DORCA_SHA_OUT \r\n");
			printbyte(DORCA_SHA_OUT,32);
			success = 0;
			printk("\r\n SHA_OUT \r\n");
			printbyte(SHA_OUT,32);
		}
		else
			{
			printk("\r\n RSSHAREAD PASS ");
			printk("\r\n DORCA_SHA_OUT \r\n");
			printbyte(DORCA_SHA_OUT,32);
			//success = 0;
			printk("\r\n SHA_OUT \r\n");
			printbyte(SHA_OUT,32);

			}

		tx_data[0] = 0x01;
		printk("\r\n OPMODE "); 	
		tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE		   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		endOP();
		GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
		ReleasePermision();
		//ReadStatusRegister();
		//
	}

	return success;
	#endif
}
int RSCreate12(void)
{
#ifdef COMPARE

	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char BKUP_ADDR = 0;
	unsigned char RAND0[64];
	unsigned char RAND1[64];
	unsigned char RSx0[64];
	unsigned char RSx1[64];
	unsigned char Data[64];
	unsigned char temp[64];
	unsigned char RS0_Reverse[64];
	int iResult = 0;
	unsigned char msb = 0xe9;
	unsigned char lsb = 0x00;

	j = 15;
	for( i=16; i<32; i++)
		//for( i=0; i<16; i++)
	{
		tx_data[i] = 0x11;
	}

	eep_page_write(msb, lsb,tx_data,1);

	memset(tx_data,0,64);
	memset(rx_data,0,64);

	GetSuperWirePermission();
	GetPermissionByPW(SUPER_PW_CT, RG_PERM_SUPER_PASS);
	printk("\r\n ---------------- start of RS CREATE 0 ---------------- \r\n");
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W,RG_AES_CTRL         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x09;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x07;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_RNDGEN_USER         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(100);
	tx_data[0] = 0x04;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_RND_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(100);
	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	j = 31;
	for(i = 0; i < 32; i++)
		RAND0[i] = rx_data[j--];
	printk("\r\n RAND0 \r\n");
	printbyte(RAND0,32);
	tx_data[0] = 0x02;
	tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x04;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_RND_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(100);
	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	j = 31;
	for(i = 0; i < 32; i++)
		RAND1[i] = rx_data[j--];
	printk("\r\n RAND1 \r\n");
	printbyte(RAND1,32);


	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_RND_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	//tx_data[0] = 0x01;
	//tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	//tx_data[0] = 0x00;
	//tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	// ---- Write IV ----


	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_AES_CTRL         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	//tx_data[0] = 0x09;
	//tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	//tx_data[0] = 0x07;
	//tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	// ---- Write KEY ----
	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(30);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n ....1");
	tx_data[0] = 0x08;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x02;
	tspi_interface(cs, ADDR_NOR_W,RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	printk("\r\n ....2");
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(70);
	//
	//	tx_data[0] = 0x04;
	//	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	j = 31;
	for(i = 0; i < 32; i++)
		temp[i] = rx_data[j--];
	printk("\r\n temp \r\n");
	printbyte(temp,32);

	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W,RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n ....3");
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(70);



	Delay_ms(8);
	//tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320         , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);
	//Delay_us(10);
	//j = 31;
	//for( i = 0; i < 32; i++)
	//	RSx0[i] = rx_data[j--];

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	////
	//	tx_data[0] = 0x01;
	//	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	////
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(50);
	printk("\r\n ---------------- END of RS CREATE 0 ---------------- \r\n");
	//printk("\r\n after eep_page_read(0xEA,0x00,0,Data);");
	//return;
	/// ---- To generate RS_x1 : start ----
	printk("\r\n ---- To generate RS_x1 : start ----");
	tx_data[0] = 0x10;
	tspi_interface(cs, ADDR_NOR_W,RG_RSCREATE_CTRL         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	// AES ENC KEY SET
	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(30);
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	//set to RSCreate 
	tx_data[0] = 0x08;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	//RSCREATE_ENC1
	printk("\r\n RSCREATE_ENC1 - BEFORE");
#ifdef READ_REGS		
	ReadStatusRegister();		
#endif
	tx_data[0] = 0x02;
	tspi_interface(cs, ADDR_NOR_W,RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	
	//	Delay_ms(6000);
	//////{{ ADD 2017-08-10 LEDë¶ì ì¼°ë¤ ?ê¸°?í ì½ë 
	//	printk("\r\n ADD 2017-08-10 CODE FOR LED BLINKING OFF");
	//	tx_data[0] = 0x02;
	//	tspi_interface(cs, ADDR_NOR_W,RG_FFFF 		, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	//	Delay_ms(6000);
	//		printk("\r\n ADD 2017-08-10 CODE FOR LED BLINKING OFF TWO");
	//////}}
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RSCREATE_ENC1");
#ifdef READ_REGS		
	ReadStatusRegister();	
#endif
	Delay_us(70);
	//RSCREATE_ENC2
	tx_data[0] = 0x03;
	tspi_interface(cs, ADDR_NOR_W,RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RSCREATE_ENC2");
#ifdef READ_REGS		
	ReadStatusRegister();
#endif
	//	printk("\r\n ADD 2017-08-10 CODE FOR LED BLINKING OFF");
	//	tx_data[0] = 0x02;
	//	Delay_ms(4000);
	//	tspi_interface(cs, ADDR_NOR_W,RG_FFFF 		, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);


	// Write time to EEPROM
	Delay_us(70);
	Delay_ms(8);
	tx_data[0] = 0x01;
	tspi_interface(cs,ADDR_NOR_W, RG_ST3_SYMCIP_RSCREATE_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x01;
	tspi_interface(cs,ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x00;
	tspi_interface(cs,ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	tx_data[0] = 0x01;
	tspi_interface(cs,ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x01;
	tspi_interface(cs,ADDR_NOR_W, RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x00;
	tspi_interface(cs,ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(50);
	endOP();
	printk("\r\n RSCREATE_ENC - AFTER - 2");
#ifdef READ_REGS	
	ReadStatusRegister();
#endif
	printk("\r\n ---- To generate RS_x1 : END ----");

	eep_page_read(0xEA,0x00,0,RSx0);
	eep_page_read(0xEA,0x40,0,RSx1);
	printk("\r\n RAND0 ");
	printbyte(RAND0,32);
	printk("\r\n RAND1 ");
	printbyte(RAND1,32);
	printk("\r\n RSx0 ");
	j = 31;
	for(i = 0; i < 32 ; i++)
	{
		RS0_Reverse[i] = RSx0[j--];
	}
	printbyte(RS0_Reverse,32);
	if(IsRsCorrect(RAND1,RS0_Reverse,0) == 0)
		success = 0;

	printk("\r\n RSx1 ");
	j = 31;
	for(i = 0; i < 32 ; i++)
	{
		temp[i] = RSx1[j--];
	}
	printbyte(temp,32);
	if(IsRsCorrect(RS0_Reverse,temp,1) == 0)
		success = 0;

	return success;
	#endif
}
int RSCreate(void)
{
	int success = 1;
	printk("\r\n\r\n RSCreate12()");
	if(RSCreate12() == 0)
		success = 0;
	printk("\r\n\r\n RSCreate34()");	
	if(RSCreate34() == 0)
		success = 0;
	return success;
}

int RootSerial()
{
#ifdef COMPARE

	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;

L_OKA_START:
	while(1)
	{
		temp = 'z' ;

		printk("\r\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  * 		   RootSerial	   TEST MAIN					  *");
		printk("\r\n  *****************************************************");
		printk("\r\n  * number of iteration 	%d						  *",NumOfIterOKA );
		printk("\r\n  * i. Input number of iteration					  *");
		printk("\r\n  * 1.-> RS_Create 					  *");	
		printk("\r\n  * 2.-> RSSHARead 					  *");
		printk("\r\n  * 3.-> RSDirectRead				  *");
		printk("\r\n  * 4. Read RS 0 ~ 3				  *");			
		printk("\r\n  * 5. Reset RS 0 ~ 3				  *");						
		printk("\r\n  * k. test all				  *");								
		printk("\r\n  * m. return to top menu							  *");	
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n");

		printk("\r\n");
		printk("\r\n  * Select : ");

		while(temp == 'z')
		{
			int HitCnt = 0;
			int MissCnt = 0;
			temp = _uart_get_char();

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");
			if(temp == 0x0d)
				goto L_OKA_START;
			if(temp == 'm')
			{
				printk("\r\nm is pressed");
				return;
			}


			switch ( temp )
			{
			case 'i' : 
				printk("\r\n input number of iteration : (4digit)");
				printk("\r\n 0x");
				NumOfIterOKA = get_int();
				NumOfIterOKA =( NumOfIterOKA<<8)| get_int();		 
				break;

			case '1' : 
				printk("\r\n RSCreate START");
				for(i = 0; i < NumOfIterOKA;i++)
				{
					//	iResult = OKA_Test();
					START;
					iResult = RSCreate();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n RSCreate END");
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);


				break;
			case '2' :
				printk("\r\nRSSHARead TEST START");
				for(i = 0; i < NumOfIterOKA;i++)
				{
					START;
					printk("\r\n Start of %dth iteration",i+1);						
					iResult = RSSHARead();
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n RSSHARead TEST END");				
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				break; 


			case '3':
				printk("\r\n RSDirectRead TEST START");
				for(i = 0; i < NumOfIterOKA;i++)
				{
					//	iResult = OKA_Test();
					START;
					iResult = RSDirectRead();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n RSDirectRead TEST END");
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				break;
			case '4':
				i = 0;
				printk("\r\n READ RS 0 ~ 3 START");
				for(i = 0; i < 4; i++)
					eep_page_read(0xEA, 0x40*i, 0, tx_data);

				printk("\r\n READ RS 0 ~ 3 END");					
			break;
			case '5':
				i = 0;
				printk("\r\n RESET RS 0 ~ 3 START");
				memset(tx_data,0,64);
				for(i = 0; i < 4; i++)
					eep_page_write(0xEA, 0x40*i, tx_data,1);

				printk("\r\n RESET RS 0 ~ 3 END");					
			break;
			case 'k':
				MissCnt = HitCnt = 0;
				printk("\r\n RSCreate START");
				for(i = 0; i < NumOfIterOKA;i++)
				{
					//	iResult = OKA_Test();
					START;
					iResult = RSCreate();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n RSCreate END");
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				MissCnt = HitCnt = 0;
				printk("\r\nRSSHARead TEST START");
				for(i = 0; i < NumOfIterOKA;i++)
				{
					START;
					printk("\r\n Start of %dth iteration",i+1);						
					iResult = RSSHARead();
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n RSSHARead TEST END");				
				PrintCnt(HitCnt,MissCnt,NumOfIterPermission);
				break; 				
				
			default : temp = 'p'; break;
			}

		}
	}

#endif

}
int PrintBISTResult(int BistNum,int retVal)
{
	int success = 1;
	printk("\r\n BIST TEST RESULT BIST NUM %d",BistNum);
	if(retVal != 0x80)
	{
		printk("FAIL  value 0x%02x",retVal);
		success = 0;
	}
	else
		printk("PASS");

	return success;
}
void ReadStatusRegister()
{

}

#if 0
PrintBISTNum(int BistNum)
{
	printk("\r\n ================== BIST %d (0x%02x) ================== \r\n",BistNum,BistNum);
}

void BIST_TEST_P1(void)
{

	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int BistNum = 0;
	int iResult = 0;
	printk("\r\n ---------------- start of BIST TV0E0007 ---------------- \r\n");	
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	//printk("\r\n Clear all EEPROM as 0 ");
	//eep_all_page_write(tx_data);
	GetSuperWirePermission();


	tx_data[0] = 0x0E;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = ST1_MEM_TEST_EE_BIST;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_MEM_TEST_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_BIST_MODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x04;PrintBISTNum(BistNum);

	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(40);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(40);
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);


	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x05;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(50);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);
	//Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(50);
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);

	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x06;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x00;
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	//	Delay_ms(28);
	Delay_ms(30);
	tx_data[0] = 0x00;	
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);
	tx_data[0] = 0x00;	
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);	

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);
	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x07;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(4);
	tx_data[0] = 0x00;	
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);
	tx_data[0] = 0x00;	
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);	

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);
	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x08;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(4);
	tx_data[0] = 0x00;	
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);
	tx_data[0] = 0x00;	
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);	

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);
	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x09;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(160);
	tx_data[0] = 0x00;	
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);	

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);	
	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x0a;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);	
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);		
	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x0b;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);// v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);	
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);		

	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x0C;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);	
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);
	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x0D;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);	
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);			

	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x0E;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);	

	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x0F;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(26);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);		

	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x10;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);	
	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x11;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);		
	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x12;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);		

	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x13;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);		
	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x14;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);//v
	Delay_ms(5);
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);	

	//////////////////////////////////////////////////////////////////////////////////////////
	/*	tx_data[0] = BistNum =  0x14;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	Delay_ms(5);
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
	success = 0;
	Delay_us(100);	
	*/
	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x15;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	Delay_ms(5);//v
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);	

	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x16;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3); //v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);	

	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x17;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5); //v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);	


	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x18;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);// v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);	

	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x19;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5); //v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);	

	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x1A;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3); //v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);		

	//////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x1B;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5); //v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);//v
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);//v

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);			

	//////////////////////////////////////////////////////////////////////////////////////////
	/*
	tx_data[0] = BistNum =  0x1B;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5); 
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);

	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
	success = 0;
	Delay_us(100);			
	*/
	printk("\r\n ---------------- END of BIST TV0E0007 ---------------- \r\n");

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_BIST_MODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_MEM_TEST_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
	ReleasePermision();

}

void BIST_TEST_P2(void)
{

	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int BistNum = 0;
	int iResult = 0;
	printk("\r\n ---------------- start of BIST TV0E0007 ---------------- \r\n");	
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	GetSuperWirePermission();


	tx_data[0] = 0x0E;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = ST1_MEM_TEST_EE_BIST;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_MEM_TEST_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x01;
	tspi_interface(cs, ADDR_NOR_W,RG_BIST_MODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	//////////////////////////////////////////////////////////////////////////////////////////
	//	printk("\r\n ---------------- start of BIST TV0E0010 ---------------- \r\n");		
	//	memset(tx_data,0xFF,64);
	//	memset(rx_data,0,64);
	//	printk("\r\n SET all EEPROM as FF ");
	//	eep_all_page_write(tx_data);	
	//	memset(tx_data,0,64);
	/////////////////////////////////////////////////////////////////////////////////////////////////////	
	tx_data[0] = BistNum =  0x20;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);			
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x21;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(6);
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;
	Delay_us(100);			
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x22;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;	
	Delay_us(100);			
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x23;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;	
	Delay_us(100);			
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x24;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(5);	
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;	
	Delay_us(100);			

	/////////////////////////////////////////////////////////////////////////////////////////////////////
	tx_data[0] = BistNum =  0x25;PrintBISTNum(BistNum);
	tspi_interface(cs, ADDR_NOR_W,RG_EE_BI_NO         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_ms(3);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	Delay_us(10);	
	tspi_interface(cs, ADDR_NOR_R,RG_MB_ERROR_BIT         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	if(PrintBISTResult(BistNum,rx_data[0]) == 0)
		success = 0;	
	Delay_us(100);	

	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_BIST_MODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_MEM_TEST_OPMODE         , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	endOP();
	ReleasePermision();
}


void ReadStatusRegister()
{
	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char Addr[2];
	int BistNum = 0;
	int iResult = 0;
	printk("\r\n ---------------- ReadStatusRegister ---------------- \r\n");	
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	tspi_interface(cs, ADDR_NOR_R,RG_ST0_CUR                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST0_CUR0 x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_CHK_RSFLAG                , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_CHK_RSFLAG 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST1_CHK_RSFLAG_CUR        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST1_CHK_RSFLAG_CUR   0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST1_PON_READ_CUR          , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n ST1_PON_READ_CUR  0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_STCM0_CUR                 , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_STCM0_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST1_STDSPI_CUR            , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST1_STDSPI_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST1_EE_CFG_CUR            , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST1_EE_CFG_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST1_RND_CUR               , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST1_RND_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST1_SYMCIP_CUR            , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST1_SYMCIP_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST1_OKA_CUR               , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST1_OKA_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST1_MIDR_CUR              , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST1_MIDR_CUR 0x%02x ",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST1_PERM_GET_CUR          , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST1_PERM_GET_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST1_EEP_OW_CTRL_CUR       , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST1_EEP_OW_CTRL_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST1_MEM_TEST_CUR          , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST1_MEM_TEST_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_EEP_OW_CTRL_CUR       , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_EEP_OW_CTRL_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_OPMODE_AES_CUR , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_OPMODE_AES_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_OKA_OKA2_CUR          , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_OKA_OKA2_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_STDSPI_SHA_CUR        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_STDSPI_SHA_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_SYMCIP_SHAAuth_CUR    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_SYMCIP_SHAAuth_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST2_RND_CUR               , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST2_RND_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST3_RND_CUR               , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST3_RND_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST3_SYMCIP_AES_CUR        , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST3_SYMCIP_AES_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST3_SYMCIP_KEYLOAD_CUR    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST3_SYMCIP_KEYLOAD_CUR 0x%02x",rx_data[0]);
	tspi_interface(cs, ADDR_NOR_R,RG_ST3_SYMCIP_RSCREATE_CUR   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_ST3_SYMCIP_RSCREATE_CUR 0x%02x",rx_data[0]);

	tspi_interface(cs, ADDR_NOR_R,RG_KL_CTRL   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RG_KL_CTRL 0x%02x",rx_data[0]);



	Addr[0] = 0x0f;
	Addr[1] = 0xfc;
	tspi_interface(cs, ADDR_NOR_R,Addr   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n USERZONE LOCK 15~8 0x%02x",rx_data[0]);

	Addr[0] = 0x0f;
	Addr[1] = 0xfd;
	tspi_interface(cs, ADDR_NOR_R,Addr   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n USERZONE LOCK 7~0 0x%02x",rx_data[0]);

	Addr[0] = 0x0f;
	Addr[1] = 0xfe;
	tspi_interface(cs, ADDR_NOR_R,Addr   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	printk("\r\n RSLock[0] USERZONELOCK[4] 7~0 0x%02x",rx_data[0]);



}
#endif
void PrintLog(unsigned char *Result,unsigned char *Expected)
{
	if( memcmp(Result,Expected,16) != 0)
	{
		printk("\r\n Result:");  
		printbyte(Result,16);

		printk("\r\n Expected:");
		printbyte(Expected,16);		

	}

}
void Reset(void)
{
	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_SOFT_RESET                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
        Delay_ms(16);
	tx_data[0] = 0x00;
	tspi_interface(cs, ADDR_NOR_W,RG_SOFT_RESET                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		
	Delay_ms(16);
	Delay_us(5);

}

int TwoFrameTest()
{
#ifdef COMPARE

	unsigned char Key101S[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char Dec101S_01[] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
	unsigned char Dec101S_02[] = {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};	
	unsigned char Dec101S_03[] = {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
	unsigned char Dec101S_04[] = {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};

	unsigned char Enc101S_01[] = {0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97};
	unsigned char Enc101S_02[] = {0xf5,0xd3,0xd5,0x85,0x03,0xb9,0x69,0x9d,0xe7,0x85,0x89,0x5a,0x96,0xfd,0xba,0xaf};	
	unsigned char Enc101S_03[] = {0x43,0xb1,0xcd,0x7f,0x59,0x8e,0xce,0x23,0x88,0x1b,0x00,0xe3,0xed,0x03,0x06,0x88};
	unsigned char Enc101S_04[] = {0x7b,0x0c,0x78,0x5e,0x27,0xe8,0xad,0x3f,0x82,0x23,0x20,0x71,0x04,0x72,0x5d,0xd4};	


	unsigned char EncOut_01[16];
	unsigned char EncOut_02[16];
	unsigned char DecOut_01[16];
	unsigned char DecOut_02[16];	
	int mode = 0;	
	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	memcpy(tx_data+16,Key101S,16);

	KEY_SET(tx_data);
	eep_page_read(0xe9,00,0,rx_data);
	printk("\r\n[NOTE] ---- TV092002, Two frame mode, 2. 1st frame enc --------\r\n");
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_EE_KEY_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0xB;
	tspi_interface(cs, ADDR_NOR_W,RG_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x2;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x3;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	Delay_us(3);
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Dec101S_01[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Dec101S_02[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		EncOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		EncOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ---- TV092002, Two frame mode, 2.1. 1st frame result compare --------\r\n");
	if( memcmp(EncOut_01,Enc101S_01,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
		printk("\r\n 1/2 frame FAIL 01");

	PrintLog(EncOut_01,Enc101S_01);

	if( memcmp(EncOut_02,Enc101S_02,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
		printk("\r\n 1/2 frame FAIL 02");

	PrintLog(EncOut_02,Enc101S_02);

	printk("\n[NOTE]  ---- TV092002, Two frame mode, 3. 2nd frame enc --------\n");
	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Dec101S_03[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Dec101S_04[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		EncOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		EncOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ---- - TV092002, Two frame mode, 3.1. 2nd frame result compare --------\r\n");
	if( memcmp(EncOut_01,Enc101S_03,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
	{
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}

	PrintLog(EncOut_01,Enc101S_03);

	if( memcmp(EncOut_02,Enc101S_04,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
	{
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(EncOut_02,Enc101S_04);

	printk("\r\n[NOTE]  ---- - TV092002, Two frame mode, 4. 3rd frame dec --------\r\n");
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_EE_KEY_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0xB;
	tspi_interface(cs, ADDR_NOR_W,RG_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x2;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x3;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	Delay_us(3);
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Enc101S_01[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Enc101S_02[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF420                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		DecOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		DecOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ----  ---- TV092002, Two frame mode, 4.1. 3rd frame result compare --------\r\n");
	if( memcmp(DecOut_01,Dec101S_01,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
	{
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}

	PrintLog(DecOut_01,Dec101S_01);

	if( memcmp(DecOut_02,Dec101S_02,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
	{
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(DecOut_02,Dec101S_02);

	printk("\n[NOTE]  ----TV092002, Two frame mode, 5. 5th frame dec--------\n");
	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Enc101S_03[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Enc101S_04[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF420                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		DecOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		DecOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ---- TV092002, Two frame mode, 5.1. 5th frame result compare --------\r\n");
	if( memcmp(DecOut_01,Dec101S_03,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
	{
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}


	PrintLog(DecOut_01,Dec101S_03);

	if( memcmp(DecOut_02,Dec101S_04,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
	{
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(DecOut_02,Dec101S_04);
#if 0	
	printk("\r\n part 1");
	printk("\r\n EncOut_01 \r\n");
	printbyte(EncOut_01,16);
	printk("\r\n EncOut_02 \r\n");
	printbyte(EncOut_02,16);	
	printk("\r\n Enc101S_01\r\n");
	printbyte(Enc101S_01,16);
	printk("\r\n Enc101S_02\r\n");
	printbyte(Enc101S_02,16);	
#endif	
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	Reset();
	return success;
#endif
}


int TwoFrameTestARIA()
{
#ifdef COMPARE

	unsigned char Key101S[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	unsigned char Dec101S_01[] = {0x17,0xc6,0xa3,0xee,0xc4,0x7f,0x7d,0x19,0xa1,0xe8,0x2b,0xb8,0x50,0x4b,0x49,0x20};
	unsigned char Dec101S_02[] = {0x31,0x44,0x20,0x2f,0xce,0x12,0x6c,0xe3,0xb5,0xf3,0x83,0x51,0x03,0x87,0x35,0xb5};	
	unsigned char Dec101S_03[] = {0x3f,0x78,0x8a,0x07,0xf5,0x45,0x1d,0x5e,0xb4,0xbc,0x7a,0x04,0xa6,0xe5,0x74,0xcb};
	unsigned char Dec101S_04[] = {0xf4,0xc0,0xe6,0x20,0x39,0x95,0xe2,0x17,0x05,0x0f,0x09,0x76,0xe2,0x2a,0xa2,0xc7};

	unsigned char Enc101S_01[] = {0xe8,0x39,0x8f,0x89,0x73,0x23,0xe7,0xbc,0xc2,0x18,0xc3,0x90,0x36,0x5d,0x69,0xe8};
	unsigned char Enc101S_02[] = {0x63,0xae,0x8e,0x4c,0x14,0xa2,0xec,0xe9,0xd9,0x09,0x31,0x9b,0x6f,0x7e,0x3b,0x9e};	
	unsigned char Enc101S_03[] = {0x25,0x36,0x6d,0x6f,0x3e,0xd0,0x8b,0xc5,0xda,0x43,0xbe,0x2c,0x08,0x48,0x73,0x6b};
	unsigned char Enc101S_04[] = {0x1d,0x1d,0x7b,0x48,0xb7,0xec,0xb7,0x0c,0xfa,0x58,0x22,0x19,0xa7,0x98,0x54,0x7c};	


	unsigned char EncOut_01[16];
	unsigned char EncOut_02[16];
	unsigned char DecOut_01[16];
	unsigned char DecOut_02[16];	
	int mode = 0;	
	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	memset(tx_data,0,64);
	memset(rx_data,0,64);
	memcpy(tx_data+16,Key101S,16);

	KEY_SET(tx_data);
	eep_page_read(0xe9,00,0,rx_data);
	printk("\r\n[NOTE] ---- ARIA, Two frame mode, 2. 1st frame enc --------\r\n");
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_EE_KEY_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = (1 << 3)|//RG_AES_2_1_FRAME
		(1 << 1)|//128(1),256(0)	;
		(0 << 0);//AES(1),ARIA(0)	;
	tspi_interface(cs, ADDR_NOR_W,RG_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x2;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x3;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	Delay_us(3);
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Dec101S_01[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Dec101S_02[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		EncOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		EncOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ---- ARIA, Two frame mode, 2.1. 1st frame result compare --------\r\n");
	if( memcmp(EncOut_01,Enc101S_01,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
		printk("\r\n 1/2 frame FAIL 01");

	PrintLog(EncOut_01,Enc101S_01);

	if( memcmp(EncOut_02,Enc101S_02,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
		printk("\r\n 1/2 frame FAIL 02");

	PrintLog(EncOut_02,Enc101S_02);

	printk("\n[NOTE]  ---- ARIA, Two frame mode, 3. 2nd frame enc --------\n");
	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Dec101S_03[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Dec101S_04[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		EncOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		EncOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ---- - ARIA, Two frame mode, 3.1. 2nd frame result compare --------\r\n");
	if( memcmp(EncOut_01,Enc101S_03,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
	{
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}

	PrintLog(EncOut_01,Enc101S_03);

	if( memcmp(EncOut_02,Enc101S_04,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
	{
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(EncOut_02,Enc101S_04);

	printk("\r\n[NOTE]  ---- - ARIA, Two frame mode, 4. 3rd frame dec --------\r\n");
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_EE_KEY_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = (1 << 3)|//RG_AES_2_1_FRAME
		(1 << 1)|//128(1),256(0)	;
		(0 << 0);//AES(1),ARIA(0)	;

	tspi_interface(cs, ADDR_NOR_W,RG_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x2;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x3;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	Delay_us(3);
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Enc101S_01[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Enc101S_02[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF420                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		DecOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		DecOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ----  ---- ARIA, Two frame mode, 4.1. 3rd frame result compare --------\r\n");
	if( memcmp(DecOut_01,Dec101S_01,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
	{
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}

	PrintLog(DecOut_01,Dec101S_01);

	if( memcmp(DecOut_02,Dec101S_02,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
	{
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(DecOut_02,Dec101S_02);

	printk("\n[NOTE]  ----ARIA, Two frame mode, 5. 5th frame dec--------\n");
	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Enc101S_03[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Enc101S_04[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF420                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		DecOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		DecOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ---- ARIA, Two frame mode, 5.1. 5th frame result compare --------\r\n");
	if( memcmp(DecOut_01,Dec101S_03,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
	{
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}


	PrintLog(DecOut_01,Dec101S_03);

	if( memcmp(DecOut_02,Dec101S_04,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
	{
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(DecOut_02,Dec101S_04);
#if 0	
	printk("\r\n part 1");
	printk("\r\n EncOut_01 \r\n");
	printbyte(EncOut_01,16);
	printk("\r\n EncOut_02 \r\n");
	printbyte(EncOut_02,16);	
	printk("\r\n Enc101S_01\r\n");
	printbyte(Enc101S_01,16);
	printk("\r\n Enc101S_02\r\n");
	printbyte(Enc101S_02,16);	
#endif	
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	Reset();
	return success;
#endif
}

int TwoFrameTest256()
{
#ifdef COMPARE

	unsigned char Key201S[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
	unsigned char Dec201S_01[] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
	unsigned char Dec201S_02[] = {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};	
	unsigned char Dec201S_03[] = {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
	unsigned char Dec201S_04[] = {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};

	unsigned char Enc201S_01[] = {0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8};
	unsigned char Enc201S_02[] = {0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70};	
	unsigned char Enc201S_03[] = {0xb6,0xed,0x21,0xb9,0x9c,0xa6,0xf4,0xf9,0xf1,0x53,0xe7,0xb1,0xbe,0xaf,0xed,0x1d};
	unsigned char Enc201S_04[] = {0x23,0x30,0x4b,0x7a,0x39,0xf9,0xf3,0xff,0x06,0x7d,0x8d,0x8f,0x9e,0x24,0xec,0xc7};	


	unsigned char EncOut_01[16];
	unsigned char EncOut_02[16];
	unsigned char DecOut_01[16];
	unsigned char DecOut_02[16];	
	int mode = 0;	
	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	memset(tx_data,0,64);
	memset(rx_data,0,64);
	memcpy(tx_data+16,Key201S,16);
	memcpy(tx_data,Key201S+16,16);	

	KEY_SET(tx_data);
	eep_page_read(0xe9,00,0,rx_data);
	printk("\r\n[NOTE] ----  , Two frame mode, 2. 1st frame enc --------\r\n");
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_EE_KEY_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = (0 <<4 ) |//RG_AES_OPMOD  3'h0 : ECB,3'h1 : CBC,3'h2 : OFB,3'h3 : CTR,3'h4 : CFB
		(1 <<3) | //Tow frame mode
		(0 <<2) |//Normal
		(0<<1)  |//256
		(1) ;// ||AES
	tspi_interface(cs, ADDR_NOR_W,RG_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x2;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x3;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	Delay_us(3);
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Dec201S_01[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Dec201S_02[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		EncOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		EncOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ----  , Two frame mode, 2.1. 1st frame result compare --------\r\n");
	if( memcmp(EncOut_01,Enc201S_01,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
		printk("\r\n 1/2 frame FAIL 01");

	PrintLog(EncOut_01,Enc201S_01);

	if( memcmp(EncOut_02,Enc201S_02,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
		printk("\r\n 1/2 frame FAIL 02");

	PrintLog(EncOut_02,Enc201S_02);

	printk("\n[NOTE]  ---- TV092002, Two frame mode, 3. 2nd frame enc --------\n");
	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Dec201S_03[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Dec201S_04[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		EncOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		EncOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ---- -  , Two frame mode, 3.1. 2nd frame result compare --------\r\n");
	if( memcmp(EncOut_01,Enc201S_03,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
	{
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}

	PrintLog(EncOut_01,Enc201S_03);

	if( memcmp(EncOut_02,Enc201S_04,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
	{
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(EncOut_02,Enc201S_04);

	printk("\r\n[NOTE]  ---- - TV092002, Two frame mode, 4. 3rd frame dec --------\r\n");
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_EE_KEY_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = (0 <<4 ) |//RG_AES_OPMOD  3'h0 : ECB,3'h1 : CBC,3'h2 : OFB,3'h3 : CTR,3'h4 : CFB
		(1 <<3) | //Tow frame mode
		(0 <<2) |//Normal
		(0<<1)  |//256
		(1) ;// ||AES
	tspi_interface(cs, ADDR_NOR_W,RG_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x2;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x3;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	Delay_us(3);
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Enc201S_01[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Enc201S_02[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF420                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		DecOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		DecOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ----  ----  , Two frame mode, 4.1. 3rd frame result compare --------\r\n");
	if( memcmp(DecOut_01,Dec201S_01,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else {
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}

	PrintLog(DecOut_01,Dec201S_01);

	if( memcmp(DecOut_02,Dec201S_02,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else {
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(DecOut_02,Dec201S_02);

	printk("\n[NOTE]  ----TV092002, Two frame mode, 5. 5th frame dec--------\n");
	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Enc201S_03[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Enc201S_04[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF420                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		DecOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		DecOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ----  , Two frame mode, 5.1. 5th frame result compare --------\r\n");
	if( memcmp(DecOut_01,Dec201S_03,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
	{
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}


	PrintLog(DecOut_01,Dec201S_03);

	if( memcmp(DecOut_02,Dec201S_04,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
	{
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(DecOut_02,Dec201S_04);
#if 0	
	printk("\r\n part 1");
	printk("\r\n EncOut_01 \r\n");
	printbyte(EncOut_01,16);
	printk("\r\n EncOut_02 \r\n");
	printbyte(EncOut_02,16);	
	printk("\r\n Enc201S_01\r\n");
	printbyte(Enc201S_01,16);
	printk("\r\n Enc201S_02\r\n");
	printbyte(Enc201S_02,16);	
#endif	
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	Reset();
	return success;
#endif
}


int TwoFrameTest256ARIA()
{
#ifdef COMPARE

	unsigned char Key201S[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	unsigned char Dec201S_01[] = {0x11,0x11,0x11,0x11,0xaa,0xaa,0xaa,0xaa,0x11,0x11,0x11,0x11,0xbb,0xbb,0xbb,0xbb};
	unsigned char Dec201S_02[] = {0x11,0x11,0x11,0x11,0xcc,0xcc,0xcc,0xcc,0x11,0x11,0x11,0x11,0xdd,0xdd,0xdd,0xdd};	
	unsigned char Dec201S_03[] = {0x22,0x22,0x22,0x22,0xaa,0xaa,0xaa,0xaa,0x22,0x22,0x22,0x22,0xbb,0xbb,0xbb,0xbb};
	unsigned char Dec201S_04[] = {0x22,0x22,0x22,0x22,0xcc,0xcc,0xcc,0xcc,0x22,0x22,0x22,0x22,0xdd,0xdd,0xdd,0xdd};

	unsigned char Enc201S_01[] = {0x58,0xa8,0x75,0xe6,0x04,0x4a,0xd7,0xff,0xfa,0x4f,0x58,0x42,0x0f,0x7f,0x44,0x2d};
	unsigned char Enc201S_02[] = {0x8e,0x19,0x10,0x16,0xf2,0x8e,0x79,0xae,0xfc,0x01,0xe2,0x04,0x77,0x32,0x80,0xd7};	
	unsigned char Enc201S_03[] = {0x01,0x8e,0x5f,0x7a,0x93,0x8e,0xc3,0x07,0x11,0x71,0x99,0x53,0xba,0xe8,0x65,0x42};
	unsigned char Enc201S_04[] = {0xcd,0x7e,0xbc,0x75,0x24,0x74,0xc1,0xa5,0xf6,0xea,0xaa,0xce,0x2a,0x7e,0x29,0x46};	


	unsigned char EncOut_01[16];
	unsigned char EncOut_02[16];
	unsigned char DecOut_01[16];
	unsigned char DecOut_02[16];	
	int mode = 0;	
	int i = 0;
	int j = 0;
	unsigned int inst = 0;
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	memset(tx_data,0,64);
	memset(rx_data,0,64);
	memcpy(tx_data+16,Key201S,16);
	memcpy(tx_data,Key201S+16,16);	

	KEY_SET(tx_data);
	eep_page_read(0xe9,00,0,rx_data);

	printk("\r\n[NOTE] ----  , Two frame mode, 2. 1st frame enc --------\r\n");
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_EE_KEY_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = (1 << 3)|//RG_AES_2_1_FRAME
		(0 << 1)|//128(1),256(0)	;
		(0 << 0);//AES(1),ARIA(0)	;

	tspi_interface(cs, ADDR_NOR_W,RG_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x2;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x3;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	Delay_us(3);
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Dec201S_01[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Dec201S_02[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		EncOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		EncOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ----  , Two frame mode, 2.1. 1st frame result compare --------\r\n");
	if( memcmp(EncOut_01,Enc201S_01,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
		printk("\r\n 1/2 frame FAIL 01");

	PrintLog(EncOut_01,Enc201S_01);

	if( memcmp(EncOut_02,Enc201S_02,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
		printk("\r\n 1/2 frame FAIL 02");

	PrintLog(EncOut_02,Enc201S_02);

	printk("\n[NOTE]  ---- 256ARIA, Two frame mode, 3. 2nd frame enc --------\n");
	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Dec201S_03[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Dec201S_04[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		EncOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		EncOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ---- -  , Two frame mode, 3.1. 2nd frame result compare --------\r\n");
	if( memcmp(EncOut_01,Enc201S_03,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
	{
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}

	PrintLog(EncOut_01,Enc201S_03);

	if( memcmp(EncOut_02,Enc201S_04,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
	{
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(EncOut_02,Enc201S_04);

	printk("\r\n[NOTE]  ---- - 256ARIA, Two frame mode, 4. 3rd frame dec --------\r\n");
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_EE_KEY_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = (1 << 3)|//RG_AES_2_1_FRAME
		(0 << 1)|//128(1),256(0)	;
		(0 << 0);//AES(1),ARIA(0)	;

	tspi_interface(cs, ADDR_NOR_W,RG_AES_CTRL                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x2;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x3;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	Delay_us(3);
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Enc201S_01[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Enc201S_02[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF420                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		DecOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		DecOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ----  ----  , Two frame mode, 4.1. 3rd frame result compare --------\r\n");
	if( memcmp(DecOut_01,Dec201S_01,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else {
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}

	PrintLog(DecOut_01,Dec201S_01);

	if( memcmp(DecOut_02,Dec201S_02,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else {
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(DecOut_02,Dec201S_02);

	printk("\n[NOTE]  ----256ARIA, Two frame mode, 5. 5th frame dec--------\n");
	j = 15;
	for( i = 0; i < 16; i++)
		tx_data[i] = Enc201S_03[j--];
	j = 15;
	for( i = 16; i < 32; i++)
		tx_data[i] = Enc201S_04[j--];	
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF400                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF420                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	j = 15;
	for( i = 0; i < 16; i++)
		DecOut_01[i] = rx_data[j--];

	j = 31;
	for( i = 0; i < 16; i++)
		DecOut_02[i] = rx_data[j--];	
	printk("\r\n[NOTE]  ----  , Two frame mode, 5.1. 5th frame result compare --------\r\n");
	if( memcmp(DecOut_01,Dec201S_03,16) == 0 )
		printk("\r\n 1/2 frame PASS 01");
	else
	{
		printk("\r\n 1/2 frame FAIL 01");
		success = 0;
	}


	PrintLog(DecOut_01,Dec201S_03);

	if( memcmp(DecOut_02,Dec201S_04,16) == 0 )
		printk("\r\n 1/2 frame PASS 02");
	else
	{
		printk("\r\n 1/2 frame FAIL 02");
		success = 0;
	}

	PrintLog(DecOut_02,Dec201S_04);
#if 0	
	printk("\r\n part 1");
	printk("\r\n EncOut_01 \r\n");
	printbyte(EncOut_01,16);
	printk("\r\n EncOut_02 \r\n");
	printbyte(EncOut_02,16);	
	printk("\r\n Enc201S_01\r\n");
	printbyte(Enc201S_01,16);
	printk("\r\n Enc201S_02\r\n");
	printbyte(Enc201S_02,16);	
#endif	
	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST2_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_SYMCIP_OPMODE                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	endOP();
	Reset();
	return success;
#endif
}
int SHA_1Frame_TEST()
{
#ifdef COMPARE

	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char buf_1FRM[64];
	unsigned char buf_1FRMANS[64];
	unsigned char buf_1SW[64];	
	unsigned char buf_1FRMANS_REOrderedFRM[64];
	int i = 0;
	int j = 0;
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	
	printk("\r\n[NOTE] ----  , SHA_1Frame_TEST --------\r\n");
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	hexstr2bytes("61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018", buf_1FRM);
	hexstr2bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",buf_1FRMANS);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x6;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE					, NULL, NULL, NULL, NULL, tx_data, rx_data, 1); 
    tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	j = 63;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buf_1FRM[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	j = 31;
	for( i = 0; i < 32; i++)
	{
		buf_1FRMANS_REOrderedFRM[i] =  rx_data[j--];
	}
	
	MCU_SHA256_EXE(buf_1FRM, buf_1SW, 3);

		/*
		printk("\r\n error comp sha result 1");
		printk("\r\n expeced");
		printbyte(buf_1FRMANS,32);
		printk("\r\n result");
		printbyte(buf_1FRMANS_REOrderedFRM,32);	
		printk("\r\n sw");
		printbyte(buf_1SW,32);	
		*/
#ifdef TEST_MODE	
	if(memcmp(buf_1FRMANS_REOrderedFRM,buf_1FRMANS,32) != 0)
	{
		printk("\r\n error comp sha result 1");
		printk("\r\n expeced");
		printbyte(buf_1FRMANS,32);
		printk("\r\n result");
		printbyte(buf_1FRMANS_REOrderedFRM,32);			
	}
	else
	{
		printk("\r\n SHA COMP PASS");
	}
#endif
	j = 63;	
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buf_1FRM[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	j = 31;
	for( i = 0; i < 32; i++)
	{
		buf_1FRMANS_REOrderedFRM[i] =  rx_data[j--];
	}
#ifdef TEST_MODE		
	if(memcmp(buf_1FRMANS_REOrderedFRM,buf_1FRMANS,32) != 0)
	{
		printk("\r\n error comp sha result 2");
		printk("\r\n expeced");
		printbyte(buf_1FRMANS,32);
		printk("\r\n result");
		printbyte(buf_1FRMANS_REOrderedFRM,32);			
		success = 0;
	}
	else
	{
		printk("\r\n SHA COMP PASS");
	}
#endif
	printk("\r\nSHA 1Frame TEST");
	printk("\r\nINPUT");
	printbyte(buf_1FRM,64);
	printk("\r\nExpected Result");
	printbyte(buf_1FRMANS,32);	
	printk("\r\nResult");
	printbyte(buf_1FRMANS_REOrderedFRM,32);	
	
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	endOP();
	return success;
#endif
}

int SHA_2Frame_TEST()
{
#ifdef COMPARE

	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char buf_2_1FRM[64];
	unsigned char buf_2_2FRM[64];
	unsigned char buf2FRMANS[32];
	unsigned char buf_2FRMANS_REOrderedFRM[32];
	int i = 0;
	int j = 0;
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	
	printk("\r\n[NOTE] ----  , SHA_1Frame_TEST --------\r\n");
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	hexstr2bytes("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70718000000000000000", buf_2_1FRM);
	hexstr2bytes("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0", buf_2_2FRM);	
	hexstr2bytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",buf2FRMANS);
	tx_data[0] = 2;
	tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x6;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE					, NULL, NULL, NULL, NULL, tx_data, rx_data, 1); 
    tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	j = 63;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buf_2_1FRM[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	tx_data[0] = 3;
	tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 63;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buf_2_2FRM[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	j = 31;
	for( i = 0; i < 32; i++)
	{
		buf_2FRMANS_REOrderedFRM[i] =  rx_data[j--];
	}
#ifdef TEST_MODE	
	if(memcmp(buf_2FRMANS_REOrderedFRM,buf2FRMANS,32) != 0)
	{
		printk("\r\n error comp sha result 1");
		printk("\r\n expeced");
		printbyte(buf2FRMANS,32);
		printk("\r\n result");
		printbyte(buf_2FRMANS_REOrderedFRM,32);			
		success = 0;
	}
	else
	{
		printk("\r\n SHA COMP PASS");
	}
#endif
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	endOP();
	printk("\r\nSHA 2Frame TEST");
	printk("\r\nINPUT");
	printbyte(buf_2_1FRM,64);
	printbyte(buf_2_2FRM,64);	
	printk("\r\nExpected Result");
	printbyte(buf2FRMANS,32);	
	printk("\r\nResult");
	printbyte(buf_2FRMANS_REOrderedFRM,32);		
	return success;
#endif
}


int SHA_4Frame_TEST()
{
#ifdef COMPARE

	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char buf_4_1FRM[64];
	unsigned char buf_4_2FRM[64];
	unsigned char buf_4_3FRM[64];
	unsigned char buf_4_4FRM[64];
		
	unsigned char buf4FRMANS[32];
	unsigned char buf_4FRMANS_REOrderedFRM[32];
	int i = 0;
	int j = 0;
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	
	printk("\r\n[NOTE] ----  , SHA_1Frame_TEST --------\r\n");
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	hexstr2bytes("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70716162636462636465", buf_4_1FRM);
	hexstr2bytes("636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f707161626364626364656364656664656667", buf_4_2FRM);	
	hexstr2bytes("65666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70716162636465666768696a6b6c6d6e6f707172737475767778", buf_4_3FRM);
	hexstr2bytes("79800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000608", buf_4_4FRM);	
	hexstr2bytes("79cfbf8f2dcee44679dd993aab66d6d6ec99e4769c4e53abec300d958a1241ef",buf4FRMANS);
	tx_data[0] = 2;
	tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x6;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE					, NULL, NULL, NULL, NULL, tx_data, rx_data, 1); 
    tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	j = 63;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buf_4_1FRM[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	Delay_us(10);

		j = 63;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buf_4_2FRM[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	Delay_us(10);

		j = 63;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buf_4_3FRM[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	Delay_us(10);

	
	tx_data[0] = 3;
	tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 63;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buf_4_4FRM[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	j = 31;
	for( i = 0; i < 32; i++)
	{
		buf_4FRMANS_REOrderedFRM[i] =  rx_data[j--];
	}
#ifdef TEST_MODE	
	if(memcmp(buf_4FRMANS_REOrderedFRM,buf4FRMANS,32) != 0)
	{
		printk("\r\n error comp sha result 1");
		printk("\r\n expeced");
		printbyte(buf4FRMANS,32);
		printk("\r\n result");
		printbyte(buf_4FRMANS_REOrderedFRM,32);			
		success = 0;
	}
	else
	{
		printk("\r\n SHA COMP PASS");
	}
#endif	
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	endOP();
	printk("\r\nSHA 4Frame TEST");
	printk("\r\nINPUT");
	printbyte(buf_4_1FRM,64);
	printbyte(buf_4_2FRM,64);
	printbyte(buf_4_3FRM,64);
	printbyte(buf_4_4FRM,64);	
	
	printk("\r\nExpected Result");
	printbyte(buf4FRMANS,32);	
	printk("\r\nResult");
	printbyte(buf_4FRMANS_REOrderedFRM,32);	
	return success;
#endif
}


int SHA_RANDOM_TEST()
{
#ifdef COMPARE

	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char result_sw[32]; 
	unsigned char buffer[64];
	unsigned char buf_1FRM[64];
	unsigned char buf_1FRMANS[64];
	unsigned char buf_1FRMANS_REOrderedFRM[64];
	int i = 0;
	int j = 0;
	int ByteNo = 0;

	memset(tx_data,0,64);
	memset(rx_data,0,64);
	memset(buffer,0,64);
	printk("\r\n[NOTE] ----  , SHA_1Frame_TEST --------\r\n");
	ByteNo = 55;
	for ( i=0; i<ByteNo; i++ )
	{
		buffer[i] = rand() & 0x7E;
		if ( buffer[i] == 0x00 ) buffer[i] = 0x01;
	}
	
	buffer[ByteNo] = 0x80;
	buffer[62] = 0x01;
	buffer[63] = 0xB8;

	MCU_SHA256_EXE(buffer, result_sw, ByteNo);
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x6;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE					, NULL, NULL, NULL, NULL, tx_data, rx_data, 1); 
    tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	j = 63;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] =  buffer[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	j = 31;
	for( i = 0; i < 32; i++)
	{
		buf_1FRMANS_REOrderedFRM[i] =  rx_data[j--];
	}
#ifdef TEST_MODE	
	if(memcmp(buf_1FRMANS_REOrderedFRM,result_sw,32) != 0)
	{
		printk("\r\n error comp sha result 1");
		printk("\r\n expeced");
		printbyte(result_sw,32);
		printk("\r\n result");
		printbyte(buf_1FRMANS_REOrderedFRM,32);			
		success = 0;
	}
	else
	{
		printk("\r\n SHA COMP RANDOM PASS");
	}
#endif	
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	endOP();

	printk("\r\nSHA 1Frame RANDOM TEST");
	printk("\r\nINPUT");
	printbyte(buffer,64);
	
	printk("\r\nExpected Result");
	printbyte(result_sw,32);	
	printk("\r\nResult");
	printbyte(buf_1FRMANS_REOrderedFRM,32);		
	return success;
#endif
}


int SHA_4FRAME_RANDOM_TEST()
{
#ifdef COMPARE

	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char buf_4_1FRM[64];
	unsigned char buf_4_2FRM[64];
	unsigned char buf_4_3FRM[64];
	unsigned char buf_4_4FRM[64];
	unsigned char buffer[256];
	unsigned char result_sw[32]; 
	int ByteNo = 193;	
	unsigned char buf4FRMANS[32];
	unsigned char buf_4FRMANS_REOrderedFRM[32];
	int i = 0;
	int j = 0;
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	
	printk("\r\n[NOTE] ----  , SHA_1Frame_TEST --------\r\n");
	memset(tx_data,0,64);
	memset(rx_data,0,64);
	memset(buffer,0,256);
//	hexstr2bytes("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70716162636462636465", buf_4_1FRM);
//	hexstr2bytes("636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f707161626364626364656364656664656667", buf_4_2FRM);	
//	hexstr2bytes("65666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70716162636465666768696a6b6c6d6e6f707172737475767778", buf_4_3FRM);
	
	for ( i=0; i<ByteNo; i++ )
	{
		buffer[i] = rand() & 0x7E;
		if ( buffer[i] == 0x00 ) buffer[i] = 0x01;
	}
	buffer[ByteNo] = 0x80;
	buffer[254] = 0x06;
	buffer[255] = 0x08;
	MCU_SHA256_EXE(buffer, result_sw, ByteNo);

//	hexstr2bytes("79800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000608", buf_4_4FRM);	
//	hexstr2bytes("79cfbf8f2dcee44679dd993aab66d6d6ec99e4769c4e53abec300d958a1241ef",buf4FRMANS);
	tx_data[0] = 2;
	tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x6;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE					, NULL, NULL, NULL, NULL, tx_data, rx_data, 1); 
    tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	j = 63;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buffer[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	Delay_us(10);

	j = 127;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buffer[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	Delay_us(10);

	j = 191;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buffer[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	Delay_us(10);

	
	tx_data[0] = 3;
	tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	j = 255;
	for( i = 0; i < 64; i++)
	{
		tx_data[i] = buffer[j--];
	}
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
	
	Delay_us(10);
	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	j = 31;
	for( i = 0; i < 32; i++)
	{
		buf_4FRMANS_REOrderedFRM[i] =  rx_data[j--];
	}
	if(memcmp(buf_4FRMANS_REOrderedFRM,result_sw,32) != 0)
	{
		printk("\r\n error comp sha result 1");
		printk("\r\n expeced");
		printbyte(result_sw,32);
		printk("\r\n result");
		printbyte(buf_4FRMANS_REOrderedFRM,32);			
		success = 0;
	}
	else
	{
		printk("\r\n SHA COMP PASS");
	}
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	endOP();

	printk("SHA 4Frame RANDOM TEST");
	printk("\r\nINPUT");
	printbyte(buffer,64);
	printbyte(buffer+64,64);
	printbyte(buffer+64+64,64);
	printbyte(buffer+64+64+64,64);	
	
	printk("Expected Result");
	printbyte(result_sw,32);	
	printk("\r\nResult");
	printbyte(buf_4FRMANS_REOrderedFRM,32);	
	return success;
#endif
}



int NumOfIterSHA256 = 1;
void SHA_Test_Main(void)
{
#ifdef COMPARE

	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	SHA_Test_Main_START:
	while(1)
	{
		temp = 'z' ;

		printk("\r\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  *            SHA    TEST MAIN                      *");
		printk("\r\n  *****************************************************");
		printk("\r\n  * number of iteration     %d                        *",NumOfIterSHA256 );
		printk("\r\n  * i. Input number of iteration                      *");
		printk("\r\n  * 1. SHA 256 1 frame (TV061001) 					*");	
		printk("\r\n  * 2. SHA 256 2 frame (TV061002)                     *");
		printk("\r\n  * 3. SHA 256 4 frame (TV061003)                       *");			
		printk("\r\n  * 4. SHA 256 RANDOM PATTERN   INPUT 440bit OUTPUT 256 bit *");			
		printk("\r\n  * 5. SHA 256 RANDOM PATTERN   INPUT 1544bit OUTPUT 256 bit *");					
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n  * m. return to top menu                             *");			
		printk("\r\n");

		printk("\r\n");
		printk("\r\n  * Select : ");

		while(temp == 'z')
		{
			int HitCnt = 0;
			int MissCnt = 0;
			temp = _uart_get_char();

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");
			if(temp == 0x0d)
				goto SHA_Test_Main_START;
			if( temp == 'm')
				return;

			switch ( temp )
			{
			case 'i' : 
				printk("\r\n input number of iteration : (4digit)");
				printk("\r\n 0x");
				NumOfIterSHA256 = get_int();
				NumOfIterSHA256 =( NumOfIterSHA256<<8)| get_int();		 
				break;
				case '5':
						printk("\r\n SHA RANDOM TEST BEGIN");
						for(i = 0; i < NumOfIterSHA256;i++)
						{
		
							START;
							iResult = SHA_4FRAME_RANDOM_TEST();
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								END;
								PrintCnt(HitCnt,MissCnt,NumOfIterSHA256);
								goto SHA_Test_Main_START;
#endif
							}
							else
							{
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumOfIterSHA256);
				
					   break;				
				case '4':
						printk("\r\n SHA RANDOM TEST BEGIN");
						for(i = 0; i < NumOfIterSHA256;i++)
						{
		
							START;
							iResult = SHA_RANDOM_TEST();
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								END;
								PrintCnt(HitCnt,MissCnt,NumOfIterSHA256);
								goto SHA_Test_Main_START;
#endif
							}
							else
							{
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumOfIterSHA256);
				
					   break;
				case '3' : 
						printk("\r\n SHA_4Frame_TEST TEST BEGIN");
						for(i = 0; i < NumOfIterSHA256;i++)
						{
		
							START;
							iResult = SHA_4Frame_TEST();
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								END;
								PrintCnt(HitCnt,MissCnt,NumOfIterSHA256);
								goto SHA_Test_Main_START;
#endif
							}
							else
							{
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumOfIterSHA256);
						break;

			case '2' : 
				printk("\r\n SHA_2Frame_TEST TEST BEGIN");
				for(i = 0; i < NumOfIterSHA256;i++)
				{

					START;
					iResult = SHA_2Frame_TEST();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterSHA256);
						goto SHA_Test_Main_START;
#endif
					}
					else
					{
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumOfIterSHA256);
				break;
				case '1' : 
				printk("\r\n SHA_1Frame_TEST TEST BEGIN");
				for(i = 0; i < NumOfIterSHA256;i++)
				{

					START;
					iResult = SHA_1Frame_TEST();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterSHA256);
						goto SHA_Test_Main_START;
#endif
					}
					else
					{
						HitCnt++;
					}
					END;

				}
				
				PrintCnt(HitCnt,MissCnt,NumOfIterSHA256);
				break;
		
			default : temp = 'p'; break;			
			}

		}
	}
	#endif
}

void SetRegister(unsigned char *addr, unsigned char val)
{


	unsigned char tx_data[64];
	unsigned char rx_data[64];
	tx_data[0] = val;

	tspi_interface(cs, ADDR_NOR_W,addr  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

}

unsigned char ReadRegister(unsigned char *addr)
{
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	
	tspi_interface(cs, ADDR_NOR_R,addr	, NULL, NULL, NULL, NULL, tx_data, rx_data, 1); 
	return rx_data[0];
}

void SPI2_Test_Main(void)
{
#ifdef COMPARE

	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	unsigned char addr[2];
	unsigned char val;
	SHA_Test_Main_START:
	while(1)
	{
		temp = 'z' ;

		printk("\r\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  *            SHA    TEST MAIN                      *");
		printk("\r\n  *****************************************************");
		printk("\r\n  * i. Input number of iteration                      *");
		printk("\r\n  * 1. RG_BT_LOGIC_SEL 								  *");	
		printk("\r\n  * 2. READ XXX REGISTER                     *");
		printk("\r\n  * 3. WRITE XXX REGISTER                     *");
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n  * m. return to top menu                             *");			
		printk("\r\n");

		printk("\r\n");
		printk("\r\n  * Select : ");

		while(temp == 'z')
		{
			int HitCnt = 0;
			int MissCnt = 0;
			temp = _uart_get_char();

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");
			if(temp == 0x0d)
				goto SHA_Test_Main_START;
			if(temp == 'm')
			{
				printk("\r\nm is pressed");
				return;
			}

			switch ( temp )
			{

				case '1':
				SetRegister(RG_BT_LOGIC_SEL,0x0C);
					   break;				
				printk("\r\n READ VAL %02x",ReadRegister(RG_BT_LOGIC_SEL));				
				case '2':
					printk("\r\nMSB:0x");
					addr[0] = get_int();
					printk("\r\nLSB:0x");				
					addr[1] = get_int();
				printk("\r\n READ VAL %02x",ReadRegister(addr));
					   break;
				case '3':
					printk("\r\nMSB:0x");
					addr[0] = get_int();
					printk("\r\nLSB:0x");				
					addr[1] = get_int();
					printk("\r\nVALUE:0x");
					val = get_int();
					SetRegister(addr,val);
					printk("\r\n READ VAL %02x",ReadRegister(addr));					
					   break;
				
				break;
		
			default : temp = 'p'; break;			
			}

		}
	}
#endif
}



int NumOfIterTwoFrame = 1;
void Two_Frame_Test_Main(void)
{
#ifdef COMPARE

	unsigned char temp ;
	int i = 0;
	int iResult = 0;
Two_Frame_Test_Main_START:
	while(1)
	{
		temp = 'z' ;

		printk("\r\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  *            TWO FRAME     TEST MAIN                      *");
		printk("\r\n  *****************************************************");
		printk("\r\n  * number of iteration     %d                        *",NumOfIterTwoFrame );
		printk("\r\n  * i. Input number of iteration                      *");
		printk("\r\n  * 1. AES 128 two frame (TV092002 ) (TAESM101_S)                       *");	
		printk("\r\n  * 2. AES 256 two frame (TAESM201_S)                     *");
		printk("\r\n  * 3. ARIA 128 two frame  (TARIAM101_S)                       *");			
		printk("\r\n  * 4. ARIA 256 two frame  (TARIAM201_S)                       *");					
		printk("\r\n  -----------------------------------------------------");
		printk("\r\n  * m. return to top menu                             *");			
		printk("\r\n");

		printk("\r\n");
		printk("\r\n  * Select : ");

		while(temp == 'z')
		{
			int HitCnt = 0;
			int MissCnt = 0;
			temp = _uart_get_char();

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");
			if(temp == 0x0d)
				goto Two_Frame_Test_Main_START;
			if(temp == 'm')
			{
				printk("\r\nm is pressed");
				SetKEYNormal();
				return;
			}

			switch ( temp )
			{
			case 'i' : 
				printk("\r\n input number of iteration : (4digit)");
				printk("\r\n 0x");
				NumOfIterTwoFrame = get_int();
				NumOfIterTwoFrame =( NumOfIterTwoFrame<<8)| get_int();		 
				break;

			case '2' : 
				printk("\r\n TwoFrameTest256 TEST BEGIN");
				for(i = 0; i < NumOfIterTwoFrame;i++)
				{
					//	iResult = OKA_Test();
					START;
					iResult = TwoFrameTest256();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterTwoFrame);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n TwoFrameTest256 TEST END");
				SetKEYNormal();
				PrintCnt(HitCnt,MissCnt,NumOfIterTwoFrame);


				break;
			case '1' :
				printk("\r\n TwoFrameTest128 TEST START");
				for(i = 0; i < NumOfIterTwoFrame;i++)
				{
					START;
					iResult = TwoFrameTest();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterTwoFrame);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n TwoFrameTest128 TEST END");				
				SetKEYNormal();
				PrintCnt(HitCnt,MissCnt,NumOfIterTwoFrame);
				break; 

			case '3' :
				printk("\r\n TwoFrameTest128 ARIATEST START");
				for(i = 0; i < NumOfIterTwoFrame;i++)
				{
					START;
					iResult = TwoFrameTestARIA();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterTwoFrame);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n TwoFrameTest128 ARIATEST TEST END");	
				SetKEYNormal();
				PrintCnt(HitCnt,MissCnt,NumOfIterTwoFrame);
				break; 


			case '4' :
				printk("\r\n TwoFrameTest256 ARIATEST START");
				for(i = 0; i < NumOfIterTwoFrame;i++)
				{
					START;
					iResult = TwoFrameTest256ARIA();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumOfIterTwoFrame);
						goto L_Start_block;
#endif
					}
					else
					{
						printk("   PASS");

						HitCnt++;
					}
					END;
				}
				printk("\r\n TwoFrameTest256 ARIATEST TEST END");				
				SetKEYNormal();
				PrintCnt(HitCnt,MissCnt,NumOfIterTwoFrame);
				break; 

			default : temp = 'p'; break;			
			}

		}
	}
#endif
}

#ifdef COMPARE

void INIT_KEY(unsigned char *KEY, int mode)
{
	unsigned char KEY32[32] ;
	
	if(mode == MODE128) //128
	{	
		printk("\r\n ================================== KEY SETTING================================== ");
		memset(KEY32,0,32);
		//hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32+16);
		memcpy(&KEY32[16], KEY,16 );
		KEY_SET(KEY32);
	}
	else//256
	{
		// 603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4
		//hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
		//hexstr2bytes("603deb1015ca71be2b73aef0857d7781", KEY32+16);	
		memcpy(KEY32,&KEY[16],16);
		memcpy(&KEY32[16],KEY,16);
		KEY_SET(KEY32);
	}

}
void INIT_AES_CBC(unsigned char *IV, int AES_OPMODE,int RG_128_256,int AES_ARIA)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];	   
	int success = 1;

	tx_data[0] = 0x0;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 
		(AES_OPMODE<<4)|
		(RG_128_256<<1)|
		AES_ARIA;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	memcpy(tx_data,IV,16);
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	delay_us(30);
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////

}

void ENC_DATA(unsigned char *PLAINTEXT, unsigned char *CYPERTEXT)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	
	memcpy(tx_data,PLAINTEXT,16);
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(20);	
	
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	memcpy(CYPERTEXT,rx_data,16);
}

void DEC_DATA(unsigned char *PLAINTEXT, unsigned char *CYPERTEXT)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	
	memcpy(tx_data,CYPERTEXT,16);
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(20);	
	
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	memcpy(PLAINTEXT,rx_data,16);
}

void TEST_AES_CBC_128(void)
{
	unsigned char CTS_PT[16*4];
	unsigned char PLAIN_TEXT[16*4];
	unsigned char PLAIN_TEXT_REV[16*4];

	unsigned char CTS_CT[16*4];	
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPTER_TEXT[16*4];
	unsigned char CYPTER_TEXT_REV[16*4];	
	

	unsigned char IV[16];
	
	unsigned char IV_REV[16];	
	unsigned char DEC_PT[16*4];
	unsigned char KEY32[32] ;
	int i;
	int j;
	int k;
//	TAESM110_S();

	printk("\r\n ================================== TEST_AES_CBC_128================================== ");
	hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32);
	INIT_KEY(KEY32,MODE128);	
//	memset(KEY32,0,32);
//	hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32+16);
//	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", PLAIN_TEXT);
	hexstr2bytes("7649abac8119b246cee98e9b12e9197d4cbbc858756b358125529e9698a38f449f6f0796ee3e47b0d87c761b20527f78070134085f02751755efca3b4cdc7d62", ENC_PLAIN_TEXT);			
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	memcpy(CTS_PT,PLAIN_TEXT,16*4);
	memcpy(CTS_CT,ENC_PLAIN_TEXT,16*4);
	
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPTER_TEXT_REV[i+j] = CYPTER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15; 	
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	INIT_AES_CBC(IV_REV, MODE_CBC, RG_128,RG_AES);
	memset(CYPTER_TEXT_REV,0,64);
	memset(CYPTER_TEXT,0,64);
	for( i = 0; i < 64; i += 16)
	{
		WHEREAMI();
		ENC_DATA(&PLAIN_TEXT_REV[i], &CYPTER_TEXT_REV[i]);
		j = 15;			
		for(k = 0; k < 16; k++)
		{
			CYPTER_TEXT[i+k] = CYPTER_TEXT_REV[i+j--];
		}
		if(memcmp(&CYPTER_TEXT[i],&CTS_CT[i],16) != 0)
		{
				printk("\r\n CBC ENC TEST ERROR %d",i);
		}
		else
			printk("\r\n CBC ENC TEST SUCCESS");	
	}

	END_OPERATION();

	memset(PLAIN_TEXT_REV,0,64);
	memset(DEC_PT,0,64);
	printk("\r\n DEC TEST \r\n");
	INIT_AES_CBC(IV_REV, MODE_CBC, RG_128,RG_AES);
	for( i = 0; i < 64; i += 16)
	{
#if 1
		WHEREAMI();
		DEC_DATA(&PLAIN_TEXT_REV[i],&ENC_PLAIN_TEXT_REV[i]);
		WHEREAMI();
		j = 15;		
		for(k = 0; k < 16; k++)
		{
			DEC_PT[i+k] = PLAIN_TEXT_REV[i+j--];
		}		
		if(memcmp(&CTS_PT[i],&DEC_PT[i],16) != 0)
			printk("\r\n CBC DEC TEST ERROR %d",i);		
		else
			printk("\r\n CBC DEC TEST SUCCESS");		
		WHEREAMI();
#endif
	}

	END_OPERATION();
	
}

void TEST_AES_CBC_256(void)
{
	unsigned char CTS_PT[16*4];
	unsigned char PLAIN_TEXT[16*4];
	unsigned char PLAIN_TEXT_REV[16*4];

	unsigned char CTS_CT[16*4];	
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPTER_TEXT[16*4];
	unsigned char CYPTER_TEXT_REV[16*4];	
	

	unsigned char IV[16];
	
	unsigned char IV_REV[16];	
	unsigned char DEC_PT[16*4];
	unsigned char KEY32[32] ;
	int i;
	int j;
	int k;
//	TAESM110_S();

	printk("\r\n ================================== TEST_AES_CBC_256================================== ");
	hexstr2bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", KEY32);
	INIT_KEY(KEY32,MODE256);	
//	memset(KEY32,0,32);
//	hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32+16);
//	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", PLAIN_TEXT);
	hexstr2bytes("f58c4c04d6e5f1ba779eabfb5f7bfbd6eb2d9e942831bd84dff00db9776b808825e80f72637337ae724abd9275366147e6ecc6346cd9151fa25d1afec9bb66b1", ENC_PLAIN_TEXT);			
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	memcpy(CTS_PT,PLAIN_TEXT,16*4);
	memcpy(CTS_CT,ENC_PLAIN_TEXT,16*4);
	
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPTER_TEXT_REV[i+j] = CYPTER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15; 	
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	INIT_AES_CBC(IV_REV, MODE_CBC, RG_256,RG_AES);
	memset(CYPTER_TEXT_REV,0,64);
	memset(CYPTER_TEXT,0,64);
	for( i = 0; i < 64; i += 16)
	{
		WHEREAMI();
		ENC_DATA(&PLAIN_TEXT_REV[i], &CYPTER_TEXT_REV[i]);
		j = 15;			
		for(k = 0; k < 16; k++)
		{
			CYPTER_TEXT[i+k] = CYPTER_TEXT_REV[i+j--];
		}
		if(memcmp(&CYPTER_TEXT[i],&CTS_CT[i],16) != 0)
		{
				printk("\r\n CBC ENC TEST ERROR %d",i);
		}
		else
			printk("\r\n CBC ENC TEST SUCCESS");	
	}

	END_OPERATION();

	memset(PLAIN_TEXT_REV,0,64);
	memset(DEC_PT,0,64);
	printk("\r\n DEC TEST \r\n");
	INIT_AES_CBC(IV_REV, MODE_CBC, RG_256,RG_AES);
	for( i = 0; i < 64; i += 16)
	{
#if 1
		WHEREAMI();
		DEC_DATA(&PLAIN_TEXT_REV[i],&ENC_PLAIN_TEXT_REV[i]);
		WHEREAMI();
		j = 15;		
		for(k = 0; k < 16; k++)
		{
			DEC_PT[i+k] = PLAIN_TEXT_REV[i+j--];
		}		
		if(memcmp(&CTS_PT[i],&DEC_PT[i],16) != 0)
			printk("\r\n CBC DEC TEST ERROR %d",i);		
		else
			printk("\r\n CBC DEC TEST SUCCESS");		
		WHEREAMI();
#endif
	}

	END_OPERATION();
	
}


int OPERATION_MODE_ENC(unsigned char *IV,unsigned char *PLAINTEXT,unsigned char *CYPERTEXT, int AES_OPMODE,int RG_128_256,int AES_ARIA)
{

	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];	   
	int success = 1;

	tx_data[0] = 0x0;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 
		(AES_OPMODE<<4)|
		(RG_128_256<<1)|
		AES_ARIA;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	memcpy(tx_data,IV,16);
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	delay_us(30);
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////

	for( i = 0; i < 4; i++)
	{
		memcpy(tx_data,PLAINTEXT+i*16,16);
		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	

		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
		if( memcmp(rx_data,CYPERTEXT+i*16,16) != 0)
		{
			success = 0;
			printk("\r\n FAIL TO TEST TV");
			printk("\r\n rx_data\r\n");
			printbyte(rx_data,16);
			printk("\r\n CYPERTEXT \r\n");
			printbyte(CYPERTEXT+i*16,16);			
		}
		else
		{
			printk("\r\n PASS ");
		}
	}
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		
	endOP();
	return success;
}

int OPERATION_MODE_DEC(unsigned char *IV,unsigned char *PLAINTEXT,unsigned char *CYPERTEXT, int AES_OPMODE,int RG_128_256,int AES_ARIA)
{

	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];	   
	int success = 1;

	tx_data[0] = 0x0;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 
		(AES_OPMODE<<4)|
		(RG_128_256<<1)|
		AES_ARIA;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	memcpy(tx_data,IV,16);
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	delay_us(30);
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////

	for( i = 0; i < 4; i++)
	{
		memcpy(tx_data, CYPERTEXT+i*16,16);
		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	

		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
		if( memcmp(rx_data,PLAINTEXT+i*16,16) != 0)
		{
			success = 0;
			printk("\r\n FAIL TO TEST TV");
			printk("\r\n rx_data\r\n");
			printbyte(rx_data,16);
			printk("\r\n PLAINTEXT \r\n");
			printbyte(PLAINTEXT+i*16,16);			
		}
		else
		{
			printk("\r\n PASS ");
		}
	}
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);		
	endOP();
	return success;
}
#endif
void KEY_SET(unsigned char *KEY)
{		
	KeyLoadDemo2(0,0,0,0,KEY,MODE256);

}
int NumOfIterTestAll = 1;
void KEY_LOAD()
{
					
	unsigned char seedkey[64];
	int i = 0;
	memset(seedkey,0x11,64);
	eep_page_write(0xec, 0x00,seedkey, 1);
	
	for(i = 5; i >= 0; i--)
	{
		if(i == RG_PERM_SUPER_PASS )
			printk("\r\n  * 0. Supper Permission KEY                                              *");	
		if(i == RG_PERM_DETOUR_PASS )
			printk("\r\n  * 1. DETOUR Permission KEY                                              *");	
		if(i == RG_PERM_DESTORY0_PASS )
			printk("\r\n  * 2. DESTORY0 Permission KEY                                              *");	
		if(i== RG_PERM_DESTORY1_PASS)
			printk("\r\n  * 3. DESTORY1 Permission KEY                                              *");	
		if(i == RG_PERM_EEPROM_PASS)
			printk("\r\n  * 4. EEPROM Permission KEY                                              *");	
		if(i == RG_PERM_UID_PASS )
			printk("\r\n  * 5. UID Permission KEY                                              *");	
		if(SAVE_KEY_REVERSE(i) == 0)
		{
			PRINTLOG("\r\n LOAD KEY FAIL %d",i);
			if(i == RG_PERM_SUPER_PASS)
				printk("\r\n  * 0. Supper Permission KEY                                              *");	
			if(i == RG_PERM_DETOUR_PASS)
				printk("\r\n  * 1. DETOUR Permission KEY                                              *");	
			if(i == RG_PERM_DESTORY0_PASS)
				printk("\r\n  * 2. DESTORY0 Permission KEY                                              *");	
			if(i== RG_PERM_DESTORY1_PASS)
				printk("\r\n  * 3. DESTORY1 Permission KEY                                              *");	
			if(i == RG_PERM_EEPROM_PASS)
				printk("\r\n  * 4. EEPROM Permission KEY                                              *");	
			if(i == RG_PERM_UID_PASS)
				printk("\r\n  * 5. UID Permission KEY                                              *");	
		}
	}


}
#ifdef COMPARE

void EEPROM_TEST_1_0()
{


	int i;
	int j;
	int k = 0;
	unsigned char temp;
	unsigned char w_data[1];
	int iResult = 0;
	int HitCnt = 0;
	int MissCnt = 0;
	unsigned char data_buf[64];

	printk("\r\n 1.0 EEPROM TEST BEGIN");
	printk("\r\n     all pages random value 64bytes wrtie & read test ");
	for(j = 0; j <= 0xffc0 ; j += 64)
	{
		int MSB = (j >> 8) & 0xFF;
		int LSB = j & 0xFF;
		START;
		srand(j);
		for(k = 0; k < 64; k++)
		{
			data_buf[k] = rand()&0xFF;
		}
		iResult = eep_page_write(MSB, LSB,data_buf, 1);
		printk("\r\n END of %dth iteration",k++);
		if(iResult == 0)
		{
			MissCnt++;printk("   FAIL");
#if ERROR_EXIT

			PrintCnt(HitCnt,MissCnt,MissCnt+MissCnt);
			goto L_Start_block;
#endif
		}
		else
		{
			printk("   PASS");
			HitCnt++;
		}
		END;
	}
	PrintCnt(HitCnt,MissCnt,MissCnt+MissCnt);
		
}
void RENDOM_TEST_2_0()
{
	printk("\r\n 2.0 RENDOM TEST BEGIN");
	GetRND();
}

void OKA_TEST_3_0()
{
	int cnt = 1;
	unsigned char temp ;
	int i = 0;
	int k = 0;
	int iResult = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	int HitCnt = 0;
	int MissCnt = 0;
	printk("\r\n 3.0 OKA TEST BEGIN");
	memset(tx_data,0,64);
	tx_data[4] = 0x02;
	printk("\r\n	tx_data[4] = 0x02;");
	eep_page_write(0xEB,0x40, tx_data, 1);
	OKAisFirst = 0;
	for( k= 0; k <= 5; k++ )
	{
	HitCnt = 0;
	MissCnt = 0;
	switch ( k )
	{
	case 1 : 
		printk("\r\n OKA ONE FRAME TEST BEGIN");
		for(i = 0; i < NumofIterAll;i++)
		{
			//	iResult = OKA_Test();
			START;
			iResult = OKA_Test_0613();
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
				MissCnt++;FAIL;
#if ERROR_EXIT

				END;
				PrintCnt(HitCnt,MissCnt,cnt);
				goto L_Start_block;
#endif
			}
			else
			{
				printk("   PASS");

				HitCnt++;
			}
			END;
		}
		printk("\r\n OKA ONE FRAME TEST END");
		PrintCnt(HitCnt,MissCnt,cnt);


		break;
	case 2 :
		printk("\r\n OKA TWO FRAME TEST START");
		for(i = 0; i < NumofIterAll;i++)
		{
			START;
			iResult = OKA_Test2_0613();
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
				MissCnt++;FAIL;
#if ERROR_EXIT

				END;
				PrintCnt(HitCnt,MissCnt,cnt);
				goto L_Start_block;
#endif
			}
			else
			{
				printk("   PASS");

				HitCnt++;
			}
			END;
		}
		printk("\r\n OKA TWO FRAME TEST END");				
		PrintCnt(HitCnt,MissCnt,cnt);
		break; 


	case 3:
		printk("\r\n OKA SW AND HW COWORK ONE FRAME TEST START");
		for(i = 0; i < NumofIterAll;i++)
		{
			//	iResult = OKA_Test();
			START;
			iResult = OKA_CTRL();
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
				MissCnt++;FAIL;
#if ERROR_EXIT

				END;
				PrintCnt(HitCnt,MissCnt,cnt);
				goto L_Start_block;
#endif
			}
			else
			{
				printk("   PASS");

				HitCnt++;
			}
			END;
		}
		printk("\r\n OKA SW AND HW COWORK ONE FRAME TEST END");
		PrintCnt(HitCnt,MissCnt,cnt);
		break;
	case 4:
		printk("\r\n OKA SW AND HW COWORK TWO FRAME TEST START");
		for(i = 0; i < NumofIterAll;i++)
		{
			//	iResult = OKA_Test();
			START;
			iResult = OKA_CTRL2Frame();
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
				MissCnt++;FAIL;
#if ERROR_EXIT

				END;
				PrintCnt(HitCnt,MissCnt,cnt);
				goto L_Start_block;
#endif
			}
			else
			{
				printk("   PASS");

				HitCnt++;
			}
			END;
		}
		printk("\r\n OKA SW AND HW COWORK TWO FRAME TEST END");
		PrintCnt(HitCnt,MissCnt,cnt);
		break;				
	case 5:
		printk("\r\n OKA_1FramePON_EE_OKA_OVERRIDE_1(); START");
		for(i = 0; i < NumofIterAll;i++)
		{
			START;
			iResult = OKA_1FramePON_EE_OKA_OVERRIDE_1();
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
				MissCnt++;FAIL;
#if ERROR_EXIT

				END;
				PrintCnt(HitCnt,MissCnt,cnt);
				goto L_Start_block;
#endif
			}
			else
			{
				printk("   PASS");

				HitCnt++;
			}
			END;
		}
		printk("\r\n OKA_1FramePON_EE_OKA_OVERRIDE_1(); END");				
		PrintCnt(HitCnt,MissCnt,cnt);				

		break;

		default : temp = 'p'; break;
		}
		}
}

void PERMISSION_TEST_4_0()
{
		unsigned char temp ;
		int i = 0;
		int iResult = 0;
		int j = 0;
		int k = 0;
	
		unsigned int inst = 0;
		int pass = 1;
		//unsigned char addr[2];
		unsigned char tx_data[64];
		unsigned char rx_data[64];
		int HitCnt,MissCnt;
		unsigned char temp_addr[2];
		unsigned char msb;
		unsigned char lsb;
		unsigned char Data[64];
		unsigned char perm_type;
		memset(Data,0,64);
L_Start_block:
		j = 15;
		for( i=16; i<32; i++)
			//for( i=0; i<16; i++)
		{
			tx_data[i] = 0x11;
		}
		//	unsigned char SUPER_PW_CT[16] = {0x0F,0x9C,0x00,0x4B,0x2C,0xB0,0x97,0xE6,0xF6,0x7A,0x8F,0x6F,0x34,0x76,0x11,0x17};
		pPW_CT[RG_PERM_SUPER_PASS ] = SUPER_PW_CT;
		pPW_CT[RG_PERM_DETOUR_PASS ] = DETOUR_PW_CT;
		pPW_CT[RG_PERM_DESTORY0_PASS ] = DESTROY0_PW_CT;
		pPW_CT[RG_PERM_DESTORY1_PASS] = DESTROY1_PW_CT;
		pPW_CT[RG_PERM_EEPROM_PASS] = EEPROM_PW_CT;
		pPW_CT[RG_PERM_UID_PASS] = UID_PW_CT;	
		//	SetKEYNormal();
		for(k = 1; k <= 13; k++)
		{
		HitCnt = 0;
		MissCnt = 0;
			switch(k)
				{
					case 1 : 
						printk("\r\n SUPER PERM TEST BEGIN");				
						for(i = 0; i < NumofIterAll;i++)
						{
							//for(j = 0; j < 6; j++)
							START;
							iResult = PERMISSION_TEST(RG_PERM_SUPER_PASS );
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								END;
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{
								printk("   PASS");
		
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						printk("\r\n SUPER PERM TEST END"); 			
						break;
					case 2 : 
						printk("\r\n DETOUR PERM TEST BEGIN");				
						for(i = 0; i < NumofIterAll;i++)
						{
							START;
							//for(j = 0; j < 6; j++)
							iResult =  PERMISSION_TEST(RG_PERM_DETOUR_PASS );
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
								END;
		
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{
								printk("   PASS");
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						printk("\r\n DETOUR PERM TEST END");				
						break;
					case 3 : 
						printk("\r\n DESTORY0 PERM TEST BEGIN");				
						for(i = 0; i < NumofIterAll;i++)
						{
							//for(j = 0; j < 6; j++)
							START;
							iResult =  PERMISSION_TEST(RG_PERM_DESTORY0_PASS );
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{
								printk("   PASS");
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						printk("\r\n DESTORY0 PERM TEST END");									
						break;
		
					case 4 : 
						printk("\r\n DESTORY1 PERM TEST BEGIN");														
						for(i = 0; i < NumofIterAll;i++)
						{
							//for(j = 0; j < 6; j++)
							START;
							iResult =  PERMISSION_TEST(RG_PERM_DESTORY1_PASS );
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								END;
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{
								printk("   PASS");
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);			
						printk("\r\n DESTORY1 PERM TEST END");														
						break;
					case 5 : 
						printk("\r\n EEPROM PERM TEST BEGIN");																			
						for(i = 0; i < NumofIterAll;i++)
						{
							//for(j = 0; j < 6; j++)
							START;
							iResult =  PERMISSION_TEST(RG_PERM_EEPROM_PASS );
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{
								printk("   PASS");
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);				
						printk("\r\n EEPROM PERM TEST END");																			
						break;	
					case 6 : 
						printk("\r\n UID PERM TEST BEGIN");
						for(i = 0; i < NumofIterAll;i++)
						{
							//for(j = 0; j < 6; j++ 																			
							START;
							iResult =  PERMISSION_TEST(RG_PERM_UID_PASS );
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
								END;
		
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{
								printk("   PASS");
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);				
						printk("\r\n UID PERM TEST END");																								
						break;			
						KEY_LOAD();
					case 7 :
						printk("\r\n SUPER PW CHANGE TEST BEGIN");				
						for(i = 0; i < NumofIterAll;i++)
						{		
							START;
							iResult = ChangePW(RG_PERM_SUPER_PASS );
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
								END;
		
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{
								printk("   PASS");
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						printk("\r\n SUPER PW CHANGE TEST END");																								
						break; 
					case 8 :
						printk("\r\n DETOUR PW CHANGE TEST BEGIN");
						for(i = 0; i < NumofIterAll;i++)
						{
							START;																				
							iResult = ChangePW(RG_PERM_DETOUR_PASS );
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
								END;
		
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{
								printk("   PASS");
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						printk("\r\n DETOUR PW CHANGE TEST END");																								
						break; 
					case 9 :
						printk("\r\n DESTORY0 PW CHANGE TEST BEGIN");
						for(i = 0; i < NumofIterAll;i++)
						{
							START;																				
							iResult =	ChangePW(RG_PERM_DESTORY0_PASS );
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
								END;		
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{
								printk("   PASS");
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						printk("\r\n DESTORY0 PW CHANGE TEST END"); 																							
						break; 
					case 10 :
						printk("\r\n DESTORY1 PW CHANGE TEST BEGIN");
						for(i = 0; i < NumofIterAll;i++)
						{
							START;																			
							iResult =  ChangePW(RG_PERM_DESTORY1_PASS );
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
#endif
							}
							else
							{
								printk("   PASS");
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						printk("\r\n DESTORY1 PW CHANGE TEST END"); 																							
						break; 
					case 11 :
						printk("\r\n EEPROM PW CHANGE TEST BEGIN"); 			
						for(i = 0; i < NumofIterAll;i++)
						{
							START;
							iResult =	ChangePW(RG_PERM_EEPROM_PASS );
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								END;
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{
								printk("   PASS");
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						printk("\r\n EEPROM PW CHANGE TEST END");																								
						break; 
					case 13 :
						printk("\r\n UID PW CHANGE TEST BEGIN");					
						for(i = 0; i < NumofIterAll;i++)
						{
							START;
							iResult = ChangePW(RG_PERM_UID_PASS);
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
								END;	
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{
								printk("   PASS");
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						printk("\r\n UID PW CHANGE TEST END");		
						KEY_LOAD();
						
						break;		
			}
		}

		for(perm_type = '0';perm_type <= '5';perm_type++ )
		{

		int select = 0;
		HitCnt = 0;
		MissCnt = 0;
		
						switch(perm_type)
						{
						case '0':
							select = RG_PERM_SUPER_PASS ;
							printk("\r\n SUPER GET AND RELEASE TEST BEGIN");
							break;
						case '1':
							select =RG_PERM_DETOUR_PASS ;
							printk("\r\n DETOUR GET AND RELEASE TEST BEGIN");							
							break;
						case '2':
							select = RG_PERM_DESTORY0_PASS ;
							printk("\r\n DESTORY0 GET AND RELEASE TEST BEGIN");														
							break;
						case '3':
							select =RG_PERM_DESTORY1_PASS ;
							printk("\r\n DESTORY1 GET AND RELEASE TEST BEGIN");																					
							break;
						case '4':
							select = RG_PERM_EEPROM_PASS;
							printk("\r\n EEPROM GET AND RELEASE TEST BEGIN");							
							break;
						case '5':
							select = RG_PERM_UID_PASS;
							printk("\r\n UID GET AND RELEASE TEST BEGIN");														
							break;
						case 'm':
							goto L_Start_block;
							break;
						}
						for(i = 0; i < NumofIterAll;i++)
						{		 
							//gPrintOut = 0;
							iResult = GetPermissionByPW(pPW_CT[select], select);
							//gPrintOut = 1;
							printk("\r\n END of %dth iteration!!!",i+1);

							if(ReleasePermision() == 0)
								iResult = 0;
							if(iResult == 0)
							{
								MissCnt++;
								printk("\r\n TEST FAIL");
#if ERROR_EXIT
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto L_Start_block;
#endif
							}
							else
							{

								printk("\r\n TEST PASS");
								HitCnt++;
							}

						} 
						PrintCnt(HitCnt,MissCnt,NumofIterAll);													
					
					switch(perm_type)
					{
					case '0':
						select = RG_PERM_SUPER_PASS ;
						printk("\r\n SUPER GET AND RELEASE TEST END");
						break;
					case '1':
						select =RG_PERM_DETOUR_PASS ;
						printk("\r\n DETOUR GET AND RELEASE TEST END");							
						break;
					case '2':
						select = RG_PERM_DESTORY0_PASS ;
						printk("\r\n DESTORY0 GET AND RELEASE TEST END");														
						break;
					case '3':
						select =RG_PERM_DESTORY1_PASS ;
						printk("\r\n DESTORY1 GET AND RELEASE TEST END");																					
						break;
					case '4':
						select = RG_PERM_EEPROM_PASS;
						printk("\r\n EEPROM GET AND RELEASE TEST END");							
						break;
					case '5':
						select = RG_PERM_UID_PASS;
						printk("\r\n UID GET AND RELEASE TEST END");														
						break;
					case 'm':
						goto L_Start_block;
						break;
				   }
	   }

}

void ShaAuth_5_0()
{
	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int j = 0;
	int HitCnt,MissCnt;
	
	for(temp = '1'; temp <= '2'; temp++)
	{
	HitCnt = 0;
	MissCnt = 0;
	switch ( temp )
				{
				case 'i' : 
					printk("\r\n input number of iteration : (4digit)");
					printk("\r\n 0x");
					NumOfIterSHA = get_int();
					NumOfIterSHA =( NumOfIterSHA<<8)| get_int();		 
					break;
	
				case '1' : 
					printk("r\n SHAAUTH_FROM_MCU");
					for(i = 0; i < NumofIterAll;i++)
					{
						//	iResult = OKA_Test();
						START;
						iResult = SHAAUTH_FROM_MCU();
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
	
							END;
							PrintCnt(HitCnt,MissCnt,HitCnt + NumofIterAll );
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
	
							HitCnt++;
						}
						END;
	
					}
					PrintCnt(HitCnt,MissCnt,NumofIterAll ); 			
					break ;
	
				case '2' :
					printk("r\n SHAAUTH_FROM_DORCA");
					for(i = 0; i < NumofIterAll;i++)
					{
						//	iResult = OKA_Test();
						START;
						iResult = SHAAUTH_FROM_DORCA();
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
	
							END;
							PrintCnt(HitCnt,MissCnt,NumofIterAll );
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
	
							HitCnt++;
						}
						END;
	
					}			
					PrintCnt(HitCnt,MissCnt,NumofIterAll ); 			
					break ;
	
				default :  break;
				}
		}

}
void DecWrite_6_0()
{
	int iResult = 0;
	int HitCnt = 0;
	int MissCnt = 0;
	int i = 0;
	//for(i = 0 ; i < NumofIterAll; i++)
	for(i = 0 ; i < 1; i++)
	{
		printk("\r\n AES256 DecWrite START");
		if(DecWrite(1) )//aes 256
			HitCnt++;
		else
		{
			MissCnt++;
			printk("\r\n TEST FAIL %d",__LINE__);
		}

		printk("\r\n AES256 DecWrite END");

		printk("\r\n AES128 DecWrite START");
		if(DecWrite(3) )//aes 256
			HitCnt++;
		else
		{
			MissCnt++;
			printk("\r\n TEST FAIL %d",__LINE__);
		}


		printk("\r\n AES128 DecWrite END");
		printk("\r\n ARIA256 DecWrite START");
		if(DecWrite(0) )//aes 256
			HitCnt++;
		else
		{
			MissCnt++;
			printk("\r\n TEST FAIL %d",__LINE__);
		}

		printk("\r\n ARIA256 DecWrite END");
		printk("\r\n ARIA28 DecWrite START");
		if(DecWrite(2) )//aes 256
			HitCnt++;
		else
		{
			MissCnt++;
			printk("\r\n TEST FAIL %d",__LINE__);
		}

		printk("\r\n ARIA128 DecWrite END");
		
/*						
		if(iResult == 4)
			PrintPASSFAIL(1);
		else
			PrintPASSFAIL(0);
*/							
	}
	PrintCnt(HitCnt,MissCnt,HitCnt+MissCnt);						
	//				VerifyAES();
	//				VerifyAES256();

}

void ReadEncAll_7_0()
{
		int iResult = 0;
		int HitCnt = 0;
		int MissCnt = 0;
		int i = 0;
		//for(i = 0 ; i < NumofIterAll; i++)
		for(i = 0 ; i < 1; i++)
		{
			
			printk("\r\n AES256 ReadEnc START");
			if(ReadEnc(1))
				HitCnt++;//aes 256
			else
				MissCnt++;
			printk("\r\n AES256 ReadEnc END");
			printk("\r\n AES128 ReadEnc START");
			if(ReadEnc(3))//aes 256
				HitCnt++;//aes 256
			else
				MissCnt++;					
			printk("\r\n AES128 ReadEnc END");
			printk("\r\n ARIA256 ReadEnc START");
			if(ReadEnc(0))//aes 256
				HitCnt++;//aes 256
			else
				MissCnt++;

			printk("\r\n ARIA256 ReadEnc END");
			printk("\r\n ARIA28 ReadEnc START");
			if(ReadEnc(2))//aes 256
				HitCnt++;//aes 256
			else
				MissCnt++;

			printk("\r\n ARIA128 ReadEnc END");
		}
		PrintCnt(HitCnt,MissCnt,HitCnt+MissCnt);
}

void TwoFrameTest_8_0()
{
	unsigned int temp ;
	int i = 0;
	int iResult = 0;
	int HitCnt;
	int MissCnt;
	for(temp = '1'; temp <= '4'; temp++ )
	{
	HitCnt =0;
	MissCnt =0;
	switch ( temp )
				{
				case 'i' : 
					printk("\r\n input number of iteration : (4digit)");
					printk("\r\n 0x");
					NumOfIterTwoFrame = get_int();
					NumOfIterTwoFrame =( NumOfIterTwoFrame<<8)| get_int();		 
					break;
	
				case '2' : 
					printk("\r\n TwoFrameTest256 TEST BEGIN");
					for(i = 0; i < NumofIterAll;i++)
					{
						//	iResult = OKA_Test();
						START;
						iResult = TwoFrameTest256();
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
	
							END;
							PrintCnt(HitCnt,MissCnt,NumofIterAll);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
	
							HitCnt++;
						}
						END;
					}
					printk("\r\n TwoFrameTest256 TEST END");
					SetKEYNormal();
					PrintCnt(HitCnt,MissCnt,NumofIterAll);
	
	
					break;
				case '1' :
					printk("\r\n TwoFrameTest128 TEST START");
					for(i = 0; i < NumofIterAll;i++)
					{
						START;
						iResult = TwoFrameTest();
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
	
							END;
							PrintCnt(HitCnt,MissCnt,NumofIterAll);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
	
							HitCnt++;
						}
						END;
					}
					printk("\r\n TwoFrameTest128 TEST END");				
					SetKEYNormal();
					PrintCnt(HitCnt,MissCnt,NumofIterAll);
					break; 
	
				case '3' :
					printk("\r\n TwoFrameTest128 ARIATEST START");
					for(i = 0; i < NumofIterAll;i++)
					{
						START;
						iResult = TwoFrameTestARIA();
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
	
							END;
							PrintCnt(HitCnt,MissCnt,NumofIterAll);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
	
							HitCnt++;
						}
						END;
					}
					printk("\r\n TwoFrameTest128 ARIATEST TEST END");	
					SetKEYNormal();
					PrintCnt(HitCnt,MissCnt,NumofIterAll);
					break; 
	
	
				case '4' :
					printk("\r\n TwoFrameTest256 ARIATEST START");
					for(i = 0; i < NumofIterAll;i++)
					{
						START;
						iResult = TwoFrameTest256ARIA();
						printk("\r\n END of %dth iteration",i+1);
						if(iResult == 0)
						{
							MissCnt++;FAIL;
#if ERROR_EXIT
	
							END;
							PrintCnt(HitCnt,MissCnt,NumofIterAll);
							goto L_Start_block;
#endif
						}
						else
						{
							printk("   PASS");
	
							HitCnt++;
						}
						END;
					}
					printk("\r\n TwoFrameTest256 ARIATEST TEST END");				
					SetKEYNormal();
					PrintCnt(HitCnt,MissCnt,NumofIterAll);
					break; 
	
				default : temp = 'p'; break;			
				}
		}

}


void AES_TEST_ALL_9_0()
{
	int i = 0;
	int HitCnt = 0;
	int MissCnt = 0;
	int IgnoreCnt =0;
	Aes256 = 0;
	Aes128 = 1;
	//GetSuperWirePermission();
	AesIsFirst = 1;
	for(i = 0; i < NumofIterAll; i++)
	{
		int iResult;// = AES(0);
		if(iResult == 0)
			MissCnt++;
		if(iResult == 2)
			IgnoreCnt++;
		if(iResult == 1)
			HitCnt++;
		printk("\r\n END of %d iteration",i+1);
	}
	//PrintCntEx(HitCnt,MissCnt,IgnoreCnt,NumOfIterMain);
	Aes256 = 1;
	Aes128 = 0;
	AesIsFirst = 1;
	for(i = 0; i < NumofIterAll; i++)
	{
		int iResult;// = AES(1);
		if(iResult == 0)
			MissCnt++;
		if(iResult == 2)
			IgnoreCnt++;
		if(iResult == 1)
			HitCnt++;
		printk("\r\n END of %d iteration",i+1); 			
	}
	//SetKEYNormal();
	SetKEYNormal();
	PrintCntEx(HitCnt,MissCnt,IgnoreCnt,HitCnt + MissCnt);
}

void ARIA_TEST_ALL_10_0()
{
	int i = 0;
	int HitCnt = 0;
	int MissCnt = 0;
	int IgnoreCnt =0;
	Aria256 = 0;
	Aria128 = 1;
	for(i = 0; i < NumofIterAll; i++)
	{
		int iResult = ARIA(0);
		if(iResult == 0)
			MissCnt++;
		if(iResult == 2)
			IgnoreCnt++;
		if(iResult == 1)
			HitCnt++;
		printk("\r\n END of %d iteration",i+1);
	}
	//PrintCntEx(HitCnt,MissCnt,IgnoreCnt,NumOfIterMain);
	Aria256 = 1;
	Aria128 = 0;

	for(i = 0; i < NumofIterAll; i++)
	{
		int iResult = ARIA(1);
		if(iResult == 0)
			MissCnt++;
		if(iResult == 2)
			IgnoreCnt++;
		if(iResult == 1)
			HitCnt++;
		printk("\r\n END of %d iteration",i+1); 			
	}

	SetKEYNormal(); 			
	PrintCntEx(HitCnt,MissCnt,IgnoreCnt,HitCnt + MissCnt);
}
void RootSerial_11_0()
{
		unsigned char temp ;
		int i = 0;
		int iResult = 0;
		unsigned int inst = 0;
		//unsigned char addr[2];
		unsigned char tx_data[64];
		unsigned char rx_data[64];
		int j = 0;
		int MissCnt;
		int HitCnt;				
		MissCnt = HitCnt = 0;
		printk("\r\n RSCreate START");
		for(i = 0; i < NumofIterAll;i++)
		{
			//	iResult = OKA_Test();
			START;
			iResult = RSCreate();
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
				MissCnt++;FAIL;
#if ERROR_EXIT

				END;
				PrintCnt(HitCnt,MissCnt,NumofIterAll);
				goto L_Start_block;
#endif
			}
			else
			{
				printk("   PASS");

				HitCnt++;
			}
			END;
		}
		printk("\r\n RSCreate END");
		
		PrintCnt(HitCnt,MissCnt,NumofIterAll);
		MissCnt = HitCnt = 0;
		printk("\r\nRSSHARead TEST START");
		for(i = 0; i < NumofIterAll;i++)
		{
			START;
			printk("\r\n Start of %dth iteration",i+1); 					
//			printk("\r\n RESET HW");
//			eep_page_read(0xF0, 00,0,rx_data);
//			GetPermissionByPW(UID_PW_CT, RG_PERM_UID_PASS);
//			ReleasePermision();
			iResult = RSSHARead();
			if(iResult == 0)
			{
				MissCnt++;FAIL;
#if ERROR_EXIT

				END;
				PrintCnt(HitCnt,MissCnt,NumofIterAll);
				goto L_Start_block;
#endif
			}
			else
			{
				printk("   PASS");

				HitCnt++;
			}
			END;
		}
		printk("\r\n RSSHARead TEST END");				
		PrintCnt(HitCnt,MissCnt,NumofIterAll);
		MissCnt = HitCnt = 0;
		printk("\r\n RSDirectRead TEST START");
		for(i = 0; i < NumofIterAll;i++)
		{
			//	iResult = OKA_Test();
			START;
			iResult = RSDirectRead();
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
				MissCnt++;FAIL;
#if ERROR_EXIT

				END;
				PrintCnt(HitCnt,MissCnt,NumofIterAll);
				goto L_Start_block;
#endif
			}
			else
			{
				printk("   PASS");

				HitCnt++;
			}
			END;
		}
		printk("\r\n RSDirectRead TEST END");
		PrintCnt(HitCnt,MissCnt,NumofIterAll);

}
void SHA_Test12_0(void)
{
	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	int k = 0;

	SHA_Test_Main_START:

		for( k = '1'; k <= '5'; k++)
		{
			int HitCnt = 0;
			int MissCnt = 0;
			switch ( k )
			{

				case '5':
						printk("\r\n SHA RANDOM TEST BEGIN");
						for(i = 0; i < NumofIterAll;i++)
						{
		
							START;
							iResult = SHA_4FRAME_RANDOM_TEST();
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								END;
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto SHA_Test_Main_START;
#endif
							}
							else
							{
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
				
					   break;				
				case '4':
						printk("\r\n SHA RANDOM TEST BEGIN");
						for(i = 0; i < NumofIterAll;i++)
						{
		
							START;
							iResult = SHA_RANDOM_TEST();
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								END;
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto SHA_Test_Main_START;
#endif
							}
							else
							{
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
				
					   break;
				case '3' : 
						printk("\r\n SHA_4Frame_TEST TEST BEGIN");
						for(i = 0; i < NumofIterAll;i++)
						{
		
							START;
							iResult = SHA_4Frame_TEST();
							printk("\r\n END of %dth iteration",i+1);
							if(iResult == 0)
							{
								MissCnt++;FAIL;
#if ERROR_EXIT
		
								END;
								PrintCnt(HitCnt,MissCnt,NumofIterAll);
								goto SHA_Test_Main_START;
#endif
							}
							else
							{
								HitCnt++;
							}
							END;
						}
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						break;

			case '2' : 
				printk("\r\n SHA_2Frame_TEST TEST BEGIN");
				for(i = 0; i < NumofIterAll;i++)
				{

					START;
					iResult = SHA_2Frame_TEST();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						goto SHA_Test_Main_START;
#endif
					}
					else
					{
						HitCnt++;
					}
					END;
				}
				PrintCnt(HitCnt,MissCnt,NumofIterAll);
				break;
				case '1' : 
				printk("\r\n SHA_1Frame_TEST TEST BEGIN");
				for(i = 0; i < NumofIterAll;i++)
				{

					START;
					iResult = SHA_1Frame_TEST();
					printk("\r\n END of %dth iteration",i+1);
					if(iResult == 0)
					{
						MissCnt++;FAIL;
#if ERROR_EXIT

						END;
						PrintCnt(HitCnt,MissCnt,NumofIterAll);
						goto SHA_Test_Main_START;
#endif
					}
					else
					{
						HitCnt++;
					}
					END;

				}
				
				PrintCnt(HitCnt,MissCnt,NumofIterAll);
				break;
		
			default : temp = 'p'; break;
			}

		}
	
}
void KEY_LOAD13_0()
{
		int i;
		int j;
		unsigned int inst = 0;
		unsigned char tx_data[64];
		unsigned char rx_data[64];
		unsigned char addr[2];
		unsigned char buf0xxx[64];
		int TestSize =0;
		int success = 1;
		int iResult = 0;
		int HitCnt = 0;
		int MissCnt = 0;
		unsigned char temp;
	L_KEYLOAD_START:

		for(i = 0; i < NumofIterAll;i++)
		{
			memset(tx_data,0,64);
			eep_page_write(ADDR_EE_KEY_AES_x0[0], ADDR_EE_KEY_AES_x0[1], tx_data, 1);
			eep_page_write(ADDR_EE_KEY_AES_x1[0], ADDR_EE_KEY_AES_x1[1], tx_data, 1);
			eep_page_write(ADDR_EE_KEY_AES_x2[0], ADDR_EE_KEY_AES_x2[1], tx_data, 1);
			eep_page_write(ADDR_EE_KEY_AES_x3[0], ADDR_EE_KEY_AES_x3[1], tx_data, 1);

			iResult = KeyLoadDemo(0,0,0,0,0,0);
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
				MissCnt++;
#if ERROR_EXIT

				PrintCnt(HitCnt,MissCnt,NumofIterAll*4);
				goto L_KEYLOAD_START;
#endif
			}
			else
			{

				HitCnt++;
			}
			iResult = KeyLoadDemo(1,0,1,0,0,0);
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
				MissCnt++;
#if ERROR_EXIT

				PrintCnt(HitCnt,MissCnt,NumofIterAll*4);
				goto L_KEYLOAD_START;
#endif
			}
			else
			{

				HitCnt++;
			}			
			iResult = KeyLoadDemo(2,0,2,0,0,0);;
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
				MissCnt++;
#if ERROR_EXIT

				PrintCnt(HitCnt,MissCnt,NumofIterAll*4);
				goto L_KEYLOAD_START;
#endif
			}
			else
			{

				HitCnt++;
			}			
			iResult = KeyLoadDemo(3,0,3,0,0,0);;
			printk("\r\n END of %dth iteration",i+1);
			if(iResult == 0)
			{
				MissCnt++;
#if ERROR_EXIT

				PrintCnt(HitCnt,MissCnt,NumofIterAll*4);
				goto L_KEYLOAD_START;
#endif
			}
			else
			{

				HitCnt++;
			}					

		}				
		SetKEYNormal();
		PrintCnt(HitCnt,MissCnt,NumofIterAll*4);

}
#endif
void TestAll()
{	
	printk("XXXX EEPROM_TEST_1_0");
	//EEPROM_TEST_1_0();	
	printk("\r\n XXXX RootSerial_11_0");		
	#if 0
	RootSerial_11_0();
	KEY_LOAD();
	printk("\r\n XXXX RENDOM_TEST_2_0");		
	RENDOM_TEST_2_0();
	printk("\r\n XXXX OKA_TEST_3_0");	
	OKA_TEST_3_0();
	printk("\r\n XXXX PERMISSION_TEST_4_0");		
	PERMISSION_TEST_4_0();
	printk("\r\n XXXX ShaAuth_5_0");		
	ShaAuth_5_0();
	printk("\r\n XXXX DecWrite_6_0");		
	DecWrite_6_0();
	printk("\r\n XXXX ReadEncAll_7_0");		
	ReadEncAll_7_0();	
	printk("\r\n XXXX TwoFrameTest_8_0");		
	TwoFrameTest_8_0();		
	printk("\r\n XXXX AES_TEST_ALL_9_0");		
	AES_TEST_ALL_9_0();
	printk("\r\n XXXX ARIA_TEST_ALL_10_0");		
	ARIA_TEST_ALL_10_0();
	printk("\r\n XXXX SHA_Test12_0");		
	SHA_Test12_0();
	KEY_LOAD13_0();
	#endif	
}
void TestAllMenu()
{
#ifdef COMPARE


	unsigned char temp ;
	int i = 0;
	int iResult = 0;
	unsigned char addr[2];
	unsigned char val;
	SHA_Test_Main_START:
	while(1)
	{
		temp = 'z' ;

		printk("\r\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  *            EXCUTE ALL    TEST MAIN                 *");
		printk("\r\n  *****************************************************");
		printk("\r\n  * i. Input number of iteration %d               *",NumofIterAll);
		printk("\r\n  * 1. TEST ALL 								  *");	
		printk("\r\n  * m. return to top menu                             *");			
		printk("\r\n");

		printk("\r\n");
		printk("\r\n  * Select : ");

		while(temp == 'z')
		{
			int HitCnt = 0;
			int MissCnt = 0;
			temp = _uart_get_char();

			if ( temp != 'z' ) printk("%c\n", temp);
			printk("\r\n");
			if(temp == 0x0d)
				goto SHA_Test_Main_START;
			if(temp == 'm')
			{
				printk("\r\nm is pressed");
				return;
			}

			switch ( temp )
			{
				case 'i': 
				printk("\r\n input number of iteration : (4digit)");
				printk("\r\n 0x");
				NumofIterAll = get_int();
				NumofIterAll =( NumofIterAll<<8)| get_int();		 
				break;
				case '1':
				//for(i = 0; i < NumOfIterTestAll; i++)
				gTESTAllErrorCnt = 0;
				gTESTAllCnt = 0;
					TestAll();
				if(gTESTAllErrorCnt > 0)
					printk("\r\n FINAL RESULT IS FAIL error cnt %d TEST cnt %d",gTESTAllErrorCnt,gTESTAllCnt);
				else
					printk("\r\n FINAL RESULT IS PASS TEST cnt %d",gTESTAllCnt);
				break;
			default : temp = 'p'; break;			
			}

		}
	}
#endif
}


void TestCM0Code()
{
#ifdef COMPARE

	unsigned int arr[42][8] = {
			/*
	0x00007ff0, 0x000001ab, 0x0000019d, 0x0000019f, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x000001a1, 0x00000000, 0x00000000, 0x000001a3, 0x000001a5,
	0x000001a7, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9,
	0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9,
	0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9,
	0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9, 0x000001a9,
	0xf802f000, 0xf846f000, 0xc830a00c, 0x18243808, 0x46a2182d, 0x46ab1e67, 0x465d4654, 0xd10142ac,
	0xf838f000, 0x3e0f467e, 0x46b6cc0f, 0x42332601, 0x1afbd000, 0x46ab46a2, 0x47184333, 0x000003ac,
	0x000003cc, 0xd3023a10, 0xc178c878, 0x0752d8fa, 0xc830d301, 0xd501c130, 0x600c6804, 0x00004770,
	0x24002300, 0x26002500, 0xd3013a10, 0xd8fbc178, 0xd3000752, 0xd500c130, 0x4770600b, 0x2978b510,
	0xf000d102, 0xbd10f8c1, 0xbd102000, 0xbd1fb51f, 0xbd10b510, 0xf968f000, 0xf7ff4611, 0xf000fff7,
	0xf000f809, 0xb403f980, 0xfff2f7ff, 0xf000bc03, 0x0000f837, 0xf000b510, 0xf000f835, 0x2400f81d,
	0xa0054621, 0xf85cf000, 0x2cff1c64, 0xf000dbf8, 0x2000f84d, 0x0000bd10, 0x00207825, 0xe7fee7fe,
	0xe7fee7fe, 0xe7fee7fe, 0xb510e7fe, 0xff88f7ff, 0x460abd10, 0x47704603, 0xb5104770, 0xf000b2c0,
	0xbd10f828, 0xf000b510, 0xf000f82a, 0xbd10f822, 0x43c02000, 0xb5104770, 0xf000b2c0, 0xbd10f81a,
	0x0000e7fe, 0x2336200a, 0x22004912, 0x638a630a, 0x628a624a, 0x630a62ca, 0x6248634a, 0x62ca628b,
	0x62c82070, 0x630800c0, 0x63482004, 0x6308480a, 0x49084770, 0x0692698a, 0x6008d4fc, 0x48054770,
	0x06c96981, 0x6800d4fc, 0x4770b2c0, 0xf7ff2004, 0xe7fefff0, 0x40002000, 0x00000381, 0x47704770,
	0x4905b40f, 0xaa03b510, 0xf0009802, 0xbc10f8c1, 0xb004bc08, 0x00004718, 0x00004000, 0x460eb5f8,
	0x20004604, 0x46206220, 0x478868e1, 0xd0292800, 0xd0022825, 0x68a16862, 0x68e1e020, 0x27004620,
	0x00054788, 0x4628d01e, 0x28193841, 0x2701d802, 0x352002ff, 0x46204632, 0x46296027, 0xff4ef7ff,
	0xd0082800, 0xd0042801, 0x08f61df6, 0x360800f6, 0x1d36e7d9, 0x6862e7d7, 0x68a14628, 0x6a204790,
	0xe7cf1c40, 0xbdf86a20, 0x4604b570, 0x4621460d, 0x46c06810, 0x882146c0, 0xd5020509, 0x447a4a0f,
	0x4a0ee002, 0x320e447a, 0x21004623, 0xe0053324, 0x09000706, 0x5d960f36, 0x1c49545e, 0xd1f72800,
	0x23007820, 0xd5050700, 0xd0032d70, 0xd0012900, 0x32112302, 0xf0004620, 0xbd70f803, 0x0000019e,
	0x4604b5ff, 0xb081460d, 0x90003024, 0x06886821, 0x2210d504, 0x439169e0, 0xe0006021, 0x42a82001,
	0x1b47dd01, 0x2700e000, 0x69a19804, 0x1810197a, 0x61a01a08, 0x06c07820, 0x4620d402, 0x46c046c0,
	0xe0082600, 0x68629803, 0x5d8068a1, 0x6a204790, 0x1c761c40, 0x98046220, 0xdbf34286, 0x06c07820,
	0x4620d50a, 0x46c046c0, 0x6862e006, 0x203068a1, 0x6a204790, 0x62201c40, 0x1e7f4638, 0xdcf42800,
	0x9800e007, 0x68a16862, 0x47905d40, 0x1c406a20, 0x46286220, 0x28001e6d, 0x4620dcf3, 0x46c046c0,
	0x06007820, 0x2002d502, 0xbdf0b005, 0xe7fb2001, 0xb5704b08, 0x447b460d, 0xf813f000, 0x46284604,
	0xfef6f7ff, 0xd0022800, 0x43c02000, 0x4620bd70, 0x0000bd70, 0xfffffde1, 0x1c4a6901, 0x78086102,
	0xb5004770, 0x9102b08f, 0x91052100, 0x93014905, 0x91034479, 0x90044611, 0xf7ff4668, 0xb00fff1f,
	0x0000bd00, 0xffffffe5, 0xf0004675, 0x46aef825, 0x46690005, 0x08c04653, 0x468500c0, 0xb520b018,
	0xfeb7f7ff, 0x2700bc60, 0x46b60849, 0xc5c02600, 0xc5c0c5c0, 0xc5c0c5c0, 0xc5c0c5c0, 0x3d40c5c0,
	0x468d0049, 0xb5104770, 0x46c04604, 0x462046c0, 0xfe79f7ff, 0x0000bd10, 0x47704800, 0x00004004,
	0x33323130, 0x37363534, 0x42413938, 0x46454443, 0x00583040, 0x33323130, 0x37363534, 0x62613938,
	0x66656463, 0x00783040, 0x000004c8, 0x00004000, 0x00000004, 0x00000104, 0x000004cc, 0x00004004,
	0x00000060, 0x00000120, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
	*/
	  0x2000FFF0, 0x000001F7, 0x000001D1, 0x000001D3, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	  0x00000000, 0x00000000, 0x00000000, 0x000001D5, 0x00000000, 0x00000000, 0x000001D7, 0x000001D9,
	  0x000001DB, 0x000001DD, 0x000001DF, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD,
	  0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD,
	  0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD,
	  0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD, 0x000001DD,
	  0xF802F000, 0xF846F000, 0xC830A00C, 0x18243808, 0x46A2182D, 0x46AB1E67, 0x465D4654, 0xD10142AC,
	  0xF838F000, 0x3E0F467E, 0x46B6CC0F, 0x42332601, 0x1AFBD000, 0x46AB46A2, 0x47184333, 0x000003FC,
	  0x0000041C, 0xD3023A10, 0xC178C878, 0x0752D8FA, 0xC830D301, 0xD501C130, 0x600C6804, 0x00004770,
	  0x24002300, 0x26002500, 0xD3013A10, 0xD8FBC178, 0xD3000752, 0xD500C130, 0x4770600B, 0x2978B510,
	  0xF000D102, 0xBD10F8E9, 0xBD102000, 0xBD1FB51F, 0xBD10B510, 0xF990F000, 0xF7FF4611, 0xF000FFF7,
	  0xF000F809, 0xB403F9A8, 0xFFF2F7FF, 0xF000BC03, 0x0000F85F, 0xF000B570, 0xF000F85D, 0x4D0BF845,
	  0x46212450, 0xF000A00A, 0x4620F883, 0x28074028, 0xA008D102, 0xF87CF000, 0x2CFF1C64, 0xA006DDF1,
	  0xF876F000, 0xF869F000, 0xBD702000, 0x80000007, 0x00782520, 0x00000D0A, 0x41550D0A, 0x70205452,
	  0x746E6972, 0x6E6F6420, 0x0A212165, 0x0000000D, 0xE7FEE7FE, 0xE7FEE7FE, 0xE7FEE7FE, 0x4809E7FE,
	  0x21016902, 0xD0042A01, 0x2A016B02, 0x62C1D100, 0x60C14770, 0xB5104770, 0xFF62F7FF, 0x460ABD10,
	  0x47704603, 0x40002400, 0xB5104770, 0xF000B2C0, 0xBD10F827, 0xF000B510, 0xF000F829, 0xBD10F821,
	  0x43C02000, 0xB5104770, 0xF000B2C0, 0xBD10F819, 0x0000E7FE, 0x4913200A, 0x630A2200, 0x624A638A,
	  0x62CA628A, 0x634A630A, 0x628A6248, 0x207062CA, 0x00C062C8, 0x20046308, 0x480B6348, 0x47706308,
	  0x698A4908, 0xD4FC0692, 0x47706008, 0x69814805, 0xD4FC06C9, 0xB2C06800, 0x20044770, 0xFFF0F7FF,
	  0x0000E7FE, 0x40002000, 0x00000381, 0x47704770, 0x4905B40F, 0xAA03B510, 0xF0009802, 0xBC10F8C1,
	  0xB004BC08, 0x00004718, 0x20008000, 0x460EB5F8, 0x20004604, 0x46206220, 0x478868E1, 0xD0292800,
	  0xD0022825, 0x68A16862, 0x68E1E020, 0x27004620, 0x00054788, 0x4628D01E, 0x28193841, 0x2701D802,
	  0x352002FF, 0x46204632, 0x46296027, 0xFF26F7FF, 0xD0082800, 0xD0042801, 0x08F61DF6, 0x360800F6,
	  0x1D36E7D9, 0x6862E7D7, 0x68A14628, 0x6A204790, 0xE7CF1C40, 0xBDF86A20, 0x4604B570, 0x4621460D,
	  0x46C06810, 0x882146C0, 0xD5020509, 0x447A4A0F, 0x4A0EE002, 0x320E447A, 0x21004623, 0xE0053324,
	  0x09000706, 0x5D960F36, 0x1C49545E, 0xD1F72800, 0x23007820, 0xD5050700, 0xD0032D70, 0xD0012900,
	  0x32112302, 0xF0004620, 0xBD70F803, 0x0000019E, 0x4604B5FF, 0xB081460D, 0x90003024, 0x06886821,
	  0x2210D504, 0x439169E0, 0xE0006021, 0x42A82001, 0x1B47DD01, 0x2700E000, 0x69A19804, 0x1810197A,
	  0x61A01A08, 0x06C07820, 0x4620D402, 0x46C046C0, 0xE0082600, 0x68629803, 0x5D8068A1, 0x6A204790,
	  0x1C761C40, 0x98046220, 0xDBF34286, 0x06C07820, 0x4620D50A, 0x46C046C0, 0x6862E006, 0x203068A1,
	  0x6A204790, 0x62201C40, 0x1E7F4638, 0xDCF42800, 0x9800E007, 0x68A16862, 0x47905D40, 0x1C406A20,
	  0x46286220, 0x28001E6D, 0x4620DCF3, 0x46C046C0, 0x06007820, 0x2002D502, 0xBDF0B005, 0xE7FB2001,
	  0xB5704B08, 0x447B460D, 0xF813F000, 0x46284604, 0xFEF6F7FF, 0xD0022800, 0x43C02000, 0x4620BD70,
	  0x0000BD70, 0xFFFFFDE1, 0x1C4A6901, 0x78086102, 0xB5004770, 0x9102B08F, 0x91052100, 0x93014905,
	  0x91034479, 0x90044611, 0xF7FF4668, 0xB00FFF1F, 0x0000BD00, 0xFFFFFFE5, 0xF0004675, 0x46AEF825,
	  0x46690005, 0x08C04653, 0x468500C0, 0xB520B018, 0xFEB5F7FF, 0x2700BC60, 0x46B60849, 0xC5C02600,
	  0xC5C0C5C0, 0xC5C0C5C0, 0xC5C0C5C0, 0x3D40C5C0, 0x468D0049, 0xB5104770, 0x46C04604, 0x462046C0,
	  0xFE51F7FF, 0x0000BD10, 0x47704800, 0x20008004, 0x33323130, 0x37363534, 0x42413938, 0x46454443,
	  0x00583040, 0x33323130, 0x37363534, 0x62613938, 0x66656463, 0x00783040, 0x00000518, 0x20008000,
	  0x00000004, 0x00000104, 0x0000051C, 0x20008004, 0x00000060, 0x00000120, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
		};
	   unsigned int i;
	   unsigned int j;
	   unsigned int *pCM0Code = &arr[0][0];
	   unsigned char Buffer[64];
	   unsigned int addr = 0;	
	   int msb;
	   int lsb;
	   for(i = 0; i < 42*8; i += 16 )
	   	{
	   		for( j = 0; j < 16; j++ )
	   		{
	   			Buffer[j*4 + 0] =  pCM0Code[i+j] & 0xFF;
	   			Buffer[j*4 + 1] = (pCM0Code[i+j] >> 8) & 0xFF;
	   			Buffer[j*4 + 2] = (pCM0Code[i+j] >> 16) & 0xFF;
	   			Buffer[j*4 + 3] = (pCM0Code[i+j] >> 24) & 0xFF;
	   		}
			msb = (addr>>8) & 0xFF;
			lsb = addr & 0xFF;
			eep_page_write(msb, lsb,Buffer, 1);
			addr += 64;
	   	}	
#endif
}
#if 0
int AES_ARIA_INIT(int RG_128_256,int AES_ARIA,unsigned char *AES_ARIA_KEY)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char KEY_BUFFER[32];
	// INIT KEY
#if 0
	if(RG_128_256 == RG_256)
	{
		for(i = 0; i < 32; i++)
		{
			AES_ARIA_KEY[i] = i;
		}
	}	
	else
	{
		for(i =0; i <16; i++)
		{
			AES_ARIA_KEY[i] = i;
		}
		for(i = 16; i < 32; i++)
			AES_ARIA_KEY[i] = 0;
	}
#endif

	if(RG_128_256 == RG_256)
	{
		memcpy(KEY_BUFFER,AES_ARIA_KEY+16,16);
		memcpy(KEY_BUFFER+16,AES_ARIA_KEY,16);		
		KEY_SET(KEY_BUFFER);
	}
	else
	{
		memcpy(KEY_BUFFER+16,AES_ARIA_KEY,16);
		KEY_SET(KEY_BUFFER);	
	}

	tx_data[0] = 0x0;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 
		(RG_128_256<<1)|
		AES_ARIA;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	delay_us(30);
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	return 0;
}

void AES_ARIA_Encrypt(unsigned char *pInput,unsigned char *pOutput)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	reversebuffer(tx_data, pInput, 16);
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(2);
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	//iEnd = pRSTC->RTTC_RTVR;
	reversebuffer(pOutput, rx_data, 16);	
	

}
void AES_ARIA_Decrypt(unsigned char *pInput,unsigned  char *pOutput)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	reversebuffer(tx_data, pInput, 16);
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(2);
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	//iEnd = pRSTC->RTTC_RTVR;
	reversebuffer(pOutput, rx_data, 16);	

}

void AES_ARIA_CLOSE()
{

	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	  


	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	  


	endOP();				

}

int AES_ARIA_ECB_TEST_ETRI(int RG_128_256,int AES_ARIA ,int EncDec)
{
	//AES TEST
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char CT[16];
	unsigned char PT[16];	
	unsigned char AES128KEY[16];
	unsigned char AES128CT[16];
	unsigned char AES128PT[16];
	unsigned char AES256KEY[32];
	unsigned char AES256CT[16];
	unsigned char AES256PT[16];

	unsigned char ARIA128KEY[16];
	unsigned char ARIA128CT[16];
	unsigned char ARIA128PT[16];
	unsigned char ARIA256KEY[32];
	unsigned char ARIA256CT[16];
	unsigned char ARIA256PT[16];
	int success = 1;
	unsigned char *pKEY;
	unsigned char *pPT;
	unsigned char *pCT;


	hexstr2bytes("000102030405060708090a0b0c0d0e0f",AES128KEY);
	hexstr2bytes("69c4e0d86a7b0430d8cdb78070b4c55a",AES128CT);	
	hexstr2bytes("00112233445566778899aabbccddeeff",AES128PT);		

	hexstr2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",AES256KEY);
	hexstr2bytes("8ea2b7ca516745bfeafc49904b496089",AES256CT);	
	hexstr2bytes("00112233445566778899aabbccddeeff",AES256PT);	

	hexstr2bytes("00112233445566778899aabbccddeeff",ARIA128KEY);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb",ARIA128PT);	
	hexstr2bytes("c6ecd08e22c30abdb215cf74e2075e6e",ARIA128CT);		

	hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",ARIA256KEY);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb",ARIA256PT);	
	hexstr2bytes("58a875e6044ad7fffa4f58420f7f442d",ARIA256CT);		


		if(RG_256 == RG_128_256) {
			if(RG_AES == AES_ARIA) {
				pKEY = AES256KEY;
				pCT = AES256CT;
				pPT = AES256PT;	
				}
			else {
				pKEY = ARIA128KEY;
				pCT = ARIA256CT;
				pPT = ARIA256PT;	
				}
				
			}
		else {
			if(RG_AES == AES_ARIA) {
				pKEY = AES128KEY;
				pCT = AES128CT;
				pPT = AES128PT;	
				}
			else {
				pKEY = ARIA128KEY;
				pCT = ARIA128CT;
				pPT = ARIA128PT;	
				}
		}
		printk("\r\n");
		if(RG_128_256 == RG_256)
			printk("256");
		else
			printk("128");
		
		if(AES_ARIA == RG_AES)
			printk("AES");
		else
			printk("ARIA"); 

		if(RG_ENC == EncDec)
			printk("\r\n ENCODING");
		else
			printk("\r\n DECODING");

		printk("\r\n pCT");
		printbyte(pCT,16);
		printk("\r\n pPT");
		printbyte(pPT,16);  
		printk("\r\n KEY");
		if(RG_128_256 == RG_256)
			printk("256");
		else
			printk("128");
		
		if(AES_ARIA == RG_AES)
			printk("AES");
		else
			printk("ARIA"); 
		
		if(RG_256 == RG_128_256)
			printbyte(pKEY,32);
		else
			printbyte(pKEY,16);

		AES_ARIA_INIT(RG_128_256 ,AES_ARIA, pKEY);
		printk("\r\n 	AES_ARIA_INIT(RG_128_256:%d ,AES_ARIA :%d)",RG_128_256,AES_ARIA);
		if(RG_ENC == EncDec) {

		printk("\r\n ENCODING TEST");

			
				AES_ARIA_Encrypt(pPT,CT);
					if(memcmp(CT,pCT,16) != 0) {

						printk("\r\n ENCODING COMPARE FAIL ");
					}

						printk("\r\n RESULT CT");
						printbyte(CT,16);
						
						printk("\r\n EXPECTED CT");
						printbyte(pCT,16);

		}
		else {
		printk("\r\n DECODING TEST");

				AES_ARIA_Decrypt(pCT,PT);
					if(memcmp(PT,pPT,16) != 0) {

						printk("\r\n DECODING COMPARE FAIL ",i);

					}

						printk("\r\n RESULT PT");
						printbyte(PT,16);	
						printk("\r\n EXPECTED PT");
						printbyte(pPT,16);
		}
		AES_ARIA_CLOSE();
}

void AES_ARIA_ECB_TEST_ETRI_MAIN()
{
	printk("\r\n PART 1 AES128 Encryption ");
	AES_ARIA_ECB_TEST_ETRI(RG_128,RG_AES,RG_ENC);
	printk("\r\n PART 1 AES256 Encryption ");		
	AES_ARIA_ECB_TEST_ETRI(RG_256,RG_AES,RG_ENC);
	printk("\r\n PART 1 AES128 Decryption ");
	AES_ARIA_ECB_TEST_ETRI(RG_128,RG_AES,RG_DEC);
	printk("\r\n PART 1 AES256 Decryption ");		
	AES_ARIA_ECB_TEST_ETRI(RG_256,RG_AES,RG_DEC);	

	printk("\r\n PART 1 ARIA128 Encryption ");
	AES_ARIA_ECB_TEST_ETRI(RG_128,RG_ARIA,RG_ENC);
	printk("\r\n PART 1 ARIA256 Encryption ");		
	AES_ARIA_ECB_TEST_ETRI(RG_256,RG_ARIA,RG_ENC);
	printk("\r\n PART 1 ARIA128 Decryption ");
	AES_ARIA_ECB_TEST_ETRI(RG_128,RG_ARIA,RG_DEC);
	printk("\r\n PART 1 ARIA256 Decryption ");		
	AES_ARIA_ECB_TEST_ETRI(RG_256,RG_ARIA,RG_DEC);		

}
#endif
#if 0
int TAESM110_S()
{
	int i,j,k;
	int success = 1;

	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM110_S================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32+16);
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", PLAIN_TEXT);
	hexstr2bytes("7649abac8119b246cee98e9b12e9197d4cbbc858756b358125529e9698a38f449f6f0796ee3e47b0d87c761b20527f78070134085f02751755efca3b4cdc7d62", ENC_PLAIN_TEXT);		
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CBC, RG_128,RG_AES)	;

	printk("\r\n DEC TEST \r\n");	   
	success +=OPERATION_MODE_DEC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CBC, RG_128,RG_AES)	;	   
	return success;
}
int TAESM111_S()
{
	int i,j,k;
	int success = 1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM111_S================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32+16);
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", PLAIN_TEXT);
	hexstr2bytes("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7", ENC_PLAIN_TEXT);		
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	hexstr2bytes("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success +=OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CBC, RG_128,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success +=OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CBC, RG_128,RG_AES)	;	   
	return success;
}

int TAESM120_S()
{
	int i,j,k;
	int success = 1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM120_S================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32+16);
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", PLAIN_TEXT);
	hexstr2bytes("3b3fd92eb72dad20333449f8e83cfb4ab265643826d2bc0982b64367f372415ecc49a7ba114397714f8248a04bf9a809ad12ff8f0756c3f922b32fb354298e64", ENC_PLAIN_TEXT);		
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	hexstr2bytes("3b3fd92eb72dad20333449f8e83cfb4ab265643826d2bc0982b64367f372415ecc49a7ba114397714f8248a04bf9a809ad12ff8f0756c3f922b32fb354298e64", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_OFB, RG_128,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_OFB, RG_128,RG_AES)	;	   
	return success;
}


int TAESM121_S()
{
	int i,j,k;
	int success = 1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM121_S================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32+16);
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", PLAIN_TEXT);
	hexstr2bytes("3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e", ENC_PLAIN_TEXT);		
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	hexstr2bytes("3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_OFB, RG_128,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_OFB, RG_128,RG_AES)	;	   
	return success;
}

int TAESM130_S()
{
	int i,j,k;
	int success = 1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM130_S================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32+16);
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", PLAIN_TEXT);
	hexstr2bytes("874d6191b620e3261bef6864990db6ce5deac2de4933cef5f19d09c68fc3648401ed7d9a56c9a8d95789b60a64297b6e835d877ddeb107503d374fca66ffbcd4", ENC_PLAIN_TEXT);		
	hexstr2bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", IV);	

	hexstr2bytes("874d6191b620e3261bef6864990db6ce5deac2de4933cef5f19d09c68fc3648401ed7d9a56c9a8d95789b60a64297b6e835d877ddeb107503d374fca66ffbcd4", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CTR, RG_128,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CTR, RG_128,RG_AES)	;	   
	return success;
}


int TAESM131_S()
{
	int i,j,k;
	int success  = 1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM131_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32+16);
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", PLAIN_TEXT);
	hexstr2bytes("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee", ENC_PLAIN_TEXT);		
	hexstr2bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", IV);	

	hexstr2bytes("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CTR, RG_128,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CTR, RG_128,RG_AES)	;	   
	return success;
}

int TAESM140_S()
{
	int i,j,k;
	int success = 1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM140_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32+16);
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", PLAIN_TEXT);
	hexstr2bytes("3b3fd92eb72dad20333449f8e83cfb4a0d4a718290f09a35ba69dc10a9207cf07a21135ebc717eab317e1078aa6003e6b488046f2e2a1ba5008711ea696ca542", ENC_PLAIN_TEXT);		
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	hexstr2bytes("3b3fd92eb72dad20333449f8e83cfb4a0d4a718290f09a35ba69dc10a9207cf07a21135ebc717eab317e1078aa6003e6b488046f2e2a1ba5008711ea696ca542", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CFB, RG_128,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CFB, RG_128,RG_AES)	;	   
	return success;
}

int TAESM141_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM141_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("2b7e151628aed2a6abf7158809cf4f3c", KEY32+16);
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	hexstr2bytes("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CFB, RG_128,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CFB, RG_128,RG_AES)	;	   
	return success;
}

int TAESM210_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM210_S ================================== ");
	memset(KEY32,0,32);
	// 603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4
	hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("603deb1015ca71be2b73aef0857d7781", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("f58c4c04d6e5f1ba779eabfb5f7bfbd6eb2d9e942831bd84dff00db9776b808825e80f72637337ae724abd9275366147e6ecc6346cd9151fa25d1afec9bb66b1", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	hexstr2bytes("f58c4c04d6e5f1ba779eabfb5f7bfbd6eb2d9e942831bd84dff00db9776b808825e80f72637337ae724abd9275366147e6ecc6346cd9151fa25d1afec9bb66b1", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CBC, RG_256,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CBC, RG_256,RG_AES)	;	   
	return success;
}


int TAESM211_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM211_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("603deb1015ca71be2b73aef0857d7781", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	hexstr2bytes("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CBC, RG_256,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CBC, RG_256,RG_AES)	;	   
	return success;
}

int TAESM220_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM220_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("603deb1015ca71be2b73aef0857d7781", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("dc7e84bfda79164b7ecd8486985d38608a07e8d270913830bf057b651c7329f62aa2e5040bf4156aff5ba353d30e81cd9c788eba96fc7f69179965e172bfc4be", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	hexstr2bytes("dc7e84bfda79164b7ecd8486985d38608a07e8d270913830bf057b651c7329f62aa2e5040bf4156aff5ba353d30e81cd9c788eba96fc7f69179965e172bfc4be", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_OFB, RG_256,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_OFB, RG_256,RG_AES)	;	   
	return success;
}


int TAESM221_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM221_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("603deb1015ca71be2b73aef0857d7781", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	hexstr2bytes("dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_OFB, RG_256,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_OFB, RG_256,RG_AES)	;	   
	return success;
}


int TAESM230_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM230_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("603deb1015ca71be2b73aef0857d7781", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("601ec313775789a5b7a7f504bbf3d22831afd77f7d218690bd0ef82dfcf66cbe7000927e2f2192cbe4b6a8b2441ddd4842975f2a4775a92757d4e262d086619c", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", IV);	

	hexstr2bytes("601ec313775789a5b7a7f504bbf3d22831afd77f7d218690bd0ef82dfcf66cbe7000927e2f2192cbe4b6a8b2441ddd4842975f2a4775a92757d4e262d086619c", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CTR, RG_256,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CTR, RG_256,RG_AES)	;	   
	return success;
}

int TAESM231_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM231_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("603deb1015ca71be2b73aef0857d7781", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", IV);	

	hexstr2bytes("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CTR, RG_256,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CTR, RG_256,RG_AES)	;	   
	return success;
}

int TAESM240_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;
	printk("\r\n ================================== TAESM240_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("603deb1015ca71be2b73aef0857d7781", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("dc7e84bfda79164b7ecd8486985d3860fc13d9a10b6b82c2459b2dde07d9d90085c7249705049cba1328a6a2bb256a6fce8e2139060377bf35e82d2deefa08cf", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	hexstr2bytes("dc7e84bfda79164b7ecd8486985d3860fc13d9a10b6b82c2459b2dde07d9d90085c7249705049cba1328a6a2bb256a6fce8e2139060377bf35e82d2deefa08cf", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CFB, RG_256,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CFB, RG_256,RG_AES)	;	   
	return success;
}

int TAESM241_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TAESM241_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("603deb1015ca71be2b73aef0857d7781", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("000102030405060708090a0b0c0d0e0f", IV);	

	hexstr2bytes("dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471", CYPER_TEXT);
	hexstr2bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CFB, RG_256,RG_AES)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CFB, RG_256,RG_AES)	;	   
	return success;
}

int TARIAM110_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM110_S ================================== ");
	memset(KEY32,0,32);
	//hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("000102030405060708090A0B0C0D0E0F", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("17c6a3eec47f7d19a1e82bb8504b492017c6a3eec47f7d19a1e82bb8504b492017c6a3eec47f7d19a1e82bb8504b492017c6a3eec47f7d19a1e82bb8504b4920", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("2c1447e94acb1c5d300f38547158505242071f50e07d0beb9a5b9fd5827436a1b9b8ae704768b32b82ca8fbeeeff8378c3e009919aa790719a39fc6890c7cb38", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", IV);	

	hexstr2bytes("2c1447e94acb1c5d300f38547158505242071f50e07d0beb9a5b9fd5827436a1b9b8ae704768b32b82ca8fbeeeff8378c3e009919aa790719a39fc6890c7cb38", CYPER_TEXT);
	hexstr2bytes("17c6a3eec47f7d19a1e82bb8504b492017c6a3eec47f7d19a1e82bb8504b492017c6a3eec47f7d19a1e82bb8504b492017c6a3eec47f7d19a1e82bb8504b4920", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CBC, RG_128,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CBC, RG_128,RG_ARIA)	;	   
	return success;
}
int TARIAM111_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM111_S ================================== ");
	memset(KEY32,0,32);
	//hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("000102030405060708090A0B0C0D0E0F", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("17c6a3eec47f7d19a1e82bb8504b49203144202fce126ce3b5f38351038735b53f788a07f5451d5eb4bc7a04a6e574cbf4c0e6203995e217050f0976e22aa2c7", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("2c1447e94acb1c5d300f385471585052c8af99fff4cf91725d8928590a5657c556ed06b136cee6e88f1dfd140a03dcf819b128a00d329d1e7faacab25824ebfb", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", IV);	

	hexstr2bytes("2c1447e94acb1c5d300f385471585052c8af99fff4cf91725d8928590a5657c556ed06b136cee6e88f1dfd140a03dcf819b128a00d329d1e7faacab25824ebfb", CYPER_TEXT);
	hexstr2bytes("17c6a3eec47f7d19a1e82bb8504b49203144202fce126ce3b5f38351038735b53f788a07f5451d5eb4bc7a04a6e574cbf4c0e6203995e217050f0976e22aa2c7", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CBC, RG_128,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CBC, RG_128,RG_ARIA)	;	   
	return success;
}

int TARIAM120_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM120_S ================================== ");
	memset(KEY32,0,32);
	//hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("3720e53ba7d615383406b09f0a05a2000063063f63066e5283faeb047aecb8a8c03fcb3fefb002a0e1b346a268ec01db0e7ac529a8b406db70ddf39115715688", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV);	

	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", CYPER_TEXT);
	hexstr2bytes("3720e53ba7d615383406b09f0a05a2000063063f63066e5283faeb047aecb8a8c03fcb3fefb002a0e1b346a268ec01db0e7ac529a8b406db70ddf39115715688", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_OFB, RG_128,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_OFB, RG_128,RG_ARIA)	;	   
	return success;
}


int TARIAM121_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM121_S ================================== ");
	memset(KEY32,0,32);
	//hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("3720e53ba7d615383406b09f0a05a2000063063f0560083483faeb041c8adecef30cf80cefb002a0d280759168ec01db3d49f61aced260bd43eec0a2731730ee", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV);	

	hexstr2bytes("3720e53ba7d615383406b09f0a05a2000063063f0560083483faeb041c8adecef30cf80cefb002a0d280759168ec01db3d49f61aced260bd43eec0a2731730ee", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_OFB, RG_128,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_OFB, RG_128,RG_ARIA)	;	   
	return success;
}

int TARIAM130_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM130_S ================================== ");
	memset(KEY32,0,32);
	//hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("ac5d7de805a0bf1c57c854501af60fa11497e2a3237fb8c7569e91e5d3aac849c08c928c975f4571c7b8d2a2613546c3a22250f3e39e1796d49d6c196e3de7e3", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("00000000000000000000000000000000", IV);	

	hexstr2bytes("ac5d7de805a0bf1c57c854501af60fa11497e2a3237fb8c7569e91e5d3aac849c08c928c975f4571c7b8d2a2613546c3a22250f3e39e1796d49d6c196e3de7e3", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CTR, RG_128,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CTR, RG_128,RG_ARIA)	;	   
	return success;
}

int TARIAM131_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM131_S ================================== ");
	memset(KEY32,0,32);
	//hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("ac5d7de805a0bf1c57c854501af60fa11497e2a34519dea1569e91e5b5ccae2ff3bfa1bf975f4571f48be191613546c3911163c085f871f0e7ae5f2a085b8185", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("00000000000000000000000000000000", IV);	

	hexstr2bytes("ac5d7de805a0bf1c57c854501af60fa11497e2a34519dea1569e91e5b5ccae2ff3bfa1bf975f4571f48be191613546c3911163c085f871f0e7ae5f2a085b8185", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CTR, RG_128,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CTR, RG_128,RG_ARIA)	;	   
	return success;
}

int TARIAM140_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM140_S ================================== ");
	memset(KEY32,0,32);
	//hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("3720e53ba7d615383406b09f0a05a200c07c21e65169275c5d132500c0e4e367c10f834a90677ff6803b54ef92775152f05ea37ff38321b665b2b10ab8baaed2", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV);	

	hexstr2bytes("3720e53ba7d615383406b09f0a05a200c07c21e65169275c5d132500c0e4e367c10f834a90677ff6803b54ef92775152f05ea37ff38321b665b2b10ab8baaed2", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CFB, RG_128,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CFB, RG_128,RG_ARIA)	;	   
	return success;
}

int TARIAM141_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM141_S ================================== ");
	memset(KEY32,0,32);
	//hexstr2bytes("1f352c073b6108d72d9810a30914dff4", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("3720e53ba7d615383406b09f0a05a200c07c21e6370f413a5d132500a68285017c61b434c7b7ca9685a51071861e4d4bb873b599b479e2d573dddeafba89f812", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV);	

	hexstr2bytes("3720e53ba7d615383406b09f0a05a200c07c21e6370f413a5d132500a68285017c61b434c7b7ca9685a51071861e4d4bb873b599b479e2d573dddeafba89f812", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CFB, RG_128,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CFB, RG_128,RG_ARIA)	;	   
	return success;
}

int TARIAM210_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM210_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("523a8a806ae621f155fdd28dbc34e1ab9ecfb451bd8cf487f7f61d21c7f20ec62da345e7c19713f36c93757b5f24668d5bb24665eb5dc5c33a79872ff67f4db3", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV);	

	hexstr2bytes("523a8a806ae621f155fdd28dbc34e1ab9ecfb451bd8cf487f7f61d21c7f20ec62da345e7c19713f36c93757b5f24668d5bb24665eb5dc5c33a79872ff67f4db3", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CBC, RG_256,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CBC, RG_256,RG_ARIA)	;	   
	return success;
}

int TARIAM211_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM141_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("523a8a806ae621f155fdd28dbc34e1ab7b9b42432ad8b2efb96e23b13f0a6e52f36185d50ad002c5f601bee5493f118b243ee2e313642bffc3902e7b2efd9a12", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV);	

	hexstr2bytes("523a8a806ae621f155fdd28dbc34e1ab7b9b42432ad8b2efb96e23b13f0a6e52f36185d50ad002c5f601bee5493f118b243ee2e313642bffc3902e7b2efd9a12", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CBC, RG_256,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CBC, RG_256,RG_ARIA)	;	   
	return success;
}

int TARIAM220_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM220_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("26834705b0f2c0e2588d4a7f0900963584c256813a24f4d39f8d3f960c13d3457687c6ca8c785d3f05b9be6cf89b7f953fd980fe05115a4012e5618b89fed27f", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV);	

	hexstr2bytes("26834705b0f2c0e2588d4a7f0900963584c256813a24f4d39f8d3f960c13d3457687c6ca8c785d3f05b9be6cf89b7f953fd980fe05115a4012e5618b89fed27f", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_OFB, RG_256,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_OFB, RG_256,RG_ARIA)	;	   
	return success;
}

int TARIAM221_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM220_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("26834705b0f2c0e2588d4a7f0900963584c256815c4292b59f8d3f966a75b52345b4f5f98c785d3f368a8d5ff89b7f950ceab3cd63773c2621d652b8ef98b419", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV);	

	hexstr2bytes("26834705b0f2c0e2588d4a7f0900963584c256815c4292b59f8d3f966a75b52345b4f5f98c785d3f368a8d5ff89b7f950ceab3cd63773c2621d652b8ef98b419", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_OFB, RG_256,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_OFB, RG_256,RG_ARIA)	;	   
	return success;
}

int TARIAM230_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM230_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("30026c329666141721178b99c0a1f1b2f0694025591d56efe2a30ea80cc5aee96a73c369d7ee41d72074884161e348f1b053740cb91b2811108cc87777aa7590", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("00000000000000000000000000000000", IV);	

	hexstr2bytes("30026c329666141721178b99c0a1f1b2f0694025591d56efe2a30ea80cc5aee96a73c369d7ee41d72074884161e348f1b053740cb91b2811108cc87777aa7590", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CTR, RG_256,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CTR, RG_256,RG_ARIA)	;	   
	return success;
}

int TARIAM231_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM231_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("30026c329666141721178b99c0a1f1b2f06940253f7b3089e2a30ea86aa3c88f5940f05ad7ee41d71347bb7261e348f18360473fdf7d4e7723bffb4411cc13f6", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("00000000000000000000000000000000", IV);	

	hexstr2bytes("30026c329666141721178b99c0a1f1b2f06940253f7b3089e2a30ea86aa3c88f5940f05ad7ee41d71347bb7261e348f18360473fdf7d4e7723bffb4411cc13f6", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CTR, RG_256,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CTR, RG_256,RG_ARIA)	;	   
	return success;
}


int TARIAM240_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM240_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("26834705b0f2c0e2588d4a7f09009635f28bb93dea579e16ec1e0bdb6e4d009c8d18760f74ca9aabe279bed3f628cf5c15c6770c4ccde85396f9b5b40ca4c137", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV);	

	hexstr2bytes("26834705b0f2c0e2588d4a7f09009635f28bb93dea579e16ec1e0bdb6e4d009c8d18760f74ca9aabe279bed3f628cf5c15c6770c4ccde85396f9b5b40ca4c137", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CFB, RG_256,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CFB, RG_256,RG_ARIA)	;	   
	return success;
}

int TARIAM241_S()
{
	int i,j,k;
	int success =1;
	unsigned char PLAIN_TEXT[16*4];
	unsigned char ENC_PLAIN_TEXT[16*4];
	unsigned char IV[16];
	unsigned char PLAIN_TEXT_REV[16*4];
	unsigned char ENC_PLAIN_TEXT_REV[16*4];

	unsigned char CYPER_TEXT[16*4];
	unsigned char DEC_CYPER_TEXT[16*4];

	unsigned char CYPER_TEXT_REV[16*4];
	unsigned char DEC_CYPER_TEXT_REV[16*4];
	unsigned char IV_REV[16];	
	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TARIAM241_S ================================== ");
	memset(KEY32,0,32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	//	return;	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", PLAIN_TEXT);
	//"6bc1bee22e409f96e93d7e117393172a"
	hexstr2bytes("26834705b0f2c0e2588d4a7f09009635f28bb93dea579e16ec1e0bdb6e4d009c8d18760f74ca9aabe279bed3f628cf5c15c6770c4ccde85396f9b5b40ca4c137", ENC_PLAIN_TEXT);		
	//"3b3fd92eb72dad20333449f8e83cfb4a"
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV);	

	hexstr2bytes("26834705b0f2c0e2588d4a7f09009635f28bb93dea579e16ec1e0bdb6e4d009c8d18760f74ca9aabe279bed3f628cf5c15c6770c4ccde85396f9b5b40ca4c137", CYPER_TEXT);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb", DEC_CYPER_TEXT);		
	j = 63;
	for(i = 0; i < 16*4; i += 16)
	{
		k = i + 16 -1;
		for( j = 0; j < 16; j++)
		{
			PLAIN_TEXT_REV[i+j] = PLAIN_TEXT[k];
			ENC_PLAIN_TEXT_REV[i+j] = ENC_PLAIN_TEXT[k];
			CYPER_TEXT_REV[i+j] = CYPER_TEXT[k];
			DEC_CYPER_TEXT_REV[i+j] = DEC_CYPER_TEXT[k];			
			k = k-1;
		}
	}
	j = 15;
	for(i = 0; i < 16; i++)
	{
		IV_REV[i] = IV[j--];
	}
	printk("\r\n ENC TEST \r\n");
	success += OPERATION_MODE_ENC(IV_REV,PLAIN_TEXT_REV,ENC_PLAIN_TEXT_REV, MODE_CFB, RG_256,RG_ARIA)	;
	printk("\r\n DEC TEST \r\n");	   
	success += OPERATION_MODE_DEC(IV_REV,DEC_CYPER_TEXT_REV,CYPER_TEXT_REV, MODE_CFB, RG_256,RG_ARIA)	;	   
	return success;
}

void SET_IV(unsigned char *IV,int AES_OPMODE,int RG_128_256,int AES_ARIA)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];	   
	int success = 1;

	tx_data[0] = 0x0;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 
		(AES_OPMODE<<4)|
		(RG_128_256<<1)|
		AES_ARIA;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	memcpy(tx_data,IV,16);
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	delay_us(30);
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////

}
int OPERATION_MODE_ENC_ONLY(unsigned char *PLAINTEXT,unsigned char *CYPERTEXT)
{

	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];	   
	int success = 1;

	////////////////////////////////////////////////////////////////////////////////////////////////////////////


	{
		memcpy(tx_data,PLAINTEXT,16);
		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	

		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
		if( memcmp(rx_data,CYPERTEXT,16) != 0)
		{
			success = 0;
			printk("\r\n FAIL TO TEST TV");
			printk("\r\n rx_data\r\n");
			printbyte(rx_data,16);
			printk("\r\n CYPERTEXT \r\n");
			printbyte(CYPERTEXT,16);			
		}
		else
		{
			printk("\r\n PASS ");
		}
	}

	return success;
}

int OPERATION_MODE_DEC_OLNY(unsigned char *PLAINTEXT,unsigned char *CYPERTEXT)
{

	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];	   
	int success = 1;


	{
		memcpy(tx_data, CYPERTEXT,16);
		tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
		delay_us(2);	

		tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		

		
		
		if( memcmp(rx_data,PLAINTEXT,16) != 0)
		{
			printk("\r\n FAIL TO TEST TV");
			printk("\r\nCYPTERTEXT");
			printbyte(CYPERTEXT,16);
			printk("\r\n rx_data");
			printbyte(rx_data,16);
			printk("\r\n PLAINTEXT ");
			printbyte(PLAINTEXT,16);			
			printk("\r\n FAIL");
			success = 0;
		}
		else
		{
			printk("\r\n PASS ");
			
		}
	}
	return success;
}
//#define CHANGE
int TCOMM001_S()
{

	int i,j,k;
	int success =1;
	unsigned char TEXT_IN[8][16];
	unsigned char TEXT_IN2[8][16];	
	unsigned char IV[8][16];	
	unsigned char ENC_OUT_CBC[8][16];
	unsigned char DEC_OUT_CBC[8][16];
	unsigned char TEXT_IN_1[12][16];
	unsigned char TEXT_IN_1_REV[12][16];

	unsigned char TEXT_IN2_1[12][16];
	unsigned char TEXT_IN2_1_REV[12][16];
	
	unsigned char TEXT_IN_1_ENC_OUT[12][16];
	unsigned char TEXT_IN_1_ENC_OUT_REV[12][16];

	unsigned char TEXT_IN2_1_DEC_OUT[12][16];
	unsigned char TEXT_IN2_1_DEC_OUT_REV[12][16];


	unsigned char TEXT_IN_REV[8][16];
	unsigned char TEXT_IN2_REV[8][16];	
	unsigned char IV_REV[8][16];	
	unsigned char ENC_OUT_CBC_REV[8][16];	
	unsigned char DEC_OUT_CBC_REV[8][16];	
	int CNT_TEXT_IN = 0;
	int CNT_TEXT_IN2 = 0;
	int CNT_IV = 0;
	int CNT_ENC_OUT_CBC =0;


	unsigned char KEY32[32] ;//?ê??ë ¥ ê¹ë³´ê´? 
	printk("\r\n ================================== TCOMM001_S ================================== ");
	hexstr2bytes("00000000000000000000000000000000", KEY32);
	hexstr2bytes("000102030405060708090A0B0C0D0E0F", KEY32+16);	
	KEY_SET(KEY32);


	hexstr2bytes("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", IV[0]);	
	hexstr2bytes("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", IV[1]);		
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV[2]);	
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV[3]);	
	hexstr2bytes("00000000000000000000000000000000", IV[4]);	
	hexstr2bytes("00000000000000000000000000000000", IV[5]);	
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV[6]);	
	hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0", IV[7]);	


	hexstr2bytes("17c6a3eec47f7d19a1e82bb8504b4920", TEXT_IN[0]);	
	hexstr2bytes("3144202FCE126CE3B5F38351038735B5", TEXT_IN[1]);		
	hexstr2bytes("3F788A07F5451D5EB4BC7A04A6E574CB", TEXT_IN[2]);	
	hexstr2bytes("F4C0E6203995E217050F0976E22AA2C7", TEXT_IN[3]);	
	hexstr2bytes("17c6a3eec47f7d19a1e82bb8504b4920", TEXT_IN[4]);	
	hexstr2bytes("3144202FCE126CE3B5F38351038735B5", TEXT_IN[5]);	
	hexstr2bytes("3F788A07F5451D5EB4BC7A04A6E574CB", TEXT_IN[6]);	
	hexstr2bytes("F4C0E6203995E217050F0976E22AA2C7", TEXT_IN[7]);	


	hexstr2bytes("2c1447e94acb1c5d300f385471585052", TEXT_IN2[0]);	
	hexstr2bytes("c8af99fff4cf91725d8928590a5657c5", TEXT_IN2[1]);		
	hexstr2bytes("56ed06b136cee6e88f1dfd140a03dcf8", TEXT_IN2[2]);	
	hexstr2bytes("19b128a00d329d1e7faacab25824ebfb", TEXT_IN2[3]);

	hexstr2bytes("2c1447e94acb1c5d300f385471585052", ENC_OUT_CBC[0]);	
	hexstr2bytes("c8af99fff4cf91725d8928590a5657c5", ENC_OUT_CBC[1]);		
	hexstr2bytes("56ed06b136cee6e88f1dfd140a03dcf8", ENC_OUT_CBC[2]);	
	hexstr2bytes("19b128a00d329d1e7faacab25824ebfb", ENC_OUT_CBC[3]);

	hexstr2bytes("17c6a3eec47f7d19a1e82bb8504b4920", ENC_OUT_CBC[4]);	
	hexstr2bytes("3144202fce126ce3b5f38351038735b5", ENC_OUT_CBC[5]);		
	hexstr2bytes("3f788a07f5451d5eb4bc7a04a6e574cb", ENC_OUT_CBC[6]);	
	hexstr2bytes("f4c0e6203995e217050f0976e22aa2c7", ENC_OUT_CBC[7]);


	

	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb", TEXT_IN_1[0]);	
	hexstr2bytes("11111111cccccccc11111111dddddddd", TEXT_IN_1[1]);		
	hexstr2bytes("22222222aaaaaaaa22222222bbbbbbbb", TEXT_IN_1[2]);	
	hexstr2bytes("22222222cccccccc22222222dddddddd", TEXT_IN_1[3]);	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb", TEXT_IN_1[4]);	
	hexstr2bytes("11111111cccccccc11111111dddddddd", TEXT_IN_1[5]);	
	hexstr2bytes("22222222aaaaaaaa22222222bbbbbbbb", TEXT_IN_1[6]);	
	hexstr2bytes("22222222cccccccc22222222dddddddd", TEXT_IN_1[7]);	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb", TEXT_IN_1[8]);	
	hexstr2bytes("11111111cccccccc11111111dddddddd", TEXT_IN_1[9]);	
	hexstr2bytes("22222222aaaaaaaa22222222bbbbbbbb", TEXT_IN_1[10]);	
	hexstr2bytes("22222222cccccccc22222222dddddddd", TEXT_IN_1[11]);	

	hexstr2bytes("3720e53ba7d615383406b09f0a05a200", TEXT_IN2_1[0]);	
	hexstr2bytes("0063063f0560083483faeb041c8adece", TEXT_IN2_1[1]);		
	hexstr2bytes("f30cf80cefb002a0d280759168ec01db", TEXT_IN2_1[2]);	
	hexstr2bytes("3d49f61aced260bd43eec0a2731730ee", TEXT_IN2_1[3]);	
	hexstr2bytes("ac5d7de805a0bf1c57c854501af60fa1", TEXT_IN2_1[4]);	
	hexstr2bytes("1497e2a34519dea1569e91e5b5ccae2f", TEXT_IN2_1[5]);	
	hexstr2bytes("f3bfa1bf975f4571f48be191613546c3", TEXT_IN2_1[6]);	
	hexstr2bytes("911163c085f871f0e7ae5f2a085b8185", TEXT_IN2_1[7]);	
	hexstr2bytes("3720e53ba7d615383406b09f0a05a200", TEXT_IN2_1[8]);	
	hexstr2bytes("c07c21e6370f413a5d132500a6828501", TEXT_IN2_1[9]);	
	hexstr2bytes("7c61b434c7b7ca9685a51071861e4d4b", TEXT_IN2_1[10]);	
	hexstr2bytes("b873b599b479e2d573dddeafba89f812", TEXT_IN2_1[11]);	

	hexstr2bytes("3720e53ba7d615383406b09f0a05a200", TEXT_IN_1_ENC_OUT[0]);	
	hexstr2bytes("0063063f0560083483faeb041c8adece", TEXT_IN_1_ENC_OUT[1]);		
	hexstr2bytes("f30cf80cefb002a0d280759168ec01db", TEXT_IN_1_ENC_OUT[2]);	
	hexstr2bytes("3d49f61aced260bd43eec0a2731730ee", TEXT_IN_1_ENC_OUT[3]);	
	hexstr2bytes("ac5d7de805a0bf1c57c854501af60fa1", TEXT_IN_1_ENC_OUT[4]);	
	hexstr2bytes("1497e2a34519dea1569e91e5b5ccae2f", TEXT_IN_1_ENC_OUT[5]);	
	hexstr2bytes("f3bfa1bf975f4571f48be191613546c3", TEXT_IN_1_ENC_OUT[6]);	
	hexstr2bytes("911163c085f871f0e7ae5f2a085b8185", TEXT_IN_1_ENC_OUT[7]);	
	hexstr2bytes("3720e53ba7d615383406b09f0a05a200", TEXT_IN_1_ENC_OUT[8]);	
	hexstr2bytes("c07c21e6370f413a5d132500a6828501", TEXT_IN_1_ENC_OUT[9]);	
	hexstr2bytes("7c61b434c7b7ca9685a51071861e4d4b", TEXT_IN_1_ENC_OUT[10]);	
	hexstr2bytes("b873b599b479e2d573dddeafba89f812", TEXT_IN_1_ENC_OUT[11]);	

	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb", TEXT_IN2_1_DEC_OUT[0]);	
	hexstr2bytes("11111111cccccccc11111111dddddddd", TEXT_IN2_1_DEC_OUT[1]);		
	hexstr2bytes("22222222aaaaaaaa22222222bbbbbbbb", TEXT_IN2_1_DEC_OUT[2]);	
	hexstr2bytes("22222222cccccccc22222222dddddddd", TEXT_IN2_1_DEC_OUT[3]);	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb", TEXT_IN2_1_DEC_OUT[4]);	
	hexstr2bytes("11111111cccccccc11111111dddddddd", TEXT_IN2_1_DEC_OUT[5]);	
	hexstr2bytes("22222222aaaaaaaa22222222bbbbbbbb", TEXT_IN2_1_DEC_OUT[6]);	
	hexstr2bytes("22222222cccccccc22222222dddddddd", TEXT_IN2_1_DEC_OUT[7]);	
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb", TEXT_IN2_1_DEC_OUT[8]);	
	hexstr2bytes("11111111cccccccc11111111dddddddd", TEXT_IN2_1_DEC_OUT[9]);	
	hexstr2bytes("22222222aaaaaaaa22222222bbbbbbbb", TEXT_IN2_1_DEC_OUT[10]);	
	hexstr2bytes("22222222cccccccc22222222dddddddd", TEXT_IN2_1_DEC_OUT[11]);
	
	for( i = 0; i < 8 ; i++)
	{
		j = 15;
		for(k = 0; k < 16; k++)
		{
			IV_REV[i][k] = IV[i][j];
			TEXT_IN_REV[i][k] = TEXT_IN[i][j];
			TEXT_IN2_REV[i][k] = TEXT_IN2[i][j];		
			ENC_OUT_CBC_REV[i][k] = ENC_OUT_CBC[i][j];
			j--;
		}

	}
	for( i = 0; i < 12 ; i++)
	{
		j = 15;
		for(k = 0; k < 16; k++)
		{
			TEXT_IN_1_REV[i][k] = TEXT_IN_1[i][j];
			TEXT_IN2_1_REV[i][k] = TEXT_IN2_1[i][j];
			TEXT_IN_1_ENC_OUT_REV[i][k] = TEXT_IN_1_ENC_OUT[i][j];
			TEXT_IN2_1_DEC_OUT_REV[i][k] = TEXT_IN2_1_DEC_OUT[i][j];
			
			j--;
		}

	}
	printk("\r\n CBC");
	/////////////////////////////////////////////////////////////////////////////
	SET_IV(IV_REV[CNT_IV++],MODE_CBC,RG_128,RG_ARIA);
	for(i = 0; i < 4; i++)
	{
		
		if(OPERATION_MODE_ENC_ONLY(TEXT_IN_REV[CNT_TEXT_IN++],ENC_OUT_CBC_REV[CNT_ENC_OUT_CBC++]) == 0)
		{
			success = 0;
		}
	}
	END_OPERATION();
	//////////////////////////////////////////////////////////////////////////////	
	/////////////////////////////////////////////////////////////////////////////
	SET_IV(IV_REV[CNT_IV++],MODE_CBC,RG_128,RG_ARIA);
	for(i = 0; i < 4; i++)
	{
		
		if(OPERATION_MODE_DEC_OLNY(ENC_OUT_CBC_REV[CNT_ENC_OUT_CBC++],TEXT_IN2_REV[CNT_TEXT_IN2++]) == 0)
		{
			success = 0;
		}
	}
	END_OPERATION();
	//////////////////////////////////////////////////////////////////////////////	
	hexstr2bytes("00000000000000000000000000000000", KEY32);
	hexstr2bytes("00112233445566778899aabbccddeeff", KEY32+16);	
	KEY_SET(KEY32);
	printk("\r\n MODE_OFB");

	/////////////////////////////////////////////////////////////////////////////
	SET_IV(IV_REV[CNT_IV++],MODE_OFB,RG_128,RG_ARIA);
	for(i = 0; i < 4; i++)
	{
		
		if(OPERATION_MODE_ENC_ONLY(TEXT_IN_1_REV[i],TEXT_IN_1_ENC_OUT_REV[i]) == 0)
		{
			success = 0;
		}
	}
	END_OPERATION();
	//////////////////////////////////////////////////////////////////////////////	
	/////////////////////////////////////////////////////////////////////////////
	SET_IV(IV_REV[CNT_IV++],MODE_OFB,RG_128,RG_ARIA);
	for(i = 0; i < 4; i++)
	{
		#ifdef CHANGE
		if(OPERATION_MODE_DEC_OLNY(TEXT_IN2_1_REV[i],TEXT_IN2_1_DEC_OUT_REV[i]) == 0)
		#else
		if(OPERATION_MODE_DEC_OLNY(TEXT_IN2_1_DEC_OUT_REV[i],TEXT_IN2_1_REV[i]) == 0)		
		#endif
		{
			success = 0;
		}
	}
	END_OPERATION();
	
	printk("\r\n MODE_CTR");
	/////////////////////////////////////////////////////////////////////////////
	SET_IV(IV_REV[CNT_IV++],MODE_CTR,RG_128,RG_ARIA);
	for(i = 4; i < 8; i++)
	{
		
		if(OPERATION_MODE_ENC_ONLY(TEXT_IN_1_REV[i],TEXT_IN_1_ENC_OUT_REV[i]) == 0)
		{
			success = 0;
		}
	}
	END_OPERATION();
	//////////////////////////////////////////////////////////////////////////////	
	/////////////////////////////////////////////////////////////////////////////
	SET_IV(IV_REV[CNT_IV++],MODE_CTR,RG_128,RG_ARIA);
	for(i = 4; i < 8; i++)
	{
		
#ifdef CHANGE
	if(OPERATION_MODE_DEC_OLNY(TEXT_IN2_1_REV[i],TEXT_IN2_1_DEC_OUT_REV[i]) == 0)
#else
	if(OPERATION_MODE_DEC_OLNY(TEXT_IN2_1_DEC_OUT_REV[i],TEXT_IN2_1_REV[i]) == 0)		
#endif

		{
			success = 0;
		}
	}
	END_OPERATION();

	printk("\r\n MODE_CFB");
	printk("\r\n IV");
	printbyte(IV[CNT_IV],16);
	/////////////////////////////////////////////////////////////////////////////
	SET_IV(IV_REV[CNT_IV++],MODE_CFB,RG_128,RG_ARIA);
	for(i = 8; i < 12; i++)
	{
		
		if(OPERATION_MODE_ENC_ONLY(TEXT_IN_1_REV[i],TEXT_IN_1_ENC_OUT_REV[i]) == 0)
		{
			success = 0;
		}
	}
	END_OPERATION();
	//////////////////////////////////////////////////////////////////////////////	
	/////////////////////////////////////////////////////////////////////////////
	printk("\r\n IV");
	printbyte(IV[CNT_IV],16);
	SET_IV(IV_REV[CNT_IV++],MODE_CFB,RG_128,RG_ARIA);
	for(i = 8; i < 12; i++)
	{

		printk("\r\n CT");
		printbyte(TEXT_IN2_1_REV[i],16);		
#ifdef CHANGE
		if(OPERATION_MODE_DEC_OLNY(TEXT_IN2_1_REV[i],TEXT_IN2_1_DEC_OUT_REV[i]) == 0)
#else
		if(OPERATION_MODE_DEC_OLNY(TEXT_IN2_1_DEC_OUT_REV[i],TEXT_IN2_1_REV[i]) == 0)		
#endif

		{
			success = 0;
		}
	}
	END_OPERATION();
	



	if(1 == success)
		return 3;
	else
		return 0;
}



#endif
#define ARM7
//#define DEBUG_DELAY
//----- SPI Interface
#ifdef PA05
#undef PA05
#endif
#ifdef PA11
#undef PA11
#endif
#ifdef PA30
#undef PA30
#endif
#ifdef PA31
#undef PA31
#endif
#ifdef PA22
#undef PA22
#endif
#if 0

#define PA05    ((unsigned int) 1 << 5)
#define PA11    ((unsigned int) 1 << 11)
#define PA31    ((unsigned int) 1 << 31)
#define PA30    ((unsigned int) 1 << 30)
#define PA22    ((unsigned int) 1 << 22)

#define CS0         PA11    // SPI CS 0
#define CS1         PA31    // SPI CS 1
#define CS2         PA30    // SPI CS 2
#define CS3         PA05    // SPI CS 3

int Mycs2 = 2;
void send_data_arm7(unsigned char *buffer,int size)
{
#if 0
int i = 0;
unsigned char rx_data[512];
unsigned int temp_cs = 0x00;

//	printk("\r\n buffer");
//	printbyte(buffer,size);
#ifdef ARM7

//	    { AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS2);AT91F_PIO_CfgOutput(AT91C_BASE_PIOA, CS1);  temp_cs = cs_spi1+1; }   // CS : Low
	   //printk("\r\n Mycs2 %d",2);

#if 0	   
	   if ( Mycs2 == 0 ) { AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS0); temp_cs = Mycs2 + 1;}   // CS : Low
	   else if ( Mycs2 == 1 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS1); temp_cs = 1<< Mycs2; }  // CS : Low
	   else if ( Mycs2 == 2 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS2);  temp_cs = 1<< Mycs2; }	// CS : Low
	   else if ( Mycs2 == 3 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS3);  temp_cs = 1<< Mycs2; }	// CS : Low
#else
	   if ( Mycs2 == 0 ) { AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS0); temp_cs = Mycs2 + 1;}   // CS : Low
	   else if ( Mycs2 == 1 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS1); temp_cs = Mycs2+1; }  // CS : Low
	   else if ( Mycs2 == 2 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS2);  temp_cs = Mycs2+1; }	// CS : Low
	   else if ( Mycs2 == 3 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS3);  temp_cs = Mycs2+1; }	// CS : Low
#endif
	   for( i = 0; i < size; i++)
	    {
	    	AT91F_SPI_PutChar(AT91C_BASE_SPI, (unsigned int)buffer[i],  temp_cs);                // 0000 0001
	    	//printk("\r\n  %x",buffer[i]);
		    while (!(*AT91C_SPI_SR & 0x0200));                              // transmit complete ?
	    }		
	   //printk("\r\n Mycs2 %d",2);

	  //  AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS2);  // CS : High
	  
	   if	   ( Mycs2 == 0 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS0);  // CS : High
	   else if ( Mycs2 == 1 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS1);  // CS : High
	   else if ( Mycs2 == 2 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS2);  // CS : High
	   else if ( Mycs2 == 3 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS3);  // CS : High
	   		//printk("\r\n Mycs2 %d",2);
#else
	send_data(buffer,size);
#endif	

#endif

//--- Stop

}


void read_data_arm7(unsigned char *tx_buffer,unsigned char *rx_buffer, int size)
{
#if 0
/*
  int k = 0;
   delay_us(100);	
   _spi_start();
   
   for(k = 0; k < 5; k++)
		_spi_write_byte(tx_buffer[k]);

  // _spi_stop();
//	 delay_us(100);
//   _spi_start();
  for(k = 0; k < size; k++)
	rx_buffer[k] = _spi_read_byte();
       _spi_stop();
*/
int i = 0;
unsigned char rx_data[512];
unsigned char temp_cs = 0x00;
int cs_spi1 = 2;
#ifdef ARM7
		delay_us(100);
		//printk("\r\n read Mycs2 %d",2);
		//CS Down
	//	{ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS2);  temp_cs = 1<< cs_spi1; }   // CS : Low
		if ( Mycs2 == 0 ) { AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS0); temp_cs = Mycs2 + 1;}   // CS : Low
		else if ( Mycs2 == 1 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS1); temp_cs = Mycs2 + 1; }  // CS : Low
		else if ( Mycs2 == 2 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS2);  temp_cs = Mycs2 + 1; }	 // CS : Low
		else if ( Mycs2 == 3 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS3);  temp_cs = Mycs2 + 1; }	 // CS : Low


	   for( i = 0; i < 5; i++)
	    {
	    	AT91F_SPI_PutChar(AT91C_BASE_SPI, tx_buffer[i],  temp_cs);                // 0000 0001
		    while (!(*AT91C_SPI_SR & 0x0200));                              // transmit complete ?
	    }		
	    
	    #if 1
		//CS UP
			//	printk("\r\n read Mycs2 %d",2);

	   //AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS2);  // CS : High

			if		( Mycs2 == 0 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS0);	// CS : High
			else if ( Mycs2 == 1 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS1);	// CS : High
			else if ( Mycs2 == 2 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS2);	// CS : High
			else if ( Mycs2 == 3 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS3);	// CS : High	   
	   
//	    delay_us(100);
		delay_us(50);
	    
	    //CS Down
	  // { AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS2);  temp_cs = 1<< cs; }   // CS : Low
	  
			if ( Mycs2 == 0 ) { AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS0); temp_cs = Mycs2 + 1;}   // CS : Low
			else if ( Mycs2 == 1 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS1); temp_cs = Mycs2 + 1; }  // CS : Low
			else if ( Mycs2 == 2 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS2);  temp_cs = Mycs2 + 1; }	 // CS : Low
			else if ( Mycs2 == 3 ){ AT91F_PIO_ClearOutput(AT91C_BASE_PIOA, CS3);  temp_cs = Mycs2 + 1; }	 // CS : Low

		#endif

	    for( i = 0 ; i < size; i++)
	    {
	       AT91F_SPI_PutChar(AT91C_BASE_SPI, 0x00, temp_cs );        // 0000 0000        // Read data
	           while(!(*AT91C_SPI_SR & 0x0200));                       // transmit complete ?
        	   rx_buffer[i] = *AT91C_SPI_RDR & 0xff ;	
	     }
		//CS UP

	  // AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS2);  // CS : High
		
		//--- Stop
			if		( Mycs2 == 0 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS0);	// CS : High
			else if ( Mycs2 == 1 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS1);	// CS : High
			else if ( Mycs2 == 2 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS2);	// CS : High
			else if ( Mycs2 == 3 ) AT91F_PIO_SetOutput(AT91C_BASE_PIOA, CS3);	// CS : High
				//	printk("\r\n read Mycs2 %d",2);
	  
#else

	read_data(tx_buffer,rx_buffer,32);
#endif
#endif
	   
}
#endif
void test()
{
	unsigned char buffer[512];
	unsigned char buffer_receive[256];
	buffer[0] = SPI1_READ_DATA;
	buffer[1] = 0;
	buffer[2] = Get_RSA_PlainText_M;
	buffer[3] = 0x01;
	buffer[4] = 0;
	read_data_arm7(buffer,buffer_receive,256);
	printk("\r\n Get_RSA_PlainText_M");	
	printbyte(buffer_receive,256);
}

int _ecdh_gen_pub_key(uint8_t* sk,point *p1)
{

	unsigned char buffer_ecdh[256];
	unsigned char buffer_receive[256];

	int i = 0;	

       for(i = 0; i < 256; i++)
	   	buffer_ecdh[i] = i;
#if 0
#ifdef ARM7
    printk("\r\n ARM7");    
	   send_data_arm7(buffer_ecdh,5);
	   Delay_us(100); 
	   read_data_only_arm7(buffer_receive, 5);
	   printk("\r\n recieved \r\n");
	   printbyte(buffer_receive,5);
#else
    printk("\r\n GPIO");    
	   send_data(buffer_ecdh,5);
	   read_data_raw(buffer_receive, 5);
	   printk("\r\n recieved \r\n");
	   printbyte(buffer_receive,5);
#endif
	   return;
#endif  
	printk("\r\n ECDH P256 \r\n");
	//printk("\r\n 250k");
	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = SIZE_ECDH_256;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
#ifdef ARM7
    printk("\r\n ARM7");    
	send_data_arm7(buffer_ecdh,5);
	//printk("\r\n ecdh_test");
	//send_data_arm7(buffer_ecdh,37);
#else
	//send_data(buffer_ecdh,37);
	printk("\r\n GPIO");
	send_data(buffer_ecdh,5);
#endif
	
	printk("\r\n read write test");
	delay_ms(40);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	
	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Set_ECDH_PrivateKey;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
	memcpy(&buffer_ecdh[5],sk,32);
	Serial.println("Set_ECDH_PrivateKey");
	for( i = 0; i < 37 ; i++)
	Serial.println(buffer_ecdh[i],HEX);
	
#ifdef ARM7
    printk("\r\n ARM7");    
	send_data_arm7(buffer_ecdh,37);
	//printk("\r\n ecdh_test");
	//send_data_arm7(buffer_ecdh,37);
#else
	//send_data(buffer_ecdh,37);
	printk("\r\n GPIO");
	send_data(buffer_ecdh,37);
#endif
//	write_spi_data(buffer_ecdh,37);
	
#if 0
	delay_ms(WATING_TIME);
	delay_ms(4000);
	printk("\r\n SEND SLEEP");
	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = SLEEP;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
	#ifdef ARM7
	send_data_arm7(buffer_ecdh,5);
	#else
	send_data(buffer_ecdh,5);
	#endif
	delay_ms(WATING_TIME*2);
	WakeUP();
#endif	
    delay_ms(40);
#ifdef DEBUG_DELAY
	delay_ms(4000);
#endif

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Create_ECHD_PublicKey;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
#ifdef ARM7
	send_data_arm7(buffer_ecdh,5);
#else	
	send_data(buffer_ecdh,5);
#endif
	
#if 0
	delay_ms(WATING_TIME);
	delay_ms(4000);

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = DEEP_SLEEP;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
	printk("\r\n SEND DEEP_SLEEP\r\n");
	#ifdef ARM7
	send_data_arm7(buffer_ecdh,5);
	#else
	send_data(buffer_ecdh,5);
	#endif
#endif

	delay_ms(200);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
	buffer_ecdh[0] = SPI1_READ_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Get_ECDH_PublicKey_X;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
#ifdef ARM7
	read_data_arm7(buffer_ecdh,buffer_receive,32);
#else
	read_data(buffer_ecdh,buffer_receive,32);
#endif
	memcpy(p1->x,buffer_receive,32);
	
	delay_ms(40);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	
	buffer_ecdh[0] = SPI1_READ_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Get_ECDH_PublicKey_Y;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
#ifdef ARM7
	read_data_arm7(buffer_ecdh,buffer_receive,32);
#else
	read_data(buffer_ecdh,buffer_receive,32);
#endif
	memcpy(p1->y,buffer_receive,32);




}
#define ECDH_SESSION_KEY_GEN_PRINT
int _ecdh_gen_session_key(uint8_t* sk,point *p1, uint8_t *key,size_t* key_length)
{
		unsigned char buffer_ecdh[256];
		unsigned char buffer_receive[256];
		unsigned char XofKey[32];
		int i = 0;	
//				printf("\r\n ECDH P256 \r\n");
				//printf("\r\n 250k");
				buffer_ecdh[0] = SPI1_WRITE_DATA;
				buffer_ecdh[1] = 0;
				buffer_ecdh[2] = SIZE_ECDH_256;
				buffer_ecdh[3] = 0;
				buffer_ecdh[4] = 0;
#ifdef ARM7
//				printf("\r\n ARM7");	
				send_data_arm7(buffer_ecdh,5);
				//printf("\r\n ecdh_test");
				//send_data_arm7(buffer_ecdh,37);
#else
				//send_data(buffer_ecdh,37);
				printf("\r\n GPIO");
				send_data(buffer_ecdh,5);
#endif
				
//				printf("\r\n read write test");
				delay_ms(40);
#ifdef DEBUG_DELAY	
				delay_ms(4000);
#endif	
				buffer_ecdh[0] = SPI1_WRITE_DATA;
				buffer_ecdh[1] = 0;
				buffer_ecdh[2] = Set_ECDH_PrivateKey;
				buffer_ecdh[3] = 0;
				buffer_ecdh[4] = 32;
				memcpy(&buffer_ecdh[5],sk,32);
				
#ifdef ARM7
//				printf("\r\n ARM7");	
				send_data_arm7(buffer_ecdh,37);
				//printf("\r\n ecdh_test");
				//send_data_arm7(buffer_ecdh,37);
#else
				//send_data(buffer_ecdh,37);
				printf("\r\n GPIO");
				send_data(buffer_ecdh,37);
#endif
		
		
					delay_ms(40);
					buffer_ecdh[0] = SPI1_WRITE_DATA;
					buffer_ecdh[1] = 0;
					buffer_ecdh[2] = Set_ECDH_PublicKey_X;
					buffer_ecdh[3] = 0;
					buffer_ecdh[4] = 32;
				//hexstr2bytes("764ea0ef1a596b196e8b7316e60de4edccbae87821e767b50f6f36656e7ebe2a",&buffer_ecdh[5]);
				memcpy(&buffer_ecdh[5],p1->x,32);
//				printf("\r\n Set_ECDH_PublicKey_X");
//				printbyte(&buffer_ecdh[5],32);
#ifdef ARM7
				send_data_arm7(buffer_ecdh,37);
#else
				send_data(buffer_ecdh,37);
#endif
				delay_ms(40);
#ifdef DEBUG_DELAY	
				delay_ms(4000);
#endif
			
				buffer_ecdh[0] = SPI1_WRITE_DATA;
				buffer_ecdh[1] = 0;
				buffer_ecdh[2] = Set_ECDH_PublicKey_Y;
				buffer_ecdh[3] = 0;
				buffer_ecdh[4] = 32;
				//hexstr2bytes("fb526fbfae10d2a0d8fab4d4bdcc883bbfadee2a73ea66a1a1fe816c282d2ce9",&buffer_ecdh[5]);
				memcpy(&buffer_ecdh[5],p1->y,32);
//				printf("\r\n Set_ECDH_PublicKey_Y");
//				printbyte(&buffer_ecdh[5],32);
#ifdef ARM7
				send_data_arm7(buffer_ecdh,37);
#else
				send_data(buffer_ecdh,37);
#endif
				delay_ms(40);
#ifdef DEBUG_DELAY	
				delay_ms(4000);
#endif	
			
				buffer_ecdh[0] = SPI1_WRITE_DATA;
				buffer_ecdh[1] = 0;
				buffer_ecdh[2] = Create_ECHD_KEY;
				buffer_ecdh[3] = 0;
				buffer_ecdh[4] = 0;
#ifdef ARM7
				send_data_arm7(buffer_ecdh,5);
#else
				send_data(buffer_ecdh,5);
#endif
				delay_ms(200);
#ifdef DEBUG_DELAY	
				delay_ms(4000);
#endif	


#if 0
				buffer_ecdh[0] = SPI1_READ_DATA;
				buffer_ecdh[1] = 0;
				buffer_ecdh[2] = Get_ECDH_KEY_X;
				buffer_ecdh[3] = 0;
				buffer_ecdh[4] = 32;
#ifdef ARM7
				read_data_arm7(buffer_ecdh,buffer_receive,32);
#else
				read_data(buffer_ecdh,buffer_receive,32);
#endif
				//printf("\r\nGet_ECDH_KEY_X\r\n");
				//printbyte(buffer_receive,32);
				
				//printf("\r\n Expected _ECDH_KEY_X\r\n");
				//printf("\r\n9e29727653fe830e9709045ead243fa44acec4efb7322048894c4d06b484ce58"); 
			
				//hexstr2bytes("9e29727653fe830e9709045ead243fa44acec4efb7322048894c4d06b484ce58",temp_buffer);
				//memcpy(XofKey,buffer_receive,32);
				//if(memcmp(buffer_receive,temp_buffer,32) == 0)
				//	printf("\r\n PASS");
				//else
				//	printf("\r\n FAIL");	

#endif

#ifdef DEBUG_DELAY	
				delay_ms(4000);
#endif	
			
				buffer_ecdh[0] = SPI1_READ_DATA;
				buffer_ecdh[1] = 0;
				buffer_ecdh[2] = Get_ECDH_KEY_Y;
				buffer_ecdh[3] = 0;
				buffer_ecdh[4] = 32;
#ifdef ARM7
				read_data_arm7(buffer_ecdh,buffer_receive,32);
#else
				read_data(buffer_ecdh,buffer_receive,32);
#endif
				memcpy(key,buffer_receive,32);
#if 0

				//printf("\r\nGet_ECDH_KEY_Y\r\n");
				//printbyte(buffer_receive,32);
				//printf("\r\n Expected _ECDH_KEY_Y\r\n");
				//printf("\r\n87fc5a996074a1852a6385874da7c8875932e612c5815e6e8c7376abb265201c"); 
			
			
				hexstr2bytes("87fc5a996074a1852a6385874da7c8875932e612c5815e6e8c7376abb265201c",temp_buffer);
			
				if(memcmp(buffer_receive,temp_buffer,32) == 0)
					printf("\r\n PASS");
				else
					printf("\r\n FAIL");	

					{
						Dorca3_CM0_Close();
						Dorca3_SPI_Init(SPI0_SPEED);				
						usleep(200*1000);
						GenINT0();
						SET_SPI0(); 

						unsigned char Sha_result[32];
						STANDARD_SHA_MODE(XofKey, Sha_result, 32);
						memcpy(key,buffer_receive,32);
						*key_length = 32;
						WRITE_TEST_5();
						Dorca3_Close();
						GenINT0();
						usleep(200*1000);
						Dorca3_CM0_SPI_Init(SPI1_SPEED);						
					}
#endif

#if 0		
		delay_ms(40);
		buffer_ecdh[0] = SPI1_WRITE_DATA;
		buffer_ecdh[1] = 0;
		buffer_ecdh[2] = SIZE_ECDH_256;
		buffer_ecdh[3] = 0;
		buffer_ecdh[4] = 0;


		//send_data_arm7(buffer_ecdh,5);
		//printf("\r\n ecdh_test");
		//send_data_arm7(buffer_ecdh,37);
		

		delay_ms(40);
#ifdef DEBUG_DELAY	
		delay_ms(4000);
#endif	
		buffer_ecdh[0] = SPI1_WRITE_DATA;
		buffer_ecdh[1] = 0;
		buffer_ecdh[2] = Set_ECDH_PrivateKey;
		buffer_ecdh[3] = 0;
		buffer_ecdh[4] = 32;
		memcpy(&buffer_ecdh[5],sk,32);
		send_data_arm7(buffer_ecdh,37);

		delay_ms(40);
		buffer_ecdh[0] = SPI1_WRITE_DATA;
		buffer_ecdh[1] = 0;
		buffer_ecdh[2] = Set_ECDH_PublicKey_X;
		buffer_ecdh[3] = 0;
		buffer_ecdh[4] = 32;
		memcpy(&buffer_ecdh[5],p1->x,32);
		send_data_arm7(buffer_ecdh,37);

		delay_ms(40);
#ifdef DEBUG_DELAY	
		delay_ms(4000);
#endif
	
		buffer_ecdh[0] = SPI1_WRITE_DATA;
		buffer_ecdh[1] = 0;
		buffer_ecdh[2] = Set_ECDH_PublicKey_Y;
		buffer_ecdh[3] = 0;
		buffer_ecdh[4] = 32;
		memcpy(&buffer_ecdh[5],p1->y,32);
		send_data_arm7(buffer_ecdh,37);
		delay_ms(40);

		buffer_ecdh[0] = SPI1_READ_DATA;
		buffer_ecdh[1] = 0;
		buffer_ecdh[2] = Get_ECDH_KEY_X;
		buffer_ecdh[3] = 0;
		buffer_ecdh[4] = 32;
		read_data_arm7(buffer_ecdh,buffer_receive,32);
		memcpy(XofKey,buffer_receive,32);
#ifdef ECDH_SESSION_KEY_GEN_PRINT
		printf("\r\nGet_ECDH_KEY_X\r\n");
		printbyte(buffer_receive,32);
		
		printf("\r\n Expected _ECDH_KEY_X\r\n");
		printf("\r\n9e29727653fe830e9709045ead243fa44acec4efb7322048894c4d06b484ce58"); 
	
		hexstr2bytes("9e29727653fe830e9709045ead243fa44acec4efb7322048894c4d06b484ce58",temp_buffer);
	
		if(memcmp(buffer_receive,temp_buffer,32) == 0)
			printf("\r\n PASS");
		else
			printf("\r\n FAIL");	
#endif	
		delay_ms(40);
#ifdef DEBUG_DELAY	
		delay_ms(4000);
#endif	
	
		buffer_ecdh[0] = SPI1_READ_DATA;
		buffer_ecdh[1] = 0;
		buffer_ecdh[2] = Get_ECDH_KEY_Y;
		buffer_ecdh[3] = 0;
		buffer_ecdh[4] = 32;
		read_data_arm7(buffer_ecdh,buffer_receive,32);

#ifdef ECDH_SESSION_KEY_GEN_PRINT

		printf("\r\nGet_ECDH_KEY_Y\r\n");
		printbyte(buffer_receive,32);
		printf("\r\n Expected _ECDH_KEY_Y\r\n");
		printf("\r\n87fc5a996074a1852a6385874da7c8875932e612c5815e6e8c7376abb265201c"); 
	
	
		hexstr2bytes("87fc5a996074a1852a6385874da7c8875932e612c5815e6e8c7376abb265201c",temp_buffer);
	
		if(memcmp(buffer_receive,temp_buffer,32) == 0)
			printf("\r\n PASS");
		else
			printf("\r\n FAIL");	
#endif


#endif
}

void TEST_ECDH_SESSION(void)
{
	uint8_t sk[32];
	uint8_t common_key[32];	
	size_t  key_length;
	int i;
	point p1;
	Serial.println("\r\n TEST _ecdh_gen_session_key");
	hexstr2bytes("c64d654e263cda95d6dc719d3cfd6c3b932b1fea6021b9e2ac36995c4d96ae3d",sk);
	hexstr2bytes("fb526fbfae10d2a0d8fab4d4bdcc883bbfadee2a73ea66a1a1fe816c282d2ce9",p1.y);
	hexstr2bytes("764ea0ef1a596b196e8b7316e60de4edccbae87821e767b50f6f36656e7ebe2a",p1.x);
	ecdh_gen_session_key(sk,&p1,common_key,&key_length);
	
	//printf("\r\nGet_ECDH_KEY_Y\r\n");
	//printbyte(buffer_receive,32);
	Serial.println("\r\n Expected _ECDH_KEY_Y\r\n");
	Serial.println("\r\n87fc5a996074a1852a6385874da7c8875932e612c5815e6e8c7376abb265201c"); 
	

	hexstr2bytes("87fc5a996074a1852a6385874da7c8875932e612c5815e6e8c7376abb265201c",temp_buffer);

	
	if( 0 == memcmp(temp_buffer,common_key,32) )
		Serial.println("TEST_ECDH_SESSION PASS");
	else
		Serial.println("TEST_ECDH_SESSION FAIL");

}
//#define DEBUG_DELAY
void TEST_ECDH_PUB(void)
{
	uint8_t sk[32];
	uint8_t common_key[32];	
	int i = 0;
	size_t  key_length;
	point p1;
	Serial.println("\r\n TEST ecdh_gen_pub_key");
	hexstr2bytes("c64d654e263cda95d6dc719d3cfd6c3b932b1fea6021b9e2ac36995c4d96ae3d",sk);
	ecdh_gen_pub_key(sk,&p1);
	Serial.println("\r\nGet_ECDH_PublicKey_X\r\n");
	for( i = 0; i < 32; i++)
		Serial.println(p1.x[i],HEX);
	
	Serial.println("\r\n Expected ECDH_PublicKey_X\r\n");
	Serial.println("\r\nefb50f68f26558c1d42847e82dc552607965049cc6f65d7ed8b8d02a1d8825f9");
	hexstr2bytes("efb50f68f26558c1d42847e82dc552607965049cc6f65d7ed8b8d02a1d8825f9",temp_buffer);
	if(memcmp(p1.x,temp_buffer,32) == 0)
		Serial.println("\r\n PASS");
	else
		Serial.println("\r\n FAIL");
	
	Serial.println("\r\nGet_ECDH_PublicKey_Y\r\n");
	for( i = 0; i < 32; i++)
		Serial.println(p1.y[i],HEX);
	
	Serial.println("\r\n Expected ECDH_PublicKey_Y\r\n");
	Serial.println("\r\n3ca531980f67c4843db00419470860d736577867c5eab3e3ed304fd253949202");

	hexstr2bytes("3ca531980f67c4843db00419470860d736577867c5eab3e3ed304fd253949202",temp_buffer);

	if(memcmp(p1.y,temp_buffer,32) == 0)
		Serial.println("\r\n PASS");
	else
		Serial.println("\r\n FAIL");	



}

void rsa_test()
{
#ifdef COMPARE
	unsigned char buffer[512];
	uint8_t  expected_result32[256];
	unsigned char buffer_receive[256];
	printk("\r\nRSA_TEST");

	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = SIZE_RSA_2048;
	buffer[3] = 0;
	buffer[4] = 0;
	send_data_arm7(buffer,5);
	delay_ms(40);
	hexstr2bytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011223344", buffer+5);//RSA_msg
	printk("\r\n rsa_test");
	printk("\r\n Set_RSA_PlainText_M");
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PlainText_M;
	buffer[3] = 0x01;
	buffer[4] = 00;
	send_data_arm7(buffer,256+5);
	printk("\r\n sent data:	00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011223344");

#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

	delay_ms(40);
	
	hexstr2bytes("F748D8D98ED057CF398C437FEFC615D757D3F8ECE6F2C580AE0780768F9EC83AAA081FF09E5317ED6099C63FD15CFE11172F78908CD58C03AEC93A481FF50E172204AFEDFC1F16AFDB990AAB45BE190BC19259BD4A1BFCDFBE2A298B3C0E318F78A33919882328DACAC85CB35A0DE537B16376975217E5A5EAAF98266B588C2DBAFD0BE371C34989CB36E623D75EFFEDBE4A951A6840982BC279B30FCD41DAC87C0074D462F1012900B8973B46ADC7EAC01770DFC632EA967F9471E9789831F3A410730FF914348BE111863C13376301079756A147D80103CE9FA688A338E22B2D916CAD42D673C9D00F08214DE544F5DE812A9A949189078B2BDA14B28CA62F", buffer+5);//RSA_n
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_Modulus_n;
	buffer[3] = 0x01;
	buffer[4] = 00;
	send_data_arm7(buffer,256+5);
	printk("\r\n Set_RSA_Modulus_n");
	printk("\r\n sent data:	F748D8D98ED057CF398C437FEFC615D757D3F8ECE6F2C580AE0780768F9EC83AAA081FF09E5317ED6099C63FD15CFE11172F78908CD58C03AEC93A481FF50E172204AFEDFC1F16AFDB990AAB45BE190BC19259BD4A1BFCDFBE2A298B3C0E318F78A33919882328DACAC85CB35A0DE537B16376975217E5A5EAAF98266B588C2DBAFD0BE371C34989CB36E623D75EFFEDBE4A951A6840982BC279B30FCD41DAC87C0074D462F1012900B8973B46ADC7EAC01770DFC632EA967F9471E9789831F3A410730FF914348BE111863C13376301079756A147D80103CE9FA688A338E22B2D916CAD42D673C9D00F08214DE544F5DE812A9A949189078B2BDA14B28CA62F");
	

#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

	delay_ms(40);

	
	hexstr2bytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001", buffer+5);//RSA_expo
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PublicExpo;
	buffer[3] = 0x01;
	buffer[4] = 00;
	printk("\r\n Set_RSA_PublicExpo");	
	send_data_arm7(buffer,256+5);
	printk("\r\n sent data:	00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");


#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

	delay_ms(40);

	
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Encrypt_RSA;
	buffer[3] = 0;
	buffer[4] = 0;
	send_data_arm7(buffer,5);
	printk("\r\n Encrypt_RSA");	

#ifdef DEBUG_DELAY	
	delay_ms(2*4000);
#endif

	delay_ms(64);
	delay_ms(64);


	buffer[0] = SPI1_READ_DATA;
	buffer[1] = 0;
	buffer[2] = Get_RSA_CipherText_C;
	buffer[3] = 0x01;
	buffer[4] = 0;
	read_data_arm7(buffer,buffer_receive,256);
	printk("\r\n Get_RSA_CipherText_C");	
	printk("\r\n receive data \r\n");
	printbyte2(buffer_receive,256);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
delay_ms(40);	


	hexstr2bytes("EE69099AFD9F99D6065D65E15F90B9237C16987D4872E2B994ED2B9E5685F9BA489AB936CC1E3DFD15B35FEE21536F8C2220AE43217D91D81C9ED01DE5BAEEF4EFC721D70D67B5166E43D82724F39BF0BD197C31E748518DEE63EC10987A08390B15CC4157677C54226A8B04B47684AEDD02B48C8ED48A44BD135397AC2869769B68C7D3BFACDB72AFCD7442C22517E044996CB68E0A311DF5D6D2D286372556F0193166CC364E654EF405DD22FBE584DBF60F0552960668FB69522C1B5264F194FAC9F35622E98227638FF28B910D8CC90E5011021212C96C64C85820877A7D1559235E99C32ABEF33D95E28E18CCA3442E6E3A432FFFEA10104A8EEE94C362", expected_result32);	
	//printk("\r\nrsa expected\r\n");  	
	//printbyte(buf.buffer,256);
	//printk("\r\nrsa result\r\n");  	
	//printbyte(expected_result32,256);
;
	if(memcmp(buffer_receive,expected_result32,256) != 0)
		printk("\r\n error RSA2048_Encode");
	else
		printk("\r\n OK RSA2048_Encode");


	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_CipherText_C;
	buffer[3] = 0x01;
	buffer[4] = 00;
	hexstr2bytes("EE69099AFD9F99D6065D65E15F90B9237C16987D4872E2B994ED2B9E5685F9BA489AB936CC1E3DFD15B35FEE21536F8C2220AE43217D91D81C9ED01DE5BAEEF4EFC721D70D67B5166E43D82724F39BF0BD197C31E748518DEE63EC10987A08390B15CC4157677C54226A8B04B47684AEDD02B48C8ED48A44BD135397AC2869769B68C7D3BFACDB72AFCD7442C22517E044996CB68E0A311DF5D6D2D286372556F0193166CC364E654EF405DD22FBE584DBF60F0552960668FB69522C1B5264F194FAC9F35622E98227638FF28B910D8CC90E5011021212C96C64C85820877A7D1559235E99C32ABEF33D95E28E18CCA3442E6E3A432FFFEA10104A8EEE94C362", buffer+5);//RSA_msg
	send_data_arm7(buffer,256+5);
	printk("\r\n Set_RSA_CipherText_C    ");	
	printk("\r\n sent data:    ");
	printbyte2(buffer,256);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
delay_ms(40);	


	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_Modulus_n;
	buffer[3] = 0x01;
	buffer[4] = 00;
	hexstr2bytes("F748D8D98ED057CF398C437FEFC615D757D3F8ECE6F2C580AE0780768F9EC83AAA081FF09E5317ED6099C63FD15CFE11172F78908CD58C03AEC93A481FF50E172204AFEDFC1F16AFDB990AAB45BE190BC19259BD4A1BFCDFBE2A298B3C0E318F78A33919882328DACAC85CB35A0DE537B16376975217E5A5EAAF98266B588C2DBAFD0BE371C34989CB36E623D75EFFEDBE4A951A6840982BC279B30FCD41DAC87C0074D462F1012900B8973B46ADC7EAC01770DFC632EA967F9471E9789831F3A410730FF914348BE111863C13376301079756A147D80103CE9FA688A338E22B2D916CAD42D673C9D00F08214DE544F5DE812A9A949189078B2BDA14B28CA62F", buffer+5);//RSA_n	
	send_data_arm7(buffer,256+5);
	printk("\r\n Set_RSA_Modulus_n    ");	
	printk("\r\n sent data:    ");
	printbyte2(buffer,256);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
delay_ms(40);		


	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PrivateKey_d;
	buffer[3] = 0x01;
	buffer[4] = 00;
	hexstr2bytes("1CBC9A76ADE208524C9DC03A5DE2E726DF4E02DF84F7317C82BCDC70EABFC905083D6978CCED5B1A7ADF63EA86AA07DC74954FAD7CB05455193AC94B186BA1F78E3C7D356AD7320BBDB94B441C16BB52626C5F815FDB60C79F91C6C227787EC9ED7B0A67AD2A68D5043BC48A132D0A362EA72060F5695186B67F316F458A44BFD1403D93A9B912CBB59815916A14A2BAD4F9A1ED578EBD2B5D472F623B4BB5F9B80B93572BEA61BD1068094E41E8390E2E28A351433EDD1A099A8C6E6892604AEF163A439B1CAE6A095E68943CA67B18C8DC7F98CC5F8EFA22BBC87D2E735783D2BAA38F4C17D5ED0C58366DCEF5E852DD3D6E0F63729543E2638B2914D72A01", buffer+5);//RSA_d	
	send_data_arm7(buffer,256+5);
	printk("\r\n Set_RSA_PrivateKey_d    ");		
	printk("\r\n sent data:    ");
	printbyte2(buffer,256);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
delay_ms(40);	


	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Decrypt_RSA;
	buffer[3] = 0;
	buffer[4] = 0;
	send_data_arm7(buffer,5);
	printk("\r\n Decrypt_RSA");
	delay_ms(5000);

	buffer[0] = SPI1_READ_DATA;
	buffer[1] = 0;
	buffer[2] = Get_RSA_PlainText_M;
	buffer[3] = 0x01;
	buffer[4] = 0;
	read_data_arm7(buffer,buffer_receive,256);
	printk("\r\n Get_RSA_PlainText_M");	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
delay_ms(40);	
	printbyte2(buffer_receive,256);
	hexstr2bytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011223344", expected_result32);
	if(memcmp(buffer_receive,expected_result32,256) != 0)
		printk("\r\n error RSA2048_Decode");
	else
		printk("\r\n OK RSA2048_Decode");
	

	return;
	#endif
}


#if 0
void rsa_test()
{
	unsigned char buffer[512];
	uint8_t  expected_result32[256];
	unsigned char buffer_receive[256];
	printk("\r\nRSA_TEST");

	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = SIZE_RSA_2048;
	buffer[3] = 0;
	buffer[4] = 0;
	send_data_arm7(buffer,5);
	delay_ms(40);
	hexstr2bytes("009AEFF546462E50BFEC1DC191D5D0CE459069756F33635AD62317FFA3981D2B674ED6E83547E479CA90CEF1EB74CBA8F36004F73B477B159B4FE4F3B5BDA05E51D7C8C674C2B9BD2060C9574E661311F4AD7FFC4C0373F1D987505DE434A32DB898B0D167D188EB9645219D5222EB107A7FAAE431705E1A3DC8F47CD936B96A02D951E997199635E49B523FD01E1D4C00CBD551F395202F771007505E1DD48B7B04A82B892FE728E190B71E6D4128571C9BED19C06123DB3EEA1A4EC645419FC879B98F82B6563B7A2C6280DB9B0434A756502306E0B244459DD012CA7198A6300058121E70917B49F6402EE738A6C60BFEBD3CD130CDFB11392AB73DA9A8CA", buffer+5);//RSA_msg
	printk("\r\n rsa_test");
	printk("\r\n Set_RSA_PlainText_M");
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PlainText_M;
	buffer[3] = 0x01;
	buffer[4] = 00;
	send_data_arm7(buffer,256+5);
	printk("\r\n sent data:	009AEFF546462E50BFEC1DC191D5D0CE459069756F33635AD62317FFA3981D2B674ED6E83547E479CA90CEF1EB74CBA8F36004F73B477B159B4FE4F3B5BDA05E51D7C8C674C2B9BD2060C9574E661311F4AD7FFC4C0373F1D987505DE434A32DB898B0D167D188EB9645219D5222EB107A7FAAE431705E1A3DC8F47CD936B96A02D951E997199635E49B523FD01E1D4C00CBD551F395202F771007505E1DD48B7B04A82B892FE728E190B71E6D4128571C9BED19C06123DB3EEA1A4EC645419FC879B98F82B6563B7A2C6280DB9B0434A756502306E0B244459DD012CA7198A6300058121E70917B49F6402EE738A6C60BFEBD3CD130CDFB11392AB73DA9A8CA");

#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

	delay_ms(40);
	
	hexstr2bytes("AE45ED5601CEC6B8CC05F803935C674DDBE0D75C4C09FD7951FC6B0CAEC313A8DF39970C518BFFBA5ED68F3F0D7F22A4029D413F1AE07E4EBE9E4177CE23E7F5404B569E4EE1BDCF3C1FB03EF113802D4F855EB9B5134B5A7C8085ADCAE6FA2FA1417EC3763BE171B0C62B760EDE23C12AD92B980884C641F5A8FAC26BDAD4A03381A22FE1B754885094C82506D4019A535A286AFEB271BB9BA592DE18DCF600C2AEEAE56E02F7CF79FC14CF3BDC7CD84FEBBBF950CA90304B2219A7AA063AEFA2C3C1980E560CD64AFE779585B6107657B957857EFDE6010988AB7DE417FC88D8F384C4E6E72C3F943E0C31C0C4A5CC36F879D8A3AC9D7D59860EAADA6B83BB", buffer+5);//RSA_n
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_Modulus_n;
	buffer[3] = 0x01;
	buffer[4] = 00;
	send_data_arm7(buffer,256+5);
	printk("\r\n Set_RSA_Modulus_n");
	printk("\r\n sent data:	AE45ED5601CEC6B8CC05F803935C674DDBE0D75C4C09FD7951FC6B0CAEC313A8DF39970C518BFFBA5ED68F3F0D7F22A4029D413F1AE07E4EBE9E4177CE23E7F5404B569E4EE1BDCF3C1FB03EF113802D4F855EB9B5134B5A7C8085ADCAE6FA2FA1417EC3763BE171B0C62B760EDE23C12AD92B980884C641F5A8FAC26BDAD4A03381A22FE1B754885094C82506D4019A535A286AFEB271BB9BA592DE18DCF600C2AEEAE56E02F7CF79FC14CF3BDC7CD84FEBBBF950CA90304B2219A7AA063AEFA2C3C1980E560CD64AFE779585B6107657B957857EFDE6010988AB7DE417FC88D8F384C4E6E72C3F943E0C31C0C4A5CC36F879D8A3AC9D7D59860EAADA6B83BB");
	

#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

	delay_ms(40);

	
	hexstr2bytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001", buffer+5);//RSA_expo
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PublicExpo;
	buffer[3] = 0x01;
	buffer[4] = 00;
	printk("\r\n Set_RSA_PublicExpo");	
	send_data_arm7(buffer,256+5);
	printk("\r\n sent data:	00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");


#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

	delay_ms(40);

	
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Encrypt_RSA;
	buffer[3] = 0;
	buffer[4] = 0;
	send_data_arm7(buffer,5);
	printk("\r\n Encrypt_RSA");	

#ifdef DEBUG_DELAY	
	delay_ms(2*4000);
#endif

	delay_ms(64);
	delay_ms(64);


	buffer[0] = SPI1_READ_DATA;
	buffer[1] = 0;
	buffer[2] = Get_RSA_CipherText_C;
	buffer[3] = 0x01;
	buffer[4] = 0;
	read_data_arm7(buffer,buffer_receive,256);
	printk("\r\n Get_RSA_CipherText_C");	
	printk("\r\n receive data");
	printbyte2(buffer_receive,256);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
delay_ms(40);	


	hexstr2bytes("53EA5DC08CD260FB3B858567287FA91552C30B2FEBFBA213F0AE87702D068D19BAB07FE574523DFB42139D68C3C5AFEEE0BFE4CB7969CBF382B804D6E61396144E2D0E60741F8993C3014B58B9B1957A8BABCD23AF854F4C356FB1662AA72BFCC7E586559DC4280D160C126785A723EBEEBEFF71F11594440AAEF87D10793A8774A239D4A04C87FE1467B9DAF85208EC6C7255794A96CC29142F9A8BD418E3C1FD67344B0CD0829DF3B2BEC60253196293C6B34D3F75D32F213DD45C6273D505ADF4CCED1057CB758FC26AEEFA441255ED4E64C199EE075E7F16646182FDB464739B68AB5DAFF0E63E9552016824F054BF4D3C8C90A97BB6B6553284EB429FCC", expected_result32);	
	//printk("\r\nrsa expected\r\n");  	
	//printbyte(buf.buffer,256);
	//printk("\r\nrsa result\r\n");  	
	//printbyte(expected_result32,256);

	printk("\r\n  Get_RSA_CipherText_C");
	printbyte2(buffer_receive,256);
	if(memcmp(buffer_receive,expected_result32,256) != 0)
		printk("\r\n error RSA2048_Encode");
	else
		printk("\r\n OK RSA2048_Encode");


	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_CipherText_C;
	buffer[3] = 0x01;
	buffer[4] = 00;
	hexstr2bytes("53EA5DC08CD260FB3B858567287FA91552C30B2FEBFBA213F0AE87702D068D19BAB07FE574523DFB42139D68C3C5AFEEE0BFE4CB7969CBF382B804D6E61396144E2D0E60741F8993C3014B58B9B1957A8BABCD23AF854F4C356FB1662AA72BFCC7E586559DC4280D160C126785A723EBEEBEFF71F11594440AAEF87D10793A8774A239D4A04C87FE1467B9DAF85208EC6C7255794A96CC29142F9A8BD418E3C1FD67344B0CD0829DF3B2BEC60253196293C6B34D3F75D32F213DD45C6273D505ADF4CCED1057CB758FC26AEEFA441255ED4E64C199EE075E7F16646182FDB464739B68AB5DAFF0E63E9552016824F054BF4D3C8C90A97BB6B6553284EB429FCC", buffer+5);//RSA_msg
	send_data_arm7(buffer,256+5);
	printk("\r\n sent data:    ");
	printbyte2(buffer,256);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
delay_ms(40);	


	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_Modulus_n;
	buffer[3] = 0x01;
	buffer[4] = 00;
	hexstr2bytes("AE45ED5601CEC6B8CC05F803935C674DDBE0D75C4C09FD7951FC6B0CAEC313A8DF39970C518BFFBA5ED68F3F0D7F22A4029D413F1AE07E4EBE9E4177CE23E7F5404B569E4EE1BDCF3C1FB03EF113802D4F855EB9B5134B5A7C8085ADCAE6FA2FA1417EC3763BE171B0C62B760EDE23C12AD92B980884C641F5A8FAC26BDAD4A03381A22FE1B754885094C82506D4019A535A286AFEB271BB9BA592DE18DCF600C2AEEAE56E02F7CF79FC14CF3BDC7CD84FEBBBF950CA90304B2219A7AA063AEFA2C3C1980E560CD64AFE779585B6107657B957857EFDE6010988AB7DE417FC88D8F384C4E6E72C3F943E0C31C0C4A5CC36F879D8A3AC9D7D59860EAADA6B83BB", buffer+5);//RSA_n	
	send_data_arm7(buffer,256+5);
	printk("\r\n sent data:    ");
	printbyte2(buffer,256);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
delay_ms(40);		


	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PrivateKey_d;
	buffer[3] = 0x01;
	buffer[4] = 00;
	hexstr2bytes("056B04216FE5F354AC77250A4B6B0C8525A85C59B0BD80C56450A22D5F438E596A333AA875E291DD43F48CB88B9D5FC0D499F9FCD1C397F9AFC070CD9E398C8D19E61DB7C7410A6B2675DFBF5D345B804D201ADD502D5CE2DFCB091CE9997BBEBE57306F383E4D588103F036F7E85D1934D152A323E4A8DB451D6F4A5B1B0F102CC150E02FEEE2B88DEA4AD4C1BACCB24D84072D14E1D24A6771F7408EE30564FB86D4393A34BCF0B788501D193303F13A2284B001F0F649EAF79328D4AC5C430AB4414920A9460ED1B7BC40EC653E876D09ABC509AE45B525190116A0C26101848298509C1C3BF3A483E7274054E15E97075036E989F60932807B5257751E79", buffer+5);//RSA_d	
	send_data_arm7(buffer,256+5);
	printk("\r\n sent data:    ");
	printbyte2(buffer,256);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
delay_ms(40);	


	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Decrypt_RSA;
	buffer[3] = 0;
	buffer[4] = 0;
	send_data_arm7(buffer,5);
	printk("\r\n Decrypt_RSA");
	delay_ms(5000);

	buffer[0] = SPI1_READ_DATA;
	buffer[1] = 0;
	buffer[2] = Get_RSA_PlainText_M;
	buffer[3] = 0x01;
	buffer[4] = 0;
	read_data_arm7(buffer,buffer_receive,256);
	printk("\r\n Get_RSA_PlainText_M");	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
delay_ms(40);	
	printbyte2(buffer_receive,256);
	hexstr2bytes("009AEFF546462E50BFEC1DC191D5D0CE459069756F33635AD62317FFA3981D2B674ED6E83547E479CA90CEF1EB74CBA8F36004F73B477B159B4FE4F3B5BDA05E51D7C8C674C2B9BD2060C9574E661311F4AD7FFC4C0373F1D987505DE434A32DB898B0D167D188EB9645219D5222EB107A7FAAE431705E1A3DC8F47CD936B96A02D951E997199635E49B523FD01E1D4C00CBD551F395202F771007505E1DD48B7B04A82B892FE728E190B71E6D4128571C9BED19C06123DB3EEA1A4EC645419FC879B98F82B6563B7A2C6280DB9B0434A756502306E0B244459DD012CA7198A6300058121E70917B49F6402EE738A6C60BFEBD3CD130CDFB11392AB73DA9A8CA", expected_result32);
	if(memcmp(buffer_receive,expected_result32,256) != 0)
		printk("\r\n error RSA2048_Decode");
	else
		printk("\r\n OK RSA2048_Decode");
	

	return;
}
#endif 

void ecdh_test_arm7()
{
#ifdef COMPARE
	unsigned char buffer_ecdh[256];
	unsigned char buffer_receive[256];

	int i = 0;	

       for(i = 0; i < 256; i++)
	   	buffer_ecdh[i] = i;
#if 0
#ifdef ARM7
    printk("\r\n ARM7");    
	   send_data_arm7(buffer_ecdh,5);
	   Delay_us(100); 
	   read_data_only_arm7(buffer_receive, 5);
	   printk("\r\n recieved \r\n");
	   printbyte(buffer_receive,5);
#else
    printk("\r\n GPIO");    
	   send_data(buffer_ecdh,5);
	   read_data_raw(buffer_receive, 5);
	   printk("\r\n recieved \r\n");
	   printbyte(buffer_receive,5);
#endif
	   return;
#endif  
	printk("\r\n ECDH P256 \r\n");
	//printk("\r\n 250k");
	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = SIZE_ECDH_256;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
#ifdef ARM7
    printk("\r\n ARM7");    
	send_data_arm7(buffer_ecdh,5);
	//printk("\r\n ecdh_test");
	//send_data_arm7(buffer_ecdh,37);
#else
	//send_data(buffer_ecdh,37);
	printk("\r\n GPIO");
	send_data(buffer_ecdh,5);
#endif
	
	printk("\r\n read write test");
	delay_ms(40);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	
	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Set_ECDH_PrivateKey;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
	hexstr2bytes("c64d654e263cda95d6dc719d3cfd6c3b932b1fea6021b9e2ac36995c4d96ae3d",&buffer_ecdh[5]);
	
#ifdef ARM7
    printk("\r\n ARM7");    
	send_data_arm7(buffer_ecdh,37);
	//printk("\r\n ecdh_test");
	//send_data_arm7(buffer_ecdh,37);
#else
	//send_data(buffer_ecdh,37);
	printk("\r\n GPIO");
	send_data(buffer_ecdh,37);
#endif
//	write_spi_data(buffer_ecdh,37);
	
#if 0
	delay_ms(WATING_TIME);
	delay_ms(4000);
	printk("\r\n SEND SLEEP");
	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = SLEEP;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
	#ifdef ARM7
	send_data_arm7(buffer_ecdh,5);
	#else
	send_data(buffer_ecdh,5);
	#endif
	delay_ms(WATING_TIME*2);
	WakeUP();
#endif	
    delay_ms(40);
#ifdef DEBUG_DELAY
	delay_ms(4000);
#endif

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Create_ECHD_PublicKey;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
#ifdef ARM7
	send_data_arm7(buffer_ecdh,5);
#else	
	send_data(buffer_ecdh,5);
#endif
	
#if 0
	delay_ms(WATING_TIME);
	delay_ms(4000);

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = DEEP_SLEEP;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
	printk("\r\n SEND DEEP_SLEEP\r\n");
	#ifdef ARM7
	send_data_arm7(buffer_ecdh,5);
	#else
	send_data(buffer_ecdh,5);
	#endif
#endif

	delay_ms(200);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
	buffer_ecdh[0] = SPI1_READ_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Get_ECDH_PublicKey_X;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
#ifdef ARM7
	read_data_arm7(buffer_ecdh,buffer_receive,32);
#else
	read_data(buffer_ecdh,buffer_receive,32);
#endif
//	write_spi_data(buffer_ecdh,5);
	
//	read_spi_data(buffer_ecdh,32+2);
	printk("\r\nGet_ECDH_PublicKey_X\r\n");
	printbyte(buffer_receive,32);
	
	printk("\r\n Expected ECDH_PublicKey_X\r\n");
	printk("\r\nefb50f68f26558c1d42847e82dc552607965049cc6f65d7ed8b8d02a1d8825f9");
	hexstr2bytes("efb50f68f26558c1d42847e82dc552607965049cc6f65d7ed8b8d02a1d8825f9",temp_buffer);
	if(memcmp(buffer_receive,temp_buffer,32) == 0)
		Serial.println(" PASS");
	else
		printk("\r\n FAIL");
	delay_ms(40);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	
	buffer_ecdh[0] = SPI1_READ_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Get_ECDH_PublicKey_Y;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
#ifdef ARM7
	read_data_arm7(buffer_ecdh,buffer_receive,32);
#else
	read_data(buffer_ecdh,buffer_receive,32);
#endif
	printk("\r\nGet_ECDH_PublicKey_Y\r\n");
	printbyte(buffer_receive,32);
	
	printk("\r\n Expected ECDH_PublicKey_Y\r\n");
	printk("\r\n3ca531980f67c4843db00419470860d736577867c5eab3e3ed304fd253949202");

	hexstr2bytes("3ca531980f67c4843db00419470860d736577867c5eab3e3ed304fd253949202",temp_buffer);

	if(memcmp(buffer_receive,temp_buffer,32) == 0)
		Serial.println(" PASS");
	else
		printk("\r\n FAIL");	
#if 0
	delay_ms(WATING_TIME);
	delay_ms(4000);
	printk("\r\n SEND SLEEP");
	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = SLEEP;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
#ifdef ARM7
	send_data_arm7(buffer_ecdh,5);
#else
	send_data(buffer_ecdh,5);
#endif
	delay_ms(WATING_TIME*2);
	WakeUP();
#endif	
//return;
	delay_ms(40);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Set_ECDH_PublicKey_X;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
	hexstr2bytes("764ea0ef1a596b196e8b7316e60de4edccbae87821e767b50f6f36656e7ebe2a",&buffer_ecdh[5]);
	printk("\r\n Set_ECDH_PublicKey_X");
	printbyte(&buffer_ecdh[5],32);
#ifdef ARM7
	send_data_arm7(buffer_ecdh,37);
#else
	send_data(buffer_ecdh,37);
#endif
	delay_ms(40);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Set_ECDH_PublicKey_Y;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
	hexstr2bytes("fb526fbfae10d2a0d8fab4d4bdcc883bbfadee2a73ea66a1a1fe816c282d2ce9",&buffer_ecdh[5]);
	printk("\r\n Set_ECDH_PublicKey_Y");
	printbyte(&buffer_ecdh[5],32);
#ifdef ARM7
	send_data_arm7(buffer_ecdh,37);
#else
	send_data(buffer_ecdh,37);
#endif
	delay_ms(40);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Create_ECHD_KEY;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
#ifdef ARM7
	send_data_arm7(buffer_ecdh,5);
#else
	send_data(buffer_ecdh,5);
#endif
	delay_ms(200);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	

	buffer_ecdh[0] = SPI1_READ_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Get_ECDH_KEY_X;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
#ifdef ARM7
	read_data_arm7(buffer_ecdh,buffer_receive,32);
#else
	read_data(buffer_ecdh,buffer_receive,32);
#endif
	printk("\r\nGet_ECDH_KEY_X\r\n");
	printbyte(buffer_receive,32);
	
	printk("\r\n Expected _ECDH_KEY_X\r\n");
	printk("\r\n9e29727653fe830e9709045ead243fa44acec4efb7322048894c4d06b484ce58");	

	hexstr2bytes("9e29727653fe830e9709045ead243fa44acec4efb7322048894c4d06b484ce58",temp_buffer);

	if(memcmp(buffer_receive,temp_buffer,32) == 0)
		Serial.println(" PASS");
	else
		printk("\r\n FAIL");	

	delay_ms(40);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	

	buffer_ecdh[0] = SPI1_READ_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Get_ECDH_KEY_Y;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
#ifdef ARM7
	read_data_arm7(buffer_ecdh,buffer_receive,32);
#else
	read_data(buffer_ecdh,buffer_receive,32);
#endif
	printk("\r\nGet_ECDH_KEY_Y\r\n");
	printbyte(buffer_receive,32);
	printk("\r\n Expected _ECDH_KEY_Y\r\n");
	printk("\r\n87fc5a996074a1852a6385874da7c8875932e612c5815e6e8c7376abb265201c");	


	hexstr2bytes("87fc5a996074a1852a6385874da7c8875932e612c5815e6e8c7376abb265201c",temp_buffer);

	if(memcmp(buffer_receive,temp_buffer,32) == 0)
		Serial.println(" PASS");
	else
		printk("\r\n FAIL");	
#if 0
	delay_ms(WATING_TIME);
	delay_ms(4000);

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = DEEP_SLEEP;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
	printk("\r\n SEND DEEP_SLEEP\r\n");
	#ifdef ARM7
	send_data_arm7(buffer_ecdh,5);
	#else
	send_data(buffer_ecdh,5);
	#endif
	delay_ms(WATING_TIME*2);
	delay_ms(4000);

	WakeUP();
#endif	

#endif
}

void ecdsa_test()
{
#ifdef COMPARE
	unsigned char buffer_ecdsa[256];
	unsigned char buffer_receive[256];
	printk("\r\n ecdsa_test P256");

	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = SIZE_ECDSA_256;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;
	send_data_arm7(buffer_ecdsa,5);
	delay_ms(40);	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_PrivateKey;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	hexstr2bytes("00d007e1b9afcc312eec9cecffa0280752bbd1953182edef12f3fc366e8f4356",&buffer_ecdsa[5]);
	send_data_arm7(buffer_ecdsa,37);
	printk("\r\n sent PrivateKey D  :");
	printbyte2(buffer_ecdsa + 5, 32);
	delay_ms(40);	

	//return;
 #ifdef DEBUG_DELAY
    delay_ms(4000);
#endif	
 	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_K_RND;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	hexstr2bytes("00c03c3b8b1e40cb328a61d51783356935625884399e26a5828f387c2bde6ebc",&buffer_ecdsa[5]);
	send_data_arm7(buffer_ecdsa,37);
	printk("\r\n sent Random value K  :");	
	printbyte2(buffer_ecdsa + 5, 32);
	delay_ms(40);	
#if 0	
#ifdef DEBUG_DELAY
    delay_ms(4000);
#endif	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_Public_Key_Xq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	hexstr2bytes("d6606271131e7e7e617a81aa11f09e7ed56311828823367a869b454040b3f905",&buffer_ecdsa[5]);
	send_data_arm7(buffer_ecdsa,37);
	printk("\r\n sent   :");	
	printbyte2(buffer_ecdsa + 5, 32);
	delay_ms(40);	
#ifdef DEBUG_DELAY
	delay_ms(4000);
#endif	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_Public_Key_Yq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	hexstr2bytes("cf4897766131aa8b7f80453a15bf90f7517878579d5a4f973aea5bb11542e07f",&buffer_ecdsa[5]);
	send_data_arm7(buffer_ecdsa,37);
	printk("\r\n sent   :");	
	printbyte2(buffer_ecdsa + 5, 32);
	delay_ms(40);	
#endif	
#ifdef DEBUG_DELAY
	delay_ms(4000);
#endif	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_h;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	hexstr2bytes("0000000000000000000000000f7b55549fab573c0361b832ad0be8cdeef91b56",&buffer_ecdsa[5]);
	send_data_arm7(buffer_ecdsa,37);         
	delay_ms(40);	
	printk("\r\n sent	Hash Message h:");
	printbyte2(buffer_ecdsa + 5, 32);
#ifdef DEBUG_DELAY
	delay_ms(4000);
#endif	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Create_ECDSA_Public_Key;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;
	send_data_arm7(buffer_ecdsa,5);
	printk("\r\n Create_ECDSA_Public_Key");
	delay_ms(40);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
	delay_ms(200);
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Create_ECDSA_Sign;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;
	send_data_arm7(buffer_ecdsa,5); 
	printk("\r\n Create_ECDSA_Sign");	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
	delay_ms(200);
//TO verify result change h value
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_h;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	hexstr2bytes("0000000000000000000000000f7b55549fab573c0361b832ad0be8cdeef91b56",&buffer_ecdsa[5]);
	send_data_arm7(buffer_ecdsa,37);         
	delay_ms(40);	
	delay_ms(200);
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Do_ECDSA_Verify;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;
	send_data_arm7(buffer_ecdsa,5);
	printk("\r\n Do_ECDSA_Verify");		
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
	delay_ms(250);
    buffer_ecdsa[0] = SPI1_READ_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Get_ECDSA_Public_Key_Yq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	read_data_arm7(buffer_ecdsa,buffer_receive,32);
	printk("\r\nGet_ECDSA_Public_Key_Yq\r\n");
	printbyte2(buffer_receive,32); 
	printk("\r\n Expected\r\n");
	printk("\r\n cf4897766131aa8b7f80453a15bf90f7517878579d5a4f973aea5bb11542e07f");
	hexstr2bytes("cf4897766131aa8b7f80453a15bf90f7517878579d5a4f973aea5bb11542e07f",temp_buffer);

	if(memcmp(buffer_receive,temp_buffer,32) == 0)
		Serial.println(" PASS");
	         
	delay_ms(40);	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

    buffer_ecdsa[0] = SPI1_READ_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Get_ECDSA_Public_Key_Xq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	read_data_arm7(buffer_ecdsa,buffer_receive,32);
	printk("\r\nGet_ECDSA_Public_Key_Xq\r\n");
	printbyte2(buffer_receive,32);  
	printk("\r\n Expected\r\n");
	printk("d6606271131e7e7e617a81aa11f09e7ed56311828823367a869b454040b3f905");

	delay_ms(40);	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

    buffer_ecdsa[0] = SPI1_READ_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Get_ECDSA_r;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	read_data_arm7(buffer_ecdsa,buffer_receive,32);
	printk("\r\nGet_ECDSA_r\r\n");
	printbyte2(buffer_receive,32); 
	printk("\r\n Expected\r\n");
	printk("b5b417619bf9fa89d50b3e22782a2de80a86db67e728114e6e0e91cab1a41612");
	
	delay_ms(40);	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

    buffer_ecdsa[0] = SPI1_READ_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Get_ECDSA_s;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	read_data_arm7(buffer_ecdsa,buffer_receive,32);
	printk("\r\nGet_ECDSA_s\r\n");
	printbyte2(buffer_receive,32);
	printk("\r\n Expected\r\n");
	printk("e43e8111258bea6f5c96bd6d66715748fbee756da418de90f64066c6b3e072f1");
	
	delay_ms(40);	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

    buffer_ecdsa[0] = SPI1_READ_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Get_ECDSA_Result;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 1;
	read_data_arm7(buffer_ecdsa,buffer_receive,1);
	printk("\r\nGet_ECDSA_Result");
	printbyte(buffer_receive,1);
#endif

}


void reversebuffer(unsigned char *dest,unsigned char *org,int count)
{
	int i;
	int j;
	j = count -1;
	for(i = 0; i < count; i++) {
		dest[i] = org[j--];
	}


}
int AES_ARIA_INIT(int RG_128_256,int AES_ARIA,unsigned char *AES_ARIA_KEY,int RG_TWO_FRAME)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char KEY_BUFFER[32];
	// INIT KEY
#if 0
	if(RG_128_256 == RG_256)
	{
		for(i = 0; i < 32; i++)
		{
			AES_ARIA_KEY[i] = i;
		}
	}	
	else
	{
		for(i =0; i <16; i++)
		{
			AES_ARIA_KEY[i] = i;
		}
		for(i = 16; i < 32; i++)
			AES_ARIA_KEY[i] = 0;
	}
#endif

	if(RG_128_256 == RG_256)
	{
		memcpy(KEY_BUFFER,AES_ARIA_KEY+16,16);
		memcpy(KEY_BUFFER+16,AES_ARIA_KEY,16);		
		KEY_SET(KEY_BUFFER);
#ifdef DEBUG_API			
		printk("\r\n RG_256");
#endif
	}
	else
	{
		memcpy(KEY_BUFFER+16,AES_ARIA_KEY,16);
		KEY_SET(KEY_BUFFER);	
#ifdef DEBUG_API				
		printk("\r\n RG_128");		
#endif
	}
#ifdef DEBUG_API		
	printbyte(AES_ARIA_KEY,32);
	printk("\r\n RG_128_256 %d",RG_128_256);
	printk("\r\n AES_ARIA %d",AES_ARIA);	
	printk("\r\n RG_TWO_FRAME %d",RG_TWO_FRAME);
#endif	
	tx_data[0] = 0x0;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 
		(RG_TWO_FRAME<<3)|
		(RG_128_256<<1)|
		AES_ARIA;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	delay_us(30);
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	return 0;
}

void AES_ARIA_Encrypt32(unsigned char *pInput,unsigned char *pOutput)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
#ifdef DEBUG_API		
	printk("\r\n AES_ARIA_Encrypt32 input");
	printbyte(pInput,32);
#endif

	reversebuffer(tx_data, pInput, 16);
	reversebuffer(tx_data+16,pInput+16,16);
	tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	Delay_us(2);

	tspi_interface(cs, ADDR_NOR_R,RG_EEBUF320                   , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	

	reversebuffer(pOutput, rx_data, 16);
	reversebuffer(pOutput+16,rx_data+16,16);	
#ifdef DEBUG_API		
	printk("\r\n AES_ARIA_Encrypt32 pOutput");
	printbyte(pOutput,32);
#endif	

}
void AES_ARIA_Decrypt32(unsigned char *pInput,unsigned  char *pOutput)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	reversebuffer(tx_data, pInput, 16);
	reversebuffer(tx_data+16,pInput+16,16);
#ifdef DEBUG_API	
	printk("\r\n AES_ARIA_Decrypt32 input");
	printbyte(pInput,32);
#endif	
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
	delay_us(2);
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);		
	//iEnd = pRSTC->RTTC_RTVR;
	reversebuffer(pOutput, rx_data, 16);
	reversebuffer(pOutput+16,rx_data+16,16);
#ifdef DEBUG_API		
	printk("\r\nAES_ARIA_Decrypt32 pOutput");
	printbyte(pOutput,32);	
#endif	

}


void AES_ARIA_Encrypt(unsigned char *pInput,unsigned char *pOutput)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	reversebuffer(tx_data, pInput, 16);
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(2);
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF320      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	//iEnd = pRSTC->RTTC_RTVR;
	reversebuffer(pOutput, rx_data, 16);	
	

}
void AES_ARIA_Decrypt(unsigned char *pInput,unsigned  char *pOutput)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	reversebuffer(tx_data, pInput, 16);
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF400      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	delay_us(2);
	tspi_interface(cs, ADDR_NOR_R, RG_EEBUF420      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);		
	//iEnd = pRSTC->RTTC_RTVR;
	reversebuffer(pOutput, rx_data, 16);	

}

void AES_ARIA_CLOSE()
{

	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	  


	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE    , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	  


	endOP();				

}

void SET_IV(unsigned char *IV,int AES_OPMODE,int RG_128_256,int AES_ARIA,unsigned char *AES_ARIA_KEY, int RG_TWO_FRAME)
{
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];	   
	int success = 1;
	unsigned char KEY_BUFFER[32];
	memset(KEY_BUFFER,0,32);
	if(RG_128_256 == RG_256)
	{
		memcpy(KEY_BUFFER,AES_ARIA_KEY+16,16);
		memcpy(KEY_BUFFER+16,AES_ARIA_KEY,16);		
		KEY_SET(KEY_BUFFER);
	}
	else
	{
		memcpy(KEY_BUFFER+16,AES_ARIA_KEY,16);
		KEY_SET(KEY_BUFFER);	
	}

	
	tx_data[0] = 0x0;// KEY_0
	tspi_interface(cs, ADDR_NOR_W, RG_EE_KEY_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 
		(AES_OPMODE<<4)|
		(RG_TWO_FRAME<<3)|
		(RG_128_256<<1)|
		AES_ARIA;
	tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x9;
	tspi_interface(cs, ADDR_NOR_W, RG_ST0_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST1_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x2;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	reversebuffer(tx_data,IV,16);
	tspi_interface(cs, ADDR_NOR_W, RG_EEBUF300      , NULL, NULL, NULL, NULL, tx_data, rx_data, 16);	
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	tx_data[0] = 0x3;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	delay_us(30);
	tx_data[0] = 0x1;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0x4;	
	tspi_interface(cs, ADDR_NOR_W, RG_ST2_SYMCIP_OPMODE      , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////

}

int AES_ARIA_ECB_TEST_ETRI(int RG_128_256,int AES_ARIA ,int EncDec)
{
	//AES TEST
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char CT[16];
	unsigned char PT[16];	
	unsigned char AES128KEY[16];
	unsigned char AES128CT[16];
	unsigned char AES128PT[16];
	unsigned char AES256KEY[32];
	unsigned char AES256CT[16];
	unsigned char AES256PT[16];

	unsigned char ARIA128KEY[16];
	unsigned char ARIA128CT[16];
	unsigned char ARIA128PT[16];
	unsigned char ARIA256KEY[32];
	unsigned char ARIA256CT[16];
	unsigned char ARIA256PT[16];
	int success = 1;
	unsigned char *pKEY;
	unsigned char *pPT;
	unsigned char *pCT;


	hexstr2bytes("000102030405060708090a0b0c0d0e0f",AES128KEY);
	hexstr2bytes("69c4e0d86a7b0430d8cdb78070b4c55a",AES128CT);	
	hexstr2bytes("00112233445566778899aabbccddeeff",AES128PT);		

	hexstr2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",AES256KEY);
	hexstr2bytes("8ea2b7ca516745bfeafc49904b496089",AES256CT);	
	hexstr2bytes("00112233445566778899aabbccddeeff",AES256PT);	

	hexstr2bytes("00112233445566778899aabbccddeeff",ARIA128KEY);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb",ARIA128PT);	
	hexstr2bytes("c6ecd08e22c30abdb215cf74e2075e6e",ARIA128CT);		

	hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",ARIA256KEY);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb",ARIA256PT);	
	hexstr2bytes("58a875e6044ad7fffa4f58420f7f442d",ARIA256CT);		


		if(RG_256 == RG_128_256) {
			if(RG_AES == AES_ARIA) {
				pKEY = AES256KEY;
				pCT = AES256CT;
				pPT = AES256PT;	
				}
			else {
				pKEY = ARIA128KEY;
				pCT = ARIA256CT;
				pPT = ARIA256PT;	
				}
				
			}
		else {
			if(RG_AES == AES_ARIA) {
				pKEY = AES128KEY;
				pCT = AES128CT;
				pPT = AES128PT;	
				}
			else {
				pKEY = ARIA128KEY;
				pCT = ARIA128CT;
				pPT = ARIA128PT;	
				}
		}
		printk("\r\n");
		if(RG_128_256 == RG_256)
			printk("256");
		else
			printk("128");
		
		if(AES_ARIA == RG_AES)
			printk("AES");
		else
			printk("ARIA"); 

		if(RG_ENC == EncDec)
			printk("\r\n ENCODING");
		else
			printk("\r\n DECODING");

		printk("\r\n pCT");
		printbyte(pCT,16);
		printk("\r\n pPT");
		printbyte(pPT,16);  
		printk("\r\n KEY");
		if(RG_256 == RG_128_256)
			printbyte(pKEY,32);
		else
			printbyte(pKEY,16);
			
		if(RG_128_256 == RG_256)
			printk("256");
		else
			printk("128");
		
		if(AES_ARIA == RG_AES)
			printk("AES");
		else
			printk("ARIA"); 
		if(RG_ENC == EncDec)
			printk("ENCODING");
		else
			printk("DECODING"); 
		

		AES_ARIA_INIT(RG_128_256 ,AES_ARIA, pKEY,0);

		if(RG_ENC == EncDec) {

			
				AES_ARIA_Encrypt(pPT,CT);
					if(memcmp(CT,pCT,16) != 0) {

						printk("\r\n ENCODING COMPARE FAIL ");
					}
					else {
						
						printk("\r\n TEST PASS");
						
						}
						if(memcmp(CT,pCT,16) == 0)
							printk("\r\n TEST PASS");
						else {
							printk("\r\n TEST FAIL");							
							success = 0;
						}
						printk("\r\n RESULT CT");
						printbyte(CT,16);
						
						printk("\r\n EXPECTED CT");
						printbyte(pCT,16);

		}
		else {


				AES_ARIA_Decrypt(pCT,PT);
					if(memcmp(PT,pPT,16) != 0) {

						printk("\r\n DECODING COMPARE FAIL ",i);

					}
					else {
						
						printk("\r\n TEST PASS");
						
						}					
					if(memcmp(PT,pPT,16) == 0)
						printk("\r\n TEST PASS");
					else {
						printk("\r\n TEST FAIL");							
						success = 0;
					}

						printk("\r\n RESULT PT");
						printbyte(PT,16);	
						printk("\r\n EXPECTED PT");
						printbyte(pPT,16);
		}
		AES_ARIA_CLOSE();
		return success;
}

void AES_ARIA_ECB_TEST_ETRI_MAIN()
{
	int success_cnt = 0;
	printk("\r\n PART 1 AES128 Encryption ");
	success_cnt += AES_ARIA_ECB_TEST_ETRI(RG_128,RG_AES,RG_ENC);
	printk("\r\n PART 1 AES256 Encryption ");		
	success_cnt += AES_ARIA_ECB_TEST_ETRI(RG_256,RG_AES,RG_ENC);
	printk("\r\n PART 1 AES128 Decryption ");
	success_cnt += AES_ARIA_ECB_TEST_ETRI(RG_128,RG_AES,RG_DEC);
	printk("\r\n PART 1 AES256 Decryption ");		
	success_cnt += AES_ARIA_ECB_TEST_ETRI(RG_256,RG_AES,RG_DEC);	

	printk("\r\n PART 1 ARIA128 Encryption ");
	success_cnt += AES_ARIA_ECB_TEST_ETRI(RG_128,RG_ARIA,RG_ENC);
	printk("\r\n PART 1 ARIA256 Encryption ");		
	success_cnt += AES_ARIA_ECB_TEST_ETRI(RG_256,RG_ARIA,RG_ENC);
	printk("\r\n PART 1 ARIA128 Decryption ");
	success_cnt += AES_ARIA_ECB_TEST_ETRI(RG_128,RG_ARIA,RG_DEC);
	printk("\r\n PART 1 ARIA256 Decryption ");		
	success_cnt += AES_ARIA_ECB_TEST_ETRI(RG_256,RG_ARIA,RG_DEC);		
	if(success_cnt == 8)
		printk("\r\n TOTAL TEST PASS");

}

void AES_ARIA_OPERATION_MODE_TEST()
{
	//AES TEST
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char SOURCE[16*10];
	unsigned char RESULT[16*10];
	unsigned char IV[16];
	unsigned char KEY[32];	
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char CT[16];
	unsigned char PT[16];	
	unsigned char AES128KEY[16];
	unsigned char AES128CT[16];
	unsigned char AES128PT[16];
	unsigned char AES256KEY[32];
	unsigned char AES256CT[16];
	unsigned char AES256PT[16];

	unsigned char ARIA128KEY[16];
	unsigned char ARIA128CT[16];
	unsigned char ARIA128PT[16];
	unsigned char ARIA256KEY[32];
	unsigned char ARIA256CT[16];
	unsigned char ARIA256PT[16];

	unsigned char *pKEY;
	unsigned char *pPT;
	unsigned char *pCT;
	unsigned char KEYBUFFER[64];
	memset(KEYBUFFER,0,64);
#if 1	
	eep_page_write(0xec, 0x80, KEYBUFFER, 1);
	hexstr2bytes("000102030405060708090a0b0c0d0e0f",AES128KEY);
	hexstr2bytes("69c4e0d86a7b0430d8cdb78070b4c55a",AES128CT);	
	hexstr2bytes("00112233445566778899aabbccddeeff",AES128PT);		

	hexstr2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",AES256KEY);
	hexstr2bytes("8ea2b7ca516745bfeafc49904b496089",AES256CT);	
	hexstr2bytes("00112233445566778899aabbccddeeff",AES256PT);	

	

	
	Serial.println("\r\n . AES MODE_ECB 128 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AES128KEY,16,NULL,CT,AES128PT,16,MODE_ECB,LAST);
	if(memcmp(CT,AES128CT,16) == 0)
	   Serial.println(" PASS");
	Serial.println("\r\n . AES MODE_ECB 128 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AES128KEY,16,NULL,PT,AES128CT,16,MODE_ECB,LAST);
	if(memcmp(PT,AES128PT,16) == 0)
	   Serial.println(" PASS");
	
	Serial.println("\r\n . AES MODE_ECB 256 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AES256KEY,32,NULL,CT,AES256PT,16,MODE_ECB,LAST);
	if(memcmp(CT,AES256CT,16) == 0)
	   Serial.println(" PASS");
	Serial.println("\r\n . AES MODE_ECB 256 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AES256KEY,32,NULL,PT,AES256CT,16,MODE_ECB,LAST);
	if(memcmp(PT,AES256PT,16) == 0)
	   Serial.println(" PASS");


#endif
	{
	unsigned char AESCBC128KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char AESCBC128IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESCBC128PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESCBC128CT[] = { 0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2,0x73,0xbe,0xd6,0xb8,0xe3,0xc1,0x74,0x3b,0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16,0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09,0x12,0x0e,0xca,0x30,0x75,0x86,0xe1,0xa7};
	Serial.println("\r\n . AES MODE_CBC 128 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCBC128KEY,16,AESCBC128IV,CT,AESCBC128PT,16,MODE_CBC,0);
	if(memcmp(CT,AESCBC128CT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCBC128CT");
		printbyte(AESCBC128CT,16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCBC128PT[16*1],16,MODE_CBC,0);
	if(memcmp(CT,&AESCBC128CT[16*1],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCBC128CT");
		printbyte(&AESCBC128CT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCBC128PT[16*2],16,MODE_CBC,0);
	if(memcmp(CT,&AESCBC128CT[16*2],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCBC128CT");
		printbyte(&AESCBC128CT[16*2],16);	
	}
	
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCBC128PT[16*3],16,MODE_CBC,LAST);
	if(memcmp(CT,&AESCBC128CT[16*3],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCBC128CT");
		printbyte(&AESCBC128CT[16*3],16);	
	}
		
	printk("\r\n . AES MODE_CBC 128 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCBC128KEY,16,AESCBC128IV,PT,AESCBC128CT,16,MODE_CBC,0);
	if(memcmp(PT,AESCBC128PT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC128PT");
		printbyte(AESCBC128PT,16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCBC128CT[16*1],16,MODE_CBC,0);
	if(memcmp(PT,&AESCBC128PT[16*1],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC128PT");
		printbyte(&AESCBC128PT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCBC128CT[16*2],16,MODE_CBC,0);
	if(memcmp(PT,&AESCBC128PT[16*2],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC128PT");
		printbyte(&AESCBC128PT[16*2],16);	
	}

	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCBC128CT[16*3],16,MODE_CBC,LAST);
	if(memcmp(PT,&AESCBC128PT[16*3],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC128PT");
		printbyte(&AESCBC128CT[16*3],16);	
	}
	

}
	{
	unsigned char AESCBC256KEY[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
	unsigned char AESCBC256IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESCBC256PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESCBC256CT[] = { 0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d,0x39,0xf2,0x33,0x69,0xa9,0xd9,0xba,0xcf,0xa5,0x30,0xe2,0x63,0x04,0x23,0x14,0x61,0xb2,0xeb,0x05,0xe2,0xc3,0x9b,0xe9,0xfc,0xda,0x6c,0x19,0x07,0x8c,0x6a,0x9d,0x1b};
	printk("\r\n . AES MODE_CBC 256 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCBC256KEY,32,AESCBC256IV,CT,AESCBC256PT,16,MODE_CBC,0);
	if(memcmp(CT,AESCBC256CT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCBC256CT");
		printbyte(AESCBC256CT,16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCBC256PT[16*1],16,MODE_CBC,0);
	if(memcmp(CT,&AESCBC256CT[16*1],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCBC256CT");
		printbyte(&AESCBC256CT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCBC256PT[16*2],16,MODE_CBC,0);
	if(memcmp(CT,&AESCBC256CT[16*2],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCBC256CT");
		printbyte(&AESCBC256CT[16*2],16);	
	}
	
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCBC256PT[16*3],16,MODE_CBC,LAST);
	if(memcmp(CT,&AESCBC256CT[16*3],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCBC256CT");
		printbyte(&AESCBC256CT[16*3],16);	
	}
		
	printk("\r\n . AES MODE_CBC 256 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCBC256KEY,32,AESCBC256IV,PT,AESCBC256CT,16,MODE_CBC,0);
	if(memcmp(PT,AESCBC256PT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC256PT");
		printbyte(AESCBC256PT,16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCBC256CT[16*1],16,MODE_CBC,0);
	if(memcmp(PT,&AESCBC256PT[16*1],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC256PT");
		printbyte(&AESCBC256PT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCBC256CT[16*2],16,MODE_CBC,0);
	if(memcmp(PT,&AESCBC256PT[16*2],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC256PT");
		printbyte(&AESCBC256PT[16*2],16);	
	}

	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCBC256CT[16*3],16,MODE_CBC,LAST);
	if(memcmp(PT,&AESCBC256PT[16*3],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC256PT");
		printbyte(&AESCBC256CT[16*3],16);	
	}
	

}

	{
	unsigned char AESCFB128KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char AESCFB128IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESCFB128PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESCFB128CT[] = { 0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a,0xc8,0xa6,0x45,0x37,0xa0,0xb3,0xa9,0x3f,0xcd,0xe3,0xcd,0xad,0x9f,0x1c,0xe5,0x8b,0x26,0x75,0x1f,0x67,0xa3,0xcb,0xb1,0x40,0xb1,0x80,0x8c,0xf1,0x87,0xa4,0xf4,0xdf,0xc0,0x4b,0x05,0x35,0x7c,0x5d,0x1c,0x0e,0xea,0xc4,0xc6,0x6f,0x9f,0xf7,0xf2,0xe6};
	printk("\r\n . AES MODE_CFB 128 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCFB128KEY,16,AESCFB128IV,CT,AESCFB128PT,16,MODE_CFB,0);
	if(memcmp(CT,AESCFB128CT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB128CT");
		printbyte(AESCFB128CT,16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCFB128PT[16*1],16,MODE_CFB,0);
	if(memcmp(CT,&AESCFB128CT[16*1],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB128CT");
		printbyte(&AESCFB128CT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCFB128PT[16*2],16,MODE_CFB,0);
	if(memcmp(CT,&AESCFB128CT[16*2],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB128CT");
		printbyte(&AESCFB128CT[16*2],16);	
	}
	
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCFB128PT[16*3],16,MODE_CFB,LAST);
	if(memcmp(CT,&AESCFB128CT[16*3],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB128CT");
		printbyte(&AESCFB128CT[16*3],16);	
	}
		
	printk("\r\n . AES MODE_CFB 128 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCFB128KEY,16,AESCFB128IV,PT,AESCFB128CT,16,MODE_CFB,0);
	if(memcmp(PT,AESCFB128PT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB128PT");
		printbyte(AESCFB128PT,16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCFB128CT[16*1],16,MODE_CFB,0);
	if(memcmp(PT,&AESCFB128PT[16*1],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB128PT");
		printbyte(&AESCFB128PT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCFB128CT[16*2],16,MODE_CFB,0);
	if(memcmp(PT,&AESCFB128PT[16*2],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB128PT");
		printbyte(&AESCFB128PT[16*2],16);	
	}

	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCFB128CT[16*3],16,MODE_CFB,LAST);
	if(memcmp(PT,&AESCFB128PT[16*3],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB128PT");
		printbyte(&AESCFB128CT[16*3],16);	
	}
	

}
	{
	unsigned char AESCFB256KEY[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
	unsigned char AESCFB256IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESCFB256PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESCFB256CT[] = { 0xdc,0x7e,0x84,0xbf,0xda,0x79,0x16,0x4b,0x7e,0xcd,0x84,0x86,0x98,0x5d,0x38,0x60,0x39,0xff,0xed,0x14,0x3b,0x28,0xb1,0xc8,0x32,0x11,0x3c,0x63,0x31,0xe5,0x40,0x7b,0xdf,0x10,0x13,0x24,0x15,0xe5,0x4b,0x92,0xa1,0x3e,0xd0,0xa8,0x26,0x7a,0xe2,0xf9,0x75,0xa3,0x85,0x74,0x1a,0xb9,0xce,0xf8,0x20,0x31,0x62,0x3d,0x55,0xb1,0xe4,0x71};
	printk("\r\n . AES MODE_CFB 256 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCFB256KEY,32,AESCFB256IV,CT,AESCFB256PT,16,MODE_CFB,0);
	if(memcmp(CT,AESCFB256CT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB256CT");
		printbyte(AESCFB256CT,16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCFB256PT[16*1],16,MODE_CFB,0);
	if(memcmp(CT,&AESCFB256CT[16*1],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB256CT");
		printbyte(&AESCFB256CT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCFB256PT[16*2],16,MODE_CFB,0);
	if(memcmp(CT,&AESCFB256CT[16*2],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB256CT");
		printbyte(&AESCFB256CT[16*2],16);	
	}
	
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCFB256PT[16*3],16,MODE_CFB,LAST);
	if(memcmp(CT,&AESCFB256CT[16*3],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB256CT");
		printbyte(&AESCFB256CT[16*3],16);	
	}
		
	printk("\r\n . AES MODE_CFB 256 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCFB256KEY,32,AESCFB256IV,PT,AESCFB256CT,16,MODE_CFB,0);
	if(memcmp(PT,AESCFB256PT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB256PT");
		printbyte(AESCFB256PT,16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCFB256CT[16*1],16,MODE_CFB,0);
	if(memcmp(PT,&AESCFB256PT[16*1],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB256PT");
		printbyte(&AESCFB256PT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCFB256CT[16*2],16,MODE_CFB,0);
	if(memcmp(PT,&AESCFB256PT[16*2],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB256PT");
		printbyte(&AESCFB256PT[16*2],16);	
	}

	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCFB256CT[16*3],16,MODE_CFB,LAST);
	if(memcmp(PT,&AESCFB256PT[16*3],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB256PT");
		printbyte(&AESCFB256CT[16*3],16);	
	}
	

}
	{
	unsigned char AESOFB128KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char AESOFB128IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESOFB128PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESOFB128CT[] = { 0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a,0x77,0x89,0x50,0x8d,0x16,0x91,0x8f,0x03,0xf5,0x3c,0x52,0xda,0xc5,0x4e,0xd8,0x25,0x97,0x40,0x05,0x1e,0x9c,0x5f,0xec,0xf6,0x43,0x44,0xf7,0xa8,0x22,0x60,0xed,0xcc,0x30,0x4c,0x65,0x28,0xf6,0x59,0xc7,0x78,0x66,0xa5,0x10,0xd9,0xc1,0xd6,0xae,0x5e};
	printk("\r\n . AES MODE_OFB 128 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESOFB128KEY,16,AESOFB128IV,CT,AESOFB128PT,16,MODE_OFB,0);
	if(memcmp(CT,AESOFB128CT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB128CT");
		printbyte(AESOFB128CT,16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESOFB128PT[16*1],16,MODE_OFB,0);
	if(memcmp(CT,&AESOFB128CT[16*1],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB128CT");
		printbyte(&AESOFB128CT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESOFB128PT[16*2],16,MODE_OFB,0);
	if(memcmp(CT,&AESOFB128CT[16*2],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB128CT");
		printbyte(&AESOFB128CT[16*2],16);	
	}
	
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESOFB128PT[16*3],16,MODE_OFB,LAST);
	if(memcmp(CT,&AESOFB128CT[16*3],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB128CT");
		printbyte(&AESOFB128CT[16*3],16);	
	}
		
	printk("\r\n . AES MODE_OFB 128 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESOFB128KEY,16,AESOFB128IV,PT,AESOFB128CT,16,MODE_OFB,0);
	if(memcmp(PT,AESOFB128PT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB128PT");
		printbyte(AESOFB128PT,16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESOFB128CT[16*1],16,MODE_OFB,0);
	if(memcmp(PT,&AESOFB128PT[16*1],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB128PT");
		printbyte(&AESOFB128PT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESOFB128CT[16*2],16,MODE_OFB,0);
	if(memcmp(PT,&AESOFB128PT[16*2],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB128PT");
		printbyte(&AESOFB128PT[16*2],16);	
	}

	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESOFB128CT[16*3],16,MODE_OFB,LAST);
	if(memcmp(PT,&AESOFB128PT[16*3],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB128PT");
		printbyte(&AESOFB128CT[16*3],16);	
	}
	

}
	{
	unsigned char AESOFB256KEY[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
	unsigned char AESOFB256IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESOFB256PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESOFB256CT[] = { 0xdc,0x7e,0x84,0xbf,0xda,0x79,0x16,0x4b,0x7e,0xcd,0x84,0x86,0x98,0x5d,0x38,0x60,0x4f,0xeb,0xdc,0x67,0x40,0xd2,0x0b,0x3a,0xc8,0x8f,0x6a,0xd8,0x2a,0x4f,0xb0,0x8d,0x71,0xab,0x47,0xa0,0x86,0xe8,0x6e,0xed,0xf3,0x9d,0x1c,0x5b,0xba,0x97,0xc4,0x08,0x01,0x26,0x14,0x1d,0x67,0xf3,0x7b,0xe8,0x53,0x8f,0x5a,0x8b,0xe7,0x40,0xe4,0x84};
	printk("\r\n . AES MODE_OFB 256 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESOFB256KEY,32,AESOFB256IV,CT,AESOFB256PT,16,MODE_OFB,0);
	if(memcmp(CT,AESOFB256CT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB256CT");
		printbyte(AESOFB256CT,16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESOFB256PT[16*1],16,MODE_OFB,0);
	if(memcmp(CT,&AESOFB256CT[16*1],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB256CT");
		printbyte(&AESOFB256CT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESOFB256PT[16*2],16,MODE_OFB,0);
	if(memcmp(CT,&AESOFB256CT[16*2],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB256CT");
		printbyte(&AESOFB256CT[16*2],16);	
	}
	
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESOFB256PT[16*3],16,MODE_OFB,LAST);
	if(memcmp(CT,&AESOFB256CT[16*3],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB256CT");
		printbyte(&AESOFB256CT[16*3],16);	
	}
		
	printk("\r\n . AES MODE_OFB 256 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESOFB256KEY,32,AESOFB256IV,PT,AESOFB256CT,16,MODE_OFB,0);
	if(memcmp(PT,AESOFB256PT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB256PT");
		printbyte(AESOFB256PT,16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESOFB256CT[16*1],16,MODE_OFB,0);
	if(memcmp(PT,&AESOFB256PT[16*1],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB256PT");
		printbyte(&AESOFB256PT[16*1],16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESOFB256CT[16*2],16,MODE_OFB,0);
	if(memcmp(PT,&AESOFB256PT[16*2],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB256PT");
		printbyte(&AESOFB256PT[16*2],16);	
	}

	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESOFB256CT[16*3],16,MODE_OFB,LAST);
	if(memcmp(PT,&AESOFB256PT[16*3],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB256PT");
		printbyte(&AESOFB256CT[16*3],16);	
	}
	

}

		{
		unsigned char AESCTR128KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
		unsigned char AESCTR128IV[] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
		unsigned char AESCTR128PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
		unsigned char AESCTR128CT[] = { 0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee};
		printk("\r\n . AES MODE_CTR 128 ENC TEST");
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCTR128KEY,16,AESCTR128IV,CT,AESCTR128PT,16,MODE_CTR,0);
		if(memcmp(CT,AESCTR128CT,16) == 0)
		   Serial.println(" PASS");
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR128CT");
			printbyte(AESCTR128CT,16);	
		}
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCTR128PT[16*1],16,MODE_CTR,0);
		if(memcmp(CT,&AESCTR128CT[16*1],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR128CT");
			printbyte(&AESCTR128CT[16*1],16);	
		}
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCTR128PT[16*2],16,MODE_CTR,0);
		if(memcmp(CT,&AESCTR128CT[16*2],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR128CT");
			printbyte(&AESCTR128CT[16*2],16);	
		}
		
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCTR128PT[16*3],16,MODE_CTR,LAST);
		if(memcmp(CT,&AESCTR128CT[16*3],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR128CT");
			printbyte(&AESCTR128CT[16*3],16);	
		}
			
		printk("\r\n . AES MODE_CTR 128 DEC TEST");
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCTR128KEY,16,AESCTR128IV,PT,AESCTR128CT,16,MODE_CTR,0);
		if(memcmp(PT,AESCTR128PT,16) == 0)
		   Serial.println(" PASS");
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR128PT");
			printbyte(AESCTR128PT,16);	
		}
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCTR128CT[16*1],16,MODE_CTR,0);
		if(memcmp(PT,&AESCTR128PT[16*1],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR128PT");
			printbyte(&AESCTR128PT[16*1],16);	
		}
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCTR128CT[16*2],16,MODE_CTR,0);
		if(memcmp(PT,&AESCTR128PT[16*2],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR128PT");
			printbyte(&AESCTR128PT[16*2],16);	
		}
	
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCTR128CT[16*3],16,MODE_CTR,LAST);
		if(memcmp(PT,&AESCTR128PT[16*3],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR128PT");
			printbyte(&AESCTR128CT[16*3],16);	
		}
		
	
	}
		{
		unsigned char AESCTR256KEY[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
		unsigned char AESCTR256IV[] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
		unsigned char AESCTR256PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
		unsigned char AESCTR256CT[] = { 0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5,0x2b,0x09,0x30,0xda,0xa2,0x3d,0xe9,0x4c,0xe8,0x70,0x17,0xba,0x2d,0x84,0x98,0x8d,0xdf,0xc9,0xc5,0x8d,0xb6,0x7a,0xad,0xa6,0x13,0xc2,0xdd,0x08,0x45,0x79,0x41,0xa6};
		printk("\r\n . AES MODE_CTR 256 ENC TEST");
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCTR256KEY,32,AESCTR256IV,CT,AESCTR256PT,16,MODE_CTR,0);
		if(memcmp(CT,AESCTR256CT,16) == 0)
		   Serial.println(" PASS");
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR256CT");
			printbyte(AESCTR256CT,16);	
		}
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCTR256PT[16*1],16,MODE_CTR,0);
		if(memcmp(CT,&AESCTR256CT[16*1],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR256CT");
			printbyte(&AESCTR256CT[16*1],16);	
		}
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCTR256PT[16*2],16,MODE_CTR,0);
		if(memcmp(CT,&AESCTR256CT[16*2],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR256CT");
			printbyte(&AESCTR256CT[16*2],16);	
		}
		
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCTR256PT[16*3],16,MODE_CTR,LAST);
		if(memcmp(CT,&AESCTR256CT[16*3],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR256CT");
			printbyte(&AESCTR256CT[16*3],16);	
		}
			
		printk("\r\n . AES MODE_CTR 256 DEC TEST");
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCTR256KEY,32,AESCTR256IV,PT,AESCTR256CT,16,MODE_CTR,0);
		if(memcmp(PT,AESCTR256PT,16) == 0)
		   Serial.println(" PASS");
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR256PT");
			printbyte(AESCTR256PT,16);	
		}
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCTR256CT[16*1],16,MODE_CTR,0);
		if(memcmp(PT,&AESCTR256PT[16*1],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR256PT");
			printbyte(&AESCTR256PT[16*1],16);	
		}
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCTR256CT[16*2],16,MODE_CTR,0);
		if(memcmp(PT,&AESCTR256PT[16*2],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR256PT");
			printbyte(&AESCTR256PT[16*2],16);	
		}
	
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCTR256CT[16*3],16,MODE_CTR,LAST);
		if(memcmp(PT,&AESCTR256PT[16*3],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR256PT");
			printbyte(&AESCTR256CT[16*3],16);	
		}
		
	
	}

	hexstr2bytes("00112233445566778899aabbccddeeff",ARIA128KEY);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb",ARIA128PT);	
	hexstr2bytes("c6ecd08e22c30abdb215cf74e2075e6e",ARIA128CT);		

	hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",ARIA256KEY);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb",ARIA256PT);	
	hexstr2bytes("58a875e6044ad7fffa4f58420f7f442d",ARIA256CT);	

	printk("\r\n . ARIA MODE_ECB 128 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,ARIA128KEY,16,NULL,CT,ARIA128PT,16,MODE_ECB,LAST);
	if(memcmp(CT,ARIA128CT,16) == 0)
	   Serial.println(" PASS");
	printk("\r\n . ARIA MODE_ECB 128 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,ARIA128KEY,16,NULL,PT,ARIA128CT,16,MODE_ECB,LAST);
	if(memcmp(PT,ARIA128PT,16) == 0)
	   Serial.println(" PASS");
	printk("\r\n . ARIA MODE_ECB 256 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,ARIA256KEY,32,NULL,CT,ARIA256PT,16,MODE_ECB,LAST);
	if(memcmp(CT,ARIA256CT,16) == 0)
	   Serial.println(" PASS");
	printk("\r\n . ARIA MODE_ECB 256 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,ARIA256KEY,32,NULL,PT,ARIA256CT,16,MODE_ECB,LAST);
	if(memcmp(PT,ARIA256PT,16) == 0)
	   Serial.println(" PASS");

	{

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("49d61860b14909109cef0d22a9268134fadf9fb23151e9645fba75018bdb1538b53334634bbf7d4cd4b5377033060c155fe3948ca75de1031e1d85619e0ad61eb419a866b3c2dbfd10a4ed18b22149f75897f0b8668b0c1c542c687778835fb7cd46e45f85eaa7072437dd9fa6793d6f8d4ccefc4eb1ac641ac1bd30b18c6d64c49bca137eb21c2e04da62712ca2b4f540c57112c38791852cfac7a5d19ed83a",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);
			hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0",IV);	
			printk("\r\n . ARIA MODE_CBC 128 ENC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,16,IV,CT,&SOURCE[16*i],16,MODE_CBC,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],16,MODE_CBC,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],16,MODE_CBC,0);

				if(memcmp(CT,&RESULT[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			printk("\r\n . ARIA MODE_CBC 128 DEC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,16,IV,PT,&RESULT[16*i],16,MODE_CBC,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],16,MODE_CBC,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],16,MODE_CBC,0);

				if(memcmp(PT,&SOURCE[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("523a8a806ae621f155fdd28dbc34e1ab7b9b42432ad8b2efb96e23b13f0a6e52f36185d50ad002c5f601bee5493f118b243ee2e313642bffc3902e7b2efd9a12fa682edd2d23c8b9c5f043c18b17c1ec4b5867918270fbec1027c19ed6af833da5d620994668ca22f599791d292dd6273b2959082aafb7a996167cce1eec5f0cfd15f610d87e2dda9ba68ce1260ca54b222491418374294e7909b1e8551cd8de",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);			
			printk("\r\n. ARIA MODE_CBC 256 ENC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,32,IV,CT,&SOURCE[16*i],16,MODE_CBC,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],16,MODE_CBC,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],16,MODE_CBC,0);

				if(memcmp(CT,&RESULT[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			printk("\r\n . ARIA MODE_CBC 256 DEC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,32,IV,PT,&RESULT[16*i],16,MODE_CBC,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],16,MODE_CBC,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],16,MODE_CBC,0);

				if(memcmp(PT,&SOURCE[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}


			
			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("3720e53ba7d615383406b09f0a05a200c07c21e6370f413a5d132500a68285017c61b434c7b7ca9685a51071861e4d4bb873b599b479e2d573dddeafba89f812ac6a9e44d554078eb3be94839db4b33da3f59c063123a7ef6f20e10579fa4fd239100ca73b52d4fcafeadee73f139f78f9b7614c2b3b9dbe010f87db06a89a9435f79ce8121431371f4e87b984e0230c22a6dacb32fc42dcc6accef33285bf11",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);	
			hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0",IV);
			printk("\r\n. ARIA MODE_CFB 128 ENC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,16,IV,CT,&SOURCE[16*i],16,MODE_CFB,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],16,MODE_CFB,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],16,MODE_CFB,0);

				if(memcmp(CT,&RESULT[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			printk("\r\n . ARIA MODE_CFB 128 DEC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,16,IV,PT,&RESULT[16*i],16,MODE_CFB,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],16,MODE_CFB,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],16,MODE_CFB,0);

				if(memcmp(PT,&SOURCE[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("26834705b0f2c0e2588d4a7f09009635f28bb93d8c31f870ec1e0bdb082b66fa402dd9c202be300c4517d196b14d4ce11dce97f7aaba54341b0d872cc9b63753a3e8556a14be6f7b3e27e3cfc39caf80f2a355aa50dc83c09c7b11828694f8e4aa726c528976b53f2c877f4991a3a8d28adb63bd751846ffb2350265e179d4990753ae8485ff9b4133ddad5875b84a90cbcfa62a045d726df71b6bda0eeca0be",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);			
			printk("\r\n. ARIA MODE_CFB 256 ENC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,32,IV,CT,&SOURCE[16*i],16,MODE_CFB,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],16,MODE_CFB,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],16,MODE_CFB,0);

				if(memcmp(CT,&RESULT[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			printk("\r\n . ARIA MODE_CFB 256 DEC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,32,IV,PT,&RESULT[16*i],16,MODE_CFB,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],16,MODE_CFB,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],16,MODE_CFB,0);

				if(memcmp(PT,&SOURCE[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("3720e53ba7d615383406b09f0a05a2000063063f0560083483faeb041c8adecef30cf80cefb002a0d280759168ec01db3d49f61aced260bd43eec0a2731730eec6fa4f2304319cf8ccac2d7be7833e4f8ae6ce967012c1c6badc5d28e7e4144f6bf5cebe01253ee202afce4bc61f28dec069a6f16f6c8a7dd2afae44148f6ff4d0029d5c607b5fa6b8c8a6301cde5c7033565cd0b8f0974ab490b236197ba04a",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);

			hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0",IV);
			printk("\r\n . ARIA MODE_OFB 128 ENC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,16,IV,CT,&SOURCE[16*i],16,MODE_OFB,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],16,MODE_OFB,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],16,MODE_OFB,0);

				if(memcmp(CT,&RESULT[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			printk("\r\n . ARIA MODE_OFB 128 DEC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,16,IV,PT,&RESULT[16*i],16,MODE_OFB,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],16,MODE_OFB,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],16,MODE_OFB,0);

				if(memcmp(PT,&SOURCE[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}


			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("26834705b0f2c0e2588d4a7f0900963584c256815c4292b59f8d3f966a75b52345b4f5f98c785d3f368a8d5ff89b7f950ceab3cd63773c2621d652b8ef98b4196afb2c2b30496bc5b7d9e7f9084f9d855f63a511751c8909e7a6deadbe0a67a4fb89383ca5d209c6f66f793fc471195c476fb9c1eab2ac91e680e454b4f3ed9a67fb52f09c29b965b23cfa6f3f6bbb2a86c6cdbaa2857bf2486f543231892a52",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);	
			printk("\r\n . ARIA MODE_OFB 256 ENC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,32,IV,CT,&SOURCE[16*i],16,MODE_OFB,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],16,MODE_OFB,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],16,MODE_OFB,0);

				if(memcmp(CT,&RESULT[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			printk("\r\n . ARIA MODE_OFB 256 DEC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,32,IV,PT,&RESULT[16*i],16,MODE_OFB,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],16,MODE_OFB,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],16,MODE_OFB,0);

				if(memcmp(PT,&SOURCE[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}


			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("ac5d7de805a0bf1c57c854501af60fa11497e2a34519dea1569e91e5b5ccae2ff3bfa1bf975f4571f48be191613546c3911163c085f871f0e7ae5f2a085b81851c2a3ddf20ecb8fa51901aec8ee4ba32a35dab67bb72cd9140ad188a967ac0fbbdfa94ea6cce47dcf8525ab5a814cfeb2bb60ee2b126e2d9d847c1a9e96f9019e3e6a7fe40d3829afb73db1cc245646addb62d9b907baaafbe46a73dbc131d3d",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);
			memset(IV,0,16);

			printk("\r\n . ARIA MODE_CTR 128 ENC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,16,IV,CT,&SOURCE[16*i],16,MODE_CTR,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],16,MODE_CTR,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],16,MODE_CTR,0);

				if(memcmp(CT,&RESULT[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			printk("\r\n . ARIA MODE_CTR 128 DEC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,16,IV,PT,&RESULT[16*i],16,MODE_CTR,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],16,MODE_CTR,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],16,MODE_CTR,0);

				if(memcmp(PT,&SOURCE[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}


			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("30026c329666141721178b99c0a1f1b2f06940253f7b3089e2a30ea86aa3c88f5940f05ad7ee41d71347bb7261e348f18360473fdf7d4e7723bffb4411cc13f6cdd89f3bc7b9c768145022c7a74f14d7c305cd012a10f16050c23f1ae5c23f45998d13fbaa041e51619577e0772764896a5d4516d8ffceb3bf7e05f613edd9a60cdcedaff9cfcaf4e00d445a54334f73ab2cad944e51d266548e61c6eb0aa1cd",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);	
			printk("\r\n . ARIA MODE_CTR 256 ENC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,32,IV,CT,&SOURCE[16*i],16,MODE_CTR,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],16,MODE_CTR,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],16,MODE_CTR,0);

				if(memcmp(CT,&RESULT[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			printk("\r\n . ARIA MODE_CTR 256 DEC TEST");	
			for(i = 0; i < 10; i++ ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,32,IV,PT,&RESULT[16*i],16,MODE_CTR,0);
				}	
				else if( 9 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],16,MODE_CTR,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],16,MODE_CTR,0);

				if(memcmp(PT,&SOURCE[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}
  }
#if 0			
			printk(". ARIA MODE_CBC 128 DEC TEST");				
			
			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("523a8a806ae621f155fdd28dbc34e1ab7b9b42432ad8b2efb96e23b13f0a6e52f36185d50ad002c5f601bee5493f118b243ee2e313642bffc3902e7b2efd9a12fa682edd2d23c8b9c5f043c18b17c1ec4b5867918270fbec1027c19ed6af833da5d620994668ca22f599791d292dd6273b2959082aafb7a996167cce1eec5f0cfd15f610d87e2dda9ba68ce1260ca54b222491418374294e7909b1e8551cd8de",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);
			printk(". ARIA MODE_CBC 256 ENC TEST");
			printk(". ARIA MODE_CBC 256 DEC TEST");			


	}
	if(Mode == MODE_CFB) {
		if(RG256 == RG_128_256){

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("26834705b0f2c0e2588d4a7f09009635f28bb93d8c31f870ec1e0bdb082b66fa402dd9c202be300c4517d196b14d4ce11dce97f7aaba54341b0d872cc9b63753a3e8556a14be6f7b3e27e3cfc39caf80f2a355aa50dc83c09c7b11828694f8e4aa726c528976b53f2c877f4991a3a8d28adb63bd751846ffb2350265e179d4990753ae8485ff9b4133ddad5875b84a90cbcfa62a045d726df71b6bda0eeca0be",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);
		}
		else
		{
			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("3720e53ba7d615383406b09f0a05a200c07c21e6370f413a5d132500a68285017c61b434c7b7ca9685a51071861e4d4bb873b599b479e2d573dddeafba89f812ac6a9e44d554078eb3be94839db4b33da3f59c063123a7ef6f20e10579fa4fd239100ca73b52d4fcafeadee73f139f78f9b7614c2b3b9dbe010f87db06a89a9435f79ce8121431371f4e87b984e0230c22a6dacb32fc42dcc6accef33285bf11",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);

		}
		hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0",IV);	

	}
	if(Mode == MODE_OFB) {
		if(RG256 == RG_128_256){

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("26834705b0f2c0e2588d4a7f0900963584c256815c4292b59f8d3f966a75b52345b4f5f98c785d3f368a8d5ff89b7f950ceab3cd63773c2621d652b8ef98b4196afb2c2b30496bc5b7d9e7f9084f9d855f63a511751c8909e7a6deadbe0a67a4fb89383ca5d209c6f66f793fc471195c476fb9c1eab2ac91e680e454b4f3ed9a67fb52f09c29b965b23cfa6f3f6bbb2a86c6cdbaa2857bf2486f543231892a52",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);
		}
		else
		{
			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("3720e53ba7d615383406b09f0a05a2000063063f0560083483faeb041c8adecef30cf80cefb002a0d280759168ec01db3d49f61aced260bd43eec0a2731730eec6fa4f2304319cf8ccac2d7be7833e4f8ae6ce967012c1c6badc5d28e7e4144f6bf5cebe01253ee202afce4bc61f28dec069a6f16f6c8a7dd2afae44148f6ff4d0029d5c607b5fa6b8c8a6301cde5c7033565cd0b8f0974ab490b236197ba04a",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);

		}
		hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0",IV);	

	}	
	if(Mode == MODE_CTR) {
		if(RG256 == RG_128_256){

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("30026c329666141721178b99c0a1f1b2f06940253f7b3089e2a30ea86aa3c88f5940f05ad7ee41d71347bb7261e348f18360473fdf7d4e7723bffb4411cc13f6cdd89f3bc7b9c768145022c7a74f14d7c305cd012a10f16050c23f1ae5c23f45998d13fbaa041e51619577e0772764896a5d4516d8ffceb3bf7e05f613edd9a60cdcedaff9cfcaf4e00d445a54334f73ab2cad944e51d266548e61c6eb0aa1cd",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);
		}
		else
		{
			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("ac5d7de805a0bf1c57c854501af60fa11497e2a34519dea1569e91e5b5ccae2ff3bfa1bf975f4571f48be191613546c3911163c085f871f0e7ae5f2a085b81851c2a3ddf20ecb8fa51901aec8ee4ba32a35dab67bb72cd9140ad188a967ac0fbbdfa94ea6cce47dcf8525ab5a814cfeb2bb60ee2b126e2d9d847c1a9e96f9019e3e6a7fe40d3829afb73db1cc245646addb62d9b907baaafbe46a73dbc131d3d",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);

		}
		memset(IV,0,16);


	}
#endif
    

}
#define TWO_LEN 64
void AES_ARIA_OPERATION_MODE_TEST32()
{
	//AES TEST
	int i;
	int j;
	unsigned int inst = 0;
	//unsigned char addr[2];
	unsigned char SOURCE[16*10];
	unsigned char RESULT[16*10];
	unsigned char IV[16];
	unsigned char KEY[32];	
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char CT[32];
	unsigned char PT[32];	
	unsigned char AES128KEY[16];
	unsigned char AES128CT[TWO_LEN];
	unsigned char AES128PT[TWO_LEN];
	unsigned char AES256KEY[32];
	unsigned char AES256CT[TWO_LEN];
	unsigned char AES256PT[TWO_LEN];

	unsigned char ARIA128KEY[16];
	unsigned char ARIA128CT[TWO_LEN];
	unsigned char ARIA128PT[TWO_LEN];
	unsigned char ARIA256KEY[32];
	unsigned char ARIA256CT[TWO_LEN];
	unsigned char ARIA256PT[TWO_LEN];

	unsigned char *pKEY;
	unsigned char *pPT;
	unsigned char *pCT;
	unsigned char KEYBUFFER[64];
	memset(KEYBUFFER,0,64);
#if 1	
	eep_page_write(0xec, 0x80, KEYBUFFER, 1);
	hexstr2bytes("000102030405060708090a0b0c0d0e0f",AES128KEY);
	hexstr2bytes("69c4e0d86a7b0430d8cdb78070b4c55a69c4e0d86a7b0430d8cdb78070b4c55a69c4e0d86a7b0430d8cdb78070b4c55a69c4e0d86a7b0430d8cdb78070b4c55a",AES128CT);	
	hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",AES128PT);		

	hexstr2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",AES256KEY);
	hexstr2bytes("8ea2b7ca516745bfeafc49904b4960898ea2b7ca516745bfeafc49904b4960898ea2b7ca516745bfeafc49904b4960898ea2b7ca516745bfeafc49904b496089",AES256CT);	
	hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",AES256PT);	

	Serial.println("\r\n . AES MODE_ECB 128 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AES128KEY,16,NULL,PT,AES128CT,32,MODE_ECB,0);
	if(memcmp(PT,AES128PT,32) == 0)
	   Serial.println(" PASS");
	else {
		Serial.println("\r\n PT");
		printbyte(PT,32);
		Serial.println("\r\n AES128PT");
		printbyte(AES128PT,32);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,AES128CT+32,32,MODE_ECB,LAST);
	if(memcmp(PT,AES128PT+32,32) == 0)
	   Serial.println(" PASS");
	else {
		Serial.println("\r\n PT");
		printbyte(PT,32);
		Serial.println("\r\n AES128PT");
		printbyte(AES128PT+32,32);	
	}
	
	//return;
	
	Serial.println("\r\n . AES MODE_ECB 128 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AES128KEY,16,NULL,CT,AES128PT,32,MODE_ECB,0);
	if(memcmp(CT,AES128CT,32) == 0)
	   Serial.println(" PASS");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,AES128PT+32,32,MODE_ECB,LAST);
	if(memcmp(CT,AES128CT+32,32) == 0)
	   Serial.println(" PASS");	
	
	

	Serial.println("\r\n . AES MODE_ECB 256 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AES256KEY,32,NULL,CT,AES256PT,32,MODE_ECB,0);
	if(memcmp(CT,AES256CT,32) == 0)
	   Serial.println(" PASS");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,AES256PT+32,32,MODE_ECB,LAST);
	if(memcmp(CT,AES256CT+32,32) == 0)
	   Serial.println(" PASS");
	
	Serial.println("\r\n . AES MODE_ECB 256 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AES256KEY,32,NULL,PT,AES256CT,32,MODE_ECB,0);
	if(memcmp(PT,AES256PT,32) == 0)
	   Serial.println(" PASS");
	else {
		printk("\r\n PT");
		printbyte(PT,32);
		printk("\r\n AES256PT");
		printbyte(AES256PT,32);	
	}	

	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,AES256CT,32,MODE_ECB,LAST);
	if(memcmp(PT,AES256PT,32) == 0)
	   Serial.println(" PASS");
	else {
		printk("\r\n PT");
		printbyte(PT,32);
		printk("\r\n AES256PT");
		printbyte(AES256PT,32);	
	}	


#endif
	{
	unsigned char AESCBC128KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char AESCBC128IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESCBC128PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESCBC128CT[] = { 0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2,0x73,0xbe,0xd6,0xb8,0xe3,0xc1,0x74,0x3b,0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16,0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09,0x12,0x0e,0xca,0x30,0x75,0x86,0xe1,0xa7};
	Serial.println("\r\n . AES MODE_CBC 128 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCBC128KEY,16,AESCBC128IV,CT,AESCBC128PT,32,MODE_CBC,0);
	if(memcmp(CT,AESCBC128CT,32) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,32);
	
		printk("\r\n AESCBC128CT");
		printbyte(AESCBC128CT,32);	
	}


	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCBC128PT[16*2],32,MODE_CBC,LAST);
	if(memcmp(CT,&AESCBC128CT[16*2],32) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCBC128CT");
		printbyte(&AESCBC128CT[16*2],16);	
	}
	

		
	Serial.println("\r\n . AES MODE_CBC 128 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCBC128KEY,16,AESCBC128IV,PT,AESCBC128CT,32,MODE_CBC,0);
	if(memcmp(PT,AESCBC128PT,32) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC128PT");
		printbyte(AESCBC128PT,16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCBC128CT[16*2],32,MODE_CBC,LAST);
	if(memcmp(PT,&AESCBC128PT[16*2],32) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC128PT");
		printbyte(&AESCBC128PT[16*2],16);	
	}
	

}
	{
	unsigned char AESCBC256KEY[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
	unsigned char AESCBC256IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESCBC256PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESCBC256CT[] = { 0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d,0x39,0xf2,0x33,0x69,0xa9,0xd9,0xba,0xcf,0xa5,0x30,0xe2,0x63,0x04,0x23,0x14,0x61,0xb2,0xeb,0x05,0xe2,0xc3,0x9b,0xe9,0xfc,0xda,0x6c,0x19,0x07,0x8c,0x6a,0x9d,0x1b};
	Serial.println("\r\n . AES MODE_CBC 256 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCBC256KEY,32,AESCBC256IV,CT,AESCBC256PT,32,MODE_CBC,0);
	if(memcmp(CT,AESCBC256CT,32) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCBC256CT");
		printbyte(AESCBC256CT,16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCBC256PT[16*2],32,MODE_CBC,LAST);
	if(memcmp(CT,&AESCBC256CT[16*2],32) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCBC256CT");
		printbyte(&AESCBC256CT[16*2],16);	
	}
	
		
	Serial.println("\r\n . AES MODE_CBC 256 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCBC256KEY,32,AESCBC256IV,PT,AESCBC256CT,32,MODE_CBC,0);
	if(memcmp(PT,AESCBC256PT,32) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC256PT");
		printbyte(AESCBC256PT,16);	
	}

	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCBC256CT[16*2],32,MODE_CBC,LAST);
	if(memcmp(PT,&AESCBC256PT[16*2],32) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCBC256PT");
		printbyte(&AESCBC256PT[16*2],16);	
	}

	

}

	{
	unsigned char AESCFB128KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char AESCFB128IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESCFB128PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESCFB128CT[] = { 0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a,0xc8,0xa6,0x45,0x37,0xa0,0xb3,0xa9,0x3f,0xcd,0xe3,0xcd,0xad,0x9f,0x1c,0xe5,0x8b,0x26,0x75,0x1f,0x67,0xa3,0xcb,0xb1,0x40,0xb1,0x80,0x8c,0xf1,0x87,0xa4,0xf4,0xdf,0xc0,0x4b,0x05,0x35,0x7c,0x5d,0x1c,0x0e,0xea,0xc4,0xc6,0x6f,0x9f,0xf7,0xf2,0xe6};
	Serial.println("\r\n . AES MODE_CFB 128 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCFB128KEY,16,AESCFB128IV,CT,AESCFB128PT,32,MODE_CFB,0);
	if(memcmp(CT,AESCFB128CT,32) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB128CT");
		printbyte(AESCFB128CT,16);	
	}

	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCFB128PT[16*2],32,MODE_CFB,LAST);
	if(memcmp(CT,&AESCFB128CT[16*2],32) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB128CT");
		printbyte(&AESCFB128CT[16*2],16);	
	}
	
		
	Serial.println("\r\n . AES MODE_CFB 128 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCFB128KEY,16,AESCFB128IV,PT,AESCFB128CT,32,MODE_CFB,0);
	if(memcmp(PT,AESCFB128PT,32) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB128PT");
		printbyte(AESCFB128PT,16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCFB128CT[16*2],32,MODE_CFB,LAST);
	if(memcmp(PT,&AESCFB128PT[16*2],32) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB128PT");
		printbyte(&AESCFB128PT[16*2],16);	
	}

	

}
	{
	unsigned char AESCFB256KEY[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
	unsigned char AESCFB256IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESCFB256PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESCFB256CT[] = { 0xdc,0x7e,0x84,0xbf,0xda,0x79,0x16,0x4b,0x7e,0xcd,0x84,0x86,0x98,0x5d,0x38,0x60,0x39,0xff,0xed,0x14,0x3b,0x28,0xb1,0xc8,0x32,0x11,0x3c,0x63,0x31,0xe5,0x40,0x7b,0xdf,0x10,0x13,0x24,0x15,0xe5,0x4b,0x92,0xa1,0x3e,0xd0,0xa8,0x26,0x7a,0xe2,0xf9,0x75,0xa3,0x85,0x74,0x1a,0xb9,0xce,0xf8,0x20,0x31,0x62,0x3d,0x55,0xb1,0xe4,0x71};
	Serial.println("\r\n . AES MODE_CFB 256 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCFB256KEY,32,AESCFB256IV,CT,AESCFB256PT,32,MODE_CFB,0);
	if(memcmp(CT,AESCFB256CT,16) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB256CT");
		printbyte(AESCFB256CT,16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCFB256PT[16*2],32,MODE_CFB,LAST);
	if(memcmp(CT,&AESCFB256CT[16*2],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESCFB256CT");
		printbyte(&AESCFB256CT[16*2],16);	
	}
	
		
	Serial.println("\r\n . AES MODE_CFB 256 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCFB256KEY,32,AESCFB256IV,PT,AESCFB256CT,32,MODE_CFB,0);
	if(memcmp(PT,AESCFB256PT,32) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB256PT");
		printbyte(AESCFB256PT,16);	
	}

	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCFB256CT[16*2],32,MODE_CFB,LAST);
	if(memcmp(PT,&AESCFB256PT[16*2],32) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESCFB256PT");
		printbyte(&AESCFB256PT[16*2],16);	
	}

	

}
	{
	unsigned char AESOFB128KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char AESOFB128IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESOFB128PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESOFB128CT[] = { 0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a,0x77,0x89,0x50,0x8d,0x16,0x91,0x8f,0x03,0xf5,0x3c,0x52,0xda,0xc5,0x4e,0xd8,0x25,0x97,0x40,0x05,0x1e,0x9c,0x5f,0xec,0xf6,0x43,0x44,0xf7,0xa8,0x22,0x60,0xed,0xcc,0x30,0x4c,0x65,0x28,0xf6,0x59,0xc7,0x78,0x66,0xa5,0x10,0xd9,0xc1,0xd6,0xae,0x5e};
	printk("\r\n . AES MODE_OFB 128 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESOFB128KEY,16,AESOFB128IV,CT,AESOFB128PT,32,MODE_OFB,0);
	if(memcmp(CT,AESOFB128CT,32) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB128CT");
		printbyte(AESOFB128CT,16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESOFB128PT[16*2],32,MODE_OFB,LAST);
	if(memcmp(CT,&AESOFB128CT[16*2],32) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB128CT");
		printbyte(&AESOFB128CT[16*2],16);	
	}
	
		
	Serial.println("\r\n . AES MODE_OFB 128 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESOFB128KEY,16,AESOFB128IV,PT,AESOFB128CT,32,MODE_OFB,0);
	if(memcmp(PT,AESOFB128PT,32) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB128PT");
		printbyte(AESOFB128PT,16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESOFB128CT[16*2],32,MODE_OFB,LAST);
	if(memcmp(PT,&AESOFB128PT[16*2],32) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB128PT");
		printbyte(&AESOFB128PT[16*2],16);	
	}

	

}
	{
	unsigned char AESOFB256KEY[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
	unsigned char AESOFB256IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	unsigned char AESOFB256PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
	unsigned char AESOFB256CT[] = { 0xdc,0x7e,0x84,0xbf,0xda,0x79,0x16,0x4b,0x7e,0xcd,0x84,0x86,0x98,0x5d,0x38,0x60,0x4f,0xeb,0xdc,0x67,0x40,0xd2,0x0b,0x3a,0xc8,0x8f,0x6a,0xd8,0x2a,0x4f,0xb0,0x8d,0x71,0xab,0x47,0xa0,0x86,0xe8,0x6e,0xed,0xf3,0x9d,0x1c,0x5b,0xba,0x97,0xc4,0x08,0x01,0x26,0x14,0x1d,0x67,0xf3,0x7b,0xe8,0x53,0x8f,0x5a,0x8b,0xe7,0x40,0xe4,0x84};
	Serial.println("\r\n . AES MODE_OFB 256 ENC TEST");
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESOFB256KEY,32,AESOFB256IV,CT,AESOFB256PT,32,MODE_OFB,0);
	if(memcmp(CT,AESOFB256CT,32) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB256CT");
		printbyte(AESOFB256CT,16);	
	}
	dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESOFB256PT[16*2],32,MODE_OFB,LAST);
	if(memcmp(CT,&AESOFB256CT[16*2],16) == 0)
	   Serial.println(" PASS");	
	else{
		printk("\r\n CT");
		printbyte(CT,16);
	
		printk("\r\n AESOFB256CT");
		printbyte(&AESOFB256CT[16*2],16);	
	}
	
		
	printk("\r\n . AES MODE_OFB 256 DEC TEST");
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESOFB256KEY,32,AESOFB256IV,PT,AESOFB256CT,32,MODE_OFB,0);
	if(memcmp(PT,AESOFB256PT,32) == 0)
	   Serial.println(" PASS");
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB256PT");
		printbyte(AESOFB256PT,16);	
	}
	dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESOFB256CT[16*2],32,MODE_OFB,LAST);
	if(memcmp(PT,&AESOFB256PT[16*2],16) == 0)
	   Serial.println(" PASS"); 
	else{
		printk("\r\n PT");
		printbyte(PT,16);

		printk("\r\n AESOFB256PT");
		printbyte(&AESOFB256PT[16*2],16);	
	}

	

}

		{
		unsigned char AESCTR128KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
		unsigned char AESCTR128IV[] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
		unsigned char AESCTR128PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
		unsigned char AESCTR128CT[] = { 0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee};
		Serial.println("\r\n . AES MODE_CTR 128 ENC TEST");
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCTR128KEY,16,AESCTR128IV,CT,AESCTR128PT,32,MODE_CTR,0);
		if(memcmp(CT,AESCTR128CT,32) == 0)
		   Serial.println(" PASS");
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR128CT");
			printbyte(AESCTR128CT,16);	
		}
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,16,NULL,CT,&AESCTR128PT[16*2],32,MODE_CTR,LAST);
		if(memcmp(CT,&AESCTR128CT[16*2],32) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR128CT");
			printbyte(&AESCTR128CT[16*2],16);	
		}
		
			
		Serial.println("\r\n . AES MODE_CTR 128 DEC TEST");
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCTR128KEY,16,AESCTR128IV,PT,AESCTR128CT,32,MODE_CTR,0);
		if(memcmp(PT,AESCTR128PT,32) == 0)
		   Serial.println(" PASS");
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR128PT");
			printbyte(AESCTR128PT,16);	
		}
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,16,NULL,PT,&AESCTR128CT[16*2],32,MODE_CTR,LAST);
		if(memcmp(PT,&AESCTR128PT[16*2],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR128PT");
			printbyte(&AESCTR128PT[16*2],16);	
		}
	
	
	}
		{
		unsigned char AESCTR256KEY[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
		unsigned char AESCTR256IV[] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
		unsigned char AESCTR256PT[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
		unsigned char AESCTR256CT[] = { 0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5,0x2b,0x09,0x30,0xda,0xa2,0x3d,0xe9,0x4c,0xe8,0x70,0x17,0xba,0x2d,0x84,0x98,0x8d,0xdf,0xc9,0xc5,0x8d,0xb6,0x7a,0xad,0xa6,0x13,0xc2,0xdd,0x08,0x45,0x79,0x41,0xa6};
		Serial.println("\r\n . AES MODE_CTR 256 ENC TEST");
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AESCTR256KEY,32,AESCTR256IV,CT,AESCTR256PT,32,MODE_CTR,0);
		if(memcmp(CT,AESCTR256CT,16) == 0)
		   Serial.println(" PASS");
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR256CT");
			printbyte(AESCTR256CT,16);	
		}
		dorca3_cipher_decipher(RG_ENC,1 /*AES*/,NULL,32,NULL,CT,&AESCTR256PT[16*2],32,MODE_CTR,LAST);
		if(memcmp(CT,&AESCTR256CT[16*2],16) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n CT");
			printbyte(CT,16);
		
			printk("\r\n AESCTR256CT");
			printbyte(&AESCTR256CT[16*2],16);	
		}
		
		Serial.println("\r\n . AES MODE_CTR 256 DEC TEST");
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,AESCTR256KEY,32,AESCTR256IV,PT,AESCTR256CT,32,MODE_CTR,0);
		if(memcmp(PT,AESCTR256PT,32) == 0)
		   Serial.println(" PASS");
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR256PT");
			printbyte(AESCTR256PT,16);	
		}
		dorca3_cipher_decipher(RG_DEC,1 /*AES*/,NULL,32,NULL,PT,&AESCTR256CT[16*2],32,MODE_CTR,LAST);
		if(memcmp(PT,&AESCTR256PT[16*2],32) == 0)
		   Serial.println(" PASS"); 
		else{
			printk("\r\n PT");
			printbyte(PT,16);
	
			printk("\r\n AESCTR256PT");
			printbyte(&AESCTR256PT[16*2],16);	
		}
	
		
	
	}

	hexstr2bytes("00112233445566778899aabbccddeeff",ARIA128KEY);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb",ARIA128PT);	
	hexstr2bytes("c6ecd08e22c30abdb215cf74e2075e6ec6ecd08e22c30abdb215cf74e2075e6ec6ecd08e22c30abdb215cf74e2075e6ec6ecd08e22c30abdb215cf74e2075e6e",ARIA128CT);		

	hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",ARIA256KEY);
	hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb11111111aaaaaaaa11111111bbbbbbbb",ARIA256PT);	
	hexstr2bytes("58a875e6044ad7fffa4f58420f7f442d58a875e6044ad7fffa4f58420f7f442d58a875e6044ad7fffa4f58420f7f442d58a875e6044ad7fffa4f58420f7f442d",ARIA256CT);	

	Serial.println("\r\n . ARIA MODE_ECB 128 ENC TEST");                                           
	dorca3_cipher_decipher(RG_ENC,2/*ARIA*/,ARIA128KEY,16,NULL,CT,ARIA128PT,32,MODE_ECB,0); 
	if(memcmp(CT,ARIA128CT,32) == 0)                                                       
	   Serial.println(" PASS");                                                                   
	dorca3_cipher_decipher(RG_ENC,2/*ARIA*/,NULL,16,NULL,CT,ARIA128PT+32,32,MODE_ECB,LAST);
	if(memcmp(CT,ARIA128CT+32,32) == 0)                                                    
	   Serial.println(" PASS");	                                                                  
	                                                                                      
	Serial.println("\r\n . ARIA MODE_ECB 128 DEC TEST");                                           
	dorca3_cipher_decipher(RG_DEC,2/*ARIA*/,ARIA128KEY,16,NULL,PT,ARIA128CT,32,MODE_ECB,0); 
	if(memcmp(PT,ARIA128PT,32) == 0)                                                       
	   Serial.println(" PASS");                                                                   
	else {                                                                                
		printk("\r\n PT");                                                                  
		printbyte(PT,32);                                                                   
		printk("\r\n ARIA128PT");                                                            
		printbyte(ARIA128PT,32);	                                                            
	}                                                                                     
	dorca3_cipher_decipher(RG_DEC,2/*ARIA*/,NULL,16,NULL,PT,ARIA128CT+32,32,MODE_ECB,LAST);
	if(memcmp(PT,ARIA128PT+32,32) == 0)                                                    
	   Serial.println(" PASS");                                                                   
	else {                                                                                
		printk("\r\n PT");                                                                  
		printbyte(PT,32);                                                                   
		printk("\r\n ARIA128PT");                                                            
		printbyte(ARIA128PT+32,32);	                                                        
	}                                                                                     
	                                                                                      
                                                                                        
	Serial.println("\r\n . ARIA MODE_ECB 256 ENC TEST");                                           
	dorca3_cipher_decipher(RG_ENC,2/*ARIA*/,ARIA256KEY,32,NULL,CT,ARIA256PT,32,MODE_ECB,0); 
	if(memcmp(CT,ARIA256CT,32) == 0)                                                       
	   Serial.println(" PASS");                                                                   
	dorca3_cipher_decipher(RG_ENC,2/*ARIA*/,NULL,32,NULL,CT,ARIA256PT+32,32,MODE_ECB,LAST);
	if(memcmp(CT,ARIA256CT+32,32) == 0)                                                    
	   Serial.println(" PASS");                                                                   
	                                                                                      
	printk("\r\n . ARIA MODE_ECB 256 DEC TEST");                                           
	dorca3_cipher_decipher(RG_DEC,2/*ARIA*/,ARIA256KEY,32,NULL,PT,ARIA256CT,32,MODE_ECB,0); 
	if(memcmp(PT,ARIA256PT,32) == 0)                                                       
	   Serial.println(" PASS");                                                                   
	else {                                                                                
		printk("\r\n PT");                                                                  
		printbyte(PT,32);                                                                   
		printk("\r\n ARIA256PT");                                                            
		printbyte(ARIA256PT,32);	                                                            
	}	                                                                            
                                                                                
	dorca3_cipher_decipher(RG_DEC,2/*ARIA*/,NULL,32,NULL,PT,ARIA256CT,32,MODE_ECB,LAST); 
	if(memcmp(PT,ARIA256PT,32) == 0)                                               
	   Serial.println(" PASS");                                                           
	else {                                                                        
		printk("\r\n PT");                                                          
		printbyte(PT,32);                                                           
		printk("\r\n ARIA256PT");                                                    
		printbyte(ARIA256PT,32);	                                                    
		}                      



	

	{

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("49d61860b14909109cef0d22a9268134fadf9fb23151e9645fba75018bdb1538b53334634bbf7d4cd4b5377033060c155fe3948ca75de1031e1d85619e0ad61eb419a866b3c2dbfd10a4ed18b22149f75897f0b8668b0c1c542c687778835fb7cd46e45f85eaa7072437dd9fa6793d6f8d4ccefc4eb1ac641ac1bd30b18c6d64c49bca137eb21c2e04da62712ca2b4f540c57112c38791852cfac7a5d19ed83a",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);
			hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0",IV);	
			Serial.println("\r\n . ARIA MODE_CBC 128 ENC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,16,IV,CT,&SOURCE[16*i],32,MODE_CBC,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],32,MODE_CBC,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],32,MODE_CBC,0);

				if(memcmp(CT,&RESULT[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			Serial.println("\r\n . ARIA MODE_CBC 128 DEC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,16,IV,PT,&RESULT[16*i],32,MODE_CBC,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],32,MODE_CBC,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],32,MODE_CBC,0);

				if(memcmp(PT,&SOURCE[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("523a8a806ae621f155fdd28dbc34e1ab7b9b42432ad8b2efb96e23b13f0a6e52f36185d50ad002c5f601bee5493f118b243ee2e313642bffc3902e7b2efd9a12fa682edd2d23c8b9c5f043c18b17c1ec4b5867918270fbec1027c19ed6af833da5d620994668ca22f599791d292dd6273b2959082aafb7a996167cce1eec5f0cfd15f610d87e2dda9ba68ce1260ca54b222491418374294e7909b1e8551cd8de",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);			
			Serial.println("\r\n. ARIA MODE_CBC 256 ENC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,32,IV,CT,&SOURCE[16*i],32,MODE_CBC,0);
				}	
				else if( 8  == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],32,MODE_CBC,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],32,MODE_CBC,0);

				if(memcmp(CT,&RESULT[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			Serial.println("\r\n . ARIA MODE_CBC 256 DEC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,32,IV,PT,&RESULT[16*i],32,MODE_CBC,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],32,MODE_CBC,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],32,MODE_CBC,0);

				if(memcmp(PT,&SOURCE[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}


			
			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("3720e53ba7d615383406b09f0a05a200c07c21e6370f413a5d132500a68285017c61b434c7b7ca9685a51071861e4d4bb873b599b479e2d573dddeafba89f812ac6a9e44d554078eb3be94839db4b33da3f59c063123a7ef6f20e10579fa4fd239100ca73b52d4fcafeadee73f139f78f9b7614c2b3b9dbe010f87db06a89a9435f79ce8121431371f4e87b984e0230c22a6dacb32fc42dcc6accef33285bf11",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);	
			hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0",IV);
			Serial.println("\r\n. ARIA MODE_CFB 128 ENC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,16,IV,CT,&SOURCE[16*i],32,MODE_CFB,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],32,MODE_CFB,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],32,MODE_CFB,0);

				if(memcmp(CT,&RESULT[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			Serial.println("\r\n . ARIA MODE_CFB 128 DEC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,16,IV,PT,&RESULT[16*i],32,MODE_CFB,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],32,MODE_CFB,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],32,MODE_CFB,0);

				if(memcmp(PT,&SOURCE[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("26834705b0f2c0e2588d4a7f09009635f28bb93d8c31f870ec1e0bdb082b66fa402dd9c202be300c4517d196b14d4ce11dce97f7aaba54341b0d872cc9b63753a3e8556a14be6f7b3e27e3cfc39caf80f2a355aa50dc83c09c7b11828694f8e4aa726c528976b53f2c877f4991a3a8d28adb63bd751846ffb2350265e179d4990753ae8485ff9b4133ddad5875b84a90cbcfa62a045d726df71b6bda0eeca0be",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);			
			printk("\r\n. ARIA MODE_CFB 256 ENC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,32,IV,CT,&SOURCE[16*i],32,MODE_CFB,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],32,MODE_CFB,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],32,MODE_CFB,0);

				if(memcmp(CT,&RESULT[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			Serial.println("\r\n . ARIA MODE_CFB 256 DEC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,32,IV,PT,&RESULT[16*i],32,MODE_CFB,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],32,MODE_CFB,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],32,MODE_CFB,0);

				if(memcmp(PT,&SOURCE[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("3720e53ba7d615383406b09f0a05a2000063063f0560083483faeb041c8adecef30cf80cefb002a0d280759168ec01db3d49f61aced260bd43eec0a2731730eec6fa4f2304319cf8ccac2d7be7833e4f8ae6ce967012c1c6badc5d28e7e4144f6bf5cebe01253ee202afce4bc61f28dec069a6f16f6c8a7dd2afae44148f6ff4d0029d5c607b5fa6b8c8a6301cde5c7033565cd0b8f0974ab490b236197ba04a",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);

			hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0",IV);
			Serial.println("\r\n . ARIA MODE_OFB 128 ENC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,16,IV,CT,&SOURCE[16*i],32,MODE_OFB,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],32,MODE_OFB,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],32,MODE_OFB,0);

				if(memcmp(CT,&RESULT[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			Serial.println("\r\n . ARIA MODE_OFB 128 DEC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,16,IV,PT,&RESULT[16*i],32,MODE_OFB,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],32,MODE_OFB,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],32,MODE_OFB,0);

				if(memcmp(PT,&SOURCE[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}


			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("26834705b0f2c0e2588d4a7f0900963584c256815c4292b59f8d3f966a75b52345b4f5f98c785d3f368a8d5ff89b7f950ceab3cd63773c2621d652b8ef98b4196afb2c2b30496bc5b7d9e7f9084f9d855f63a511751c8909e7a6deadbe0a67a4fb89383ca5d209c6f66f793fc471195c476fb9c1eab2ac91e680e454b4f3ed9a67fb52f09c29b965b23cfa6f3f6bbb2a86c6cdbaa2857bf2486f543231892a52",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);	
			Serial.println("\r\n . ARIA MODE_OFB 256 ENC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,32,IV,CT,&SOURCE[16*i],32,MODE_OFB,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],32,MODE_OFB,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],32,MODE_OFB,0);

				if(memcmp(CT,&RESULT[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			Serial.println("\r\n . ARIA MODE_OFB 256 DEC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,32,IV,PT,&RESULT[16*i],32,MODE_OFB,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],32,MODE_OFB,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],32,MODE_OFB,0);

				if(memcmp(PT,&SOURCE[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}


			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("ac5d7de805a0bf1c57c854501af60fa11497e2a34519dea1569e91e5b5ccae2ff3bfa1bf975f4571f48be191613546c3911163c085f871f0e7ae5f2a085b81851c2a3ddf20ecb8fa51901aec8ee4ba32a35dab67bb72cd9140ad188a967ac0fbbdfa94ea6cce47dcf8525ab5a814cfeb2bb60ee2b126e2d9d847c1a9e96f9019e3e6a7fe40d3829afb73db1cc245646addb62d9b907baaafbe46a73dbc131d3d",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);
			memset(IV,0,16);

			Serial.println("\r\n . ARIA MODE_CTR 128 ENC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,16,IV,CT,&SOURCE[16*i],32,MODE_CTR,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],32,MODE_CTR,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,16,NULL,CT,&SOURCE[16*i],32,MODE_CTR,0);

				if(memcmp(CT,&RESULT[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			Serial.println("\r\n . ARIA MODE_CTR 128 DEC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,16,IV,PT,&RESULT[16*i],32,MODE_CTR,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],32,MODE_CTR,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,16,NULL,PT,&RESULT[16*i],32,MODE_CTR,0);

				if(memcmp(PT,&SOURCE[16*i],16) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}


			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("30026c329666141721178b99c0a1f1b2f06940253f7b3089e2a30ea86aa3c88f5940f05ad7ee41d71347bb7261e348f18360473fdf7d4e7723bffb4411cc13f6cdd89f3bc7b9c768145022c7a74f14d7c305cd012a10f16050c23f1ae5c23f45998d13fbaa041e51619577e0772764896a5d4516d8ffceb3bf7e05f613edd9a60cdcedaff9cfcaf4e00d445a54334f73ab2cad944e51d266548e61c6eb0aa1cd",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);	
			Serial.println("\r\n . ARIA MODE_CTR 256 ENC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,KEY,32,IV,CT,&SOURCE[16*i],32,MODE_CTR,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],32,MODE_CTR,LAST);
				else
					dorca3_cipher_decipher(RG_ENC,2 /*ARIA*/,NULL,32,NULL,CT,&SOURCE[16*i],32,MODE_CTR,0);

				if(memcmp(CT,&RESULT[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n CT");
					printbyte(CT,16);
			
					printk("\r\n &RESULT");
					printbyte(&RESULT[16*i],16);	
				}
			}

			Serial.println("\r\n . ARIA MODE_CTR 256 DEC TEST");	
			for(i = 0; i < 10; i += 2 ){
				
				if(0 == i){
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,KEY,32,IV,PT,&RESULT[16*i],32,MODE_CTR,0);
				}	
				else if( 8 == i)
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],32,MODE_CTR,LAST);
				else
					dorca3_cipher_decipher(RG_DEC,2 /*ARIA*/,NULL,32,NULL,PT,&RESULT[16*i],32,MODE_CTR,0);

				if(memcmp(PT,&SOURCE[16*i],32) == 0)
				   Serial.println(" PASS"); 
				else{
					printk("\r\n PT");
					printbyte(PT,16);
			
					printk("\r\n &RESULT");
					printbyte(&SOURCE,16);	
				}
			}
  }
#if 0			
			printk(". ARIA MODE_CBC 128 DEC TEST");				
			
			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("523a8a806ae621f155fdd28dbc34e1ab7b9b42432ad8b2efb96e23b13f0a6e52f36185d50ad002c5f601bee5493f118b243ee2e313642bffc3902e7b2efd9a12fa682edd2d23c8b9c5f043c18b17c1ec4b5867918270fbec1027c19ed6af833da5d620994668ca22f599791d292dd6273b2959082aafb7a996167cce1eec5f0cfd15f610d87e2dda9ba68ce1260ca54b222491418374294e7909b1e8551cd8de",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);
			printk(". ARIA MODE_CBC 256 ENC TEST");
			printk(". ARIA MODE_CBC 256 DEC TEST");			


	}
	if(Mode == MODE_CFB) {
		if(RG256 == RG_128_256){

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("26834705b0f2c0e2588d4a7f09009635f28bb93d8c31f870ec1e0bdb082b66fa402dd9c202be300c4517d196b14d4ce11dce97f7aaba54341b0d872cc9b63753a3e8556a14be6f7b3e27e3cfc39caf80f2a355aa50dc83c09c7b11828694f8e4aa726c528976b53f2c877f4991a3a8d28adb63bd751846ffb2350265e179d4990753ae8485ff9b4133ddad5875b84a90cbcfa62a045d726df71b6bda0eeca0be",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);
		}
		else
		{
			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("3720e53ba7d615383406b09f0a05a200c07c21e6370f413a5d132500a68285017c61b434c7b7ca9685a51071861e4d4bb873b599b479e2d573dddeafba89f812ac6a9e44d554078eb3be94839db4b33da3f59c063123a7ef6f20e10579fa4fd239100ca73b52d4fcafeadee73f139f78f9b7614c2b3b9dbe010f87db06a89a9435f79ce8121431371f4e87b984e0230c22a6dacb32fc42dcc6accef33285bf11",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);

		}
		hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0",IV);	

	}
	if(Mode == MODE_OFB) {
		if(RG256 == RG_128_256){

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("26834705b0f2c0e2588d4a7f0900963584c256815c4292b59f8d3f966a75b52345b4f5f98c785d3f368a8d5ff89b7f950ceab3cd63773c2621d652b8ef98b4196afb2c2b30496bc5b7d9e7f9084f9d855f63a511751c8909e7a6deadbe0a67a4fb89383ca5d209c6f66f793fc471195c476fb9c1eab2ac91e680e454b4f3ed9a67fb52f09c29b965b23cfa6f3f6bbb2a86c6cdbaa2857bf2486f543231892a52",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);
		}
		else
		{
			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("3720e53ba7d615383406b09f0a05a2000063063f0560083483faeb041c8adecef30cf80cefb002a0d280759168ec01db3d49f61aced260bd43eec0a2731730eec6fa4f2304319cf8ccac2d7be7833e4f8ae6ce967012c1c6badc5d28e7e4144f6bf5cebe01253ee202afce4bc61f28dec069a6f16f6c8a7dd2afae44148f6ff4d0029d5c607b5fa6b8c8a6301cde5c7033565cd0b8f0974ab490b236197ba04a",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);

		}
		hexstr2bytes("0f1e2d3c4b5a69788796a5b4c3d2e1f0",IV);	

	}	
	if(Mode == MODE_CTR) {
		if(RG256 == RG_128_256){

			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("30026c329666141721178b99c0a1f1b2f06940253f7b3089e2a30ea86aa3c88f5940f05ad7ee41d71347bb7261e348f18360473fdf7d4e7723bffb4411cc13f6cdd89f3bc7b9c768145022c7a74f14d7c305cd012a10f16050c23f1ae5c23f45998d13fbaa041e51619577e0772764896a5d4516d8ffceb3bf7e05f613edd9a60cdcedaff9cfcaf4e00d445a54334f73ab2cad944e51d266548e61c6eb0aa1cd",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",KEY);
		}
		else
		{
			hexstr2bytes("11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd",SOURCE);
			hexstr2bytes("ac5d7de805a0bf1c57c854501af60fa11497e2a34519dea1569e91e5b5ccae2ff3bfa1bf975f4571f48be191613546c3911163c085f871f0e7ae5f2a085b81851c2a3ddf20ecb8fa51901aec8ee4ba32a35dab67bb72cd9140ad188a967ac0fbbdfa94ea6cce47dcf8525ab5a814cfeb2bb60ee2b126e2d9d847c1a9e96f9019e3e6a7fe40d3829afb73db1cc245646addb62d9b907baaafbe46a73dbc131d3d",RESULT);
			hexstr2bytes("00112233445566778899aabbccddeeff",KEY);

		}
		memset(IV,0,16);


	}
#endif
    

}


void _ecdsa_gen_public_key(unsigned char *private_key, point *public_key)
{
	unsigned char buffer_ecdsa[256];
	unsigned char buffer_receive[256];
	printk("\r\n ecdsa_test P256");

	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = SIZE_ECDSA_256;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;
	send_data_arm7(buffer_ecdsa,5);
	delay_ms(40);	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_PrivateKey;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	memcpy(&buffer_ecdsa[5],private_key,32);
	send_data_arm7(buffer_ecdsa,37);
	delay_ms(40);
//	printk("\r\n private key in api");
//	printbyte(private_key,32);
	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Create_ECDSA_Public_Key;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;
	send_data_arm7(buffer_ecdsa,5);
	printk("\r\n Create_ECDSA_Public_Key");
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
	delay_ms(1000);
    buffer_ecdsa[0] = SPI1_READ_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Get_ECDSA_Public_Key_Yq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	read_data_arm7(buffer_ecdsa,public_key->y,32);

	         
	delay_ms(40);	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

    buffer_ecdsa[0] = SPI1_READ_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Get_ECDSA_Public_Key_Xq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	read_data_arm7(buffer_ecdsa,public_key->x,32);
	delay_ms(40);	
}
void _ecdsa_gen_signature(uint8_t *d, uint8_t *k, uint8_t *h, uint8_t *r, uint8_t *s)
{
		unsigned char buffer_ecdsa[256];
		unsigned char buffer_receive[256];
	
		buffer_ecdsa[0] = SPI1_WRITE_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = SIZE_ECDSA_256;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 0;
		send_data_arm7(buffer_ecdsa,5);
		delay_ms(40);	
#ifdef DEBUG_DELAY	
		delay_ms(4000);
#endif	
		buffer_ecdsa[0] = SPI1_WRITE_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Set_ECDSA_PrivateKey;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 32;
		//hexstr2bytes("00d007e1b9afcc312eec9cecffa0280752bbd1953182edef12f3fc366e8f4356",&buffer_ecdsa[5]);
		memcpy(&buffer_ecdsa[5],d,32);
		send_data_arm7(buffer_ecdsa,37);
		delay_ms(40);	
	
		//return;
 #ifdef DEBUG_DELAY
		delay_ms(4000);
#endif	
		buffer_ecdsa[0] = SPI1_WRITE_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Set_ECDSA_K_RND;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 32;
		//hexstr2bytes("00c03c3b8b1e40cb328a61d51783356935625884399e26a5828f387c2bde6ebc",&buffer_ecdsa[5]);
		memcpy(&buffer_ecdsa[5],k,32);		
		send_data_arm7(buffer_ecdsa,37);
		delay_ms(40);	
	
		buffer_ecdsa[0] = SPI1_WRITE_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Set_ECDSA_h;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 32;
//		hexstr2bytes("0000000000000000000000000f7b55549fab573c0361b832ad0be8cdeef91b56",&buffer_ecdsa[5]);
		memcpy(&buffer_ecdsa[5],h,32);		
		send_data_arm7(buffer_ecdsa,37);		 
		delay_ms(40);	
	
		
		buffer_ecdsa[0] = SPI1_WRITE_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Create_ECDSA_Sign;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 0;
		send_data_arm7(buffer_ecdsa,5); 
        delay_ms(200);
#ifdef DEBUG_DELAY	
		delay_ms(4000);
#endif
	
			buffer_ecdsa[0] = SPI1_READ_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Get_ECDSA_r;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 32;
		read_data_arm7(buffer_ecdsa,r,32);
		
		delay_ms(40);	
#ifdef DEBUG_DELAY	
		delay_ms(4000);
#endif
	
		buffer_ecdsa[0] = SPI1_READ_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Get_ECDSA_s;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 32;
		read_data_arm7(buffer_ecdsa,s,32);
		
		delay_ms(40);	

}
//#define DEBUG_DELAY;

int _ecdsa_verify_signature(point *public_key, uint8_t *r,uint8_t *s,uint8_t *h )
{
	unsigned char buffer_ecdsa[256];
	unsigned char buffer_receive[256];


	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = SIZE_ECDSA_256;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;

	send_data_arm7(buffer_ecdsa,5);
	delay_ms(40);	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_r;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	memcpy(&buffer_ecdsa[5],r,32);
	send_data_arm7(buffer_ecdsa,37);
	delay_ms(40);	


	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_s;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	memcpy(&buffer_ecdsa[5],s,32);
	send_data_arm7(buffer_ecdsa,37);
	delay_ms(40);		


	#ifdef DEBUG_DELAY
    delay_ms(4000);
#endif	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_Public_Key_Xq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	memcpy(&buffer_ecdsa[5],public_key->x,32);
	send_data_arm7(buffer_ecdsa,37);
	delay_ms(40);	
#ifdef DEBUG_DELAY
	delay_ms(4000);
#endif	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_Public_Key_Yq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	memcpy(&buffer_ecdsa[5],public_key->y,32);
	send_data_arm7(buffer_ecdsa,37);
	printbyte2(buffer_ecdsa + 5, 32);
	delay_ms(40);	


	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_h;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
//		hexstr2bytes("0000000000000000000000000f7b55549fab573c0361b832ad0be8cdeef91b56",&buffer_ecdsa[5]);
	memcpy(&buffer_ecdsa[5],h,32);		
	send_data_arm7(buffer_ecdsa,37);		 
	delay_ms(40);	

	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Do_ECDSA_Verify;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;
	send_data_arm7(buffer_ecdsa,5);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
	delay_ms(250);


    buffer_ecdsa[0] = SPI1_READ_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Get_ECDSA_Result;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 1;
	read_data_arm7(buffer_ecdsa,buffer_receive,1);

	Serial.println("\r\n Get_ECDSA_Result");
	Serial.println(buffer_receive[0],HEX);
   return buffer_receive[0]; 

	

}

void ecdsa_gen_public_key_test(void)
{
	unsigned char private_key[32];
	unsigned char temp[32];	
	point  public_key;
	hexstr2bytes("00d007e1b9afcc312eec9cecffa0280752bbd1953182edef12f3fc366e8f4356",private_key);
	ecdsa_gen_public_key(private_key,&public_key);
	Serial.println("\r\nGet_ECDSA_Public_Key_Yq\r\n");
	printbyte(public_key.y,32); 
	Serial.println("\r\n Expected\r\n");
	Serial.println("\r\n cf4897766131aa8b7f80453a15bf90f7517878579d5a4f973aea5bb11542e07f");
	hexstr2bytes("cf4897766131aa8b7f80453a15bf90f7517878579d5a4f973aea5bb11542e07f",temp);
	if(memcmp(temp,public_key.y,32) == 0)
		Serial.println(" PASS");

	Serial.println("\r\nGet_ECDSA_Public_Key_Xq\r\n");
	printbyte(public_key.x,32); 
	Serial.println("\r\n Expected\r\n");
	Serial.println("\r\n d6606271131e7e7e617a81aa11f09e7ed56311828823367a869b454040b3f905");
	hexstr2bytes("d6606271131e7e7e617a81aa11f09e7ed56311828823367a869b454040b3f905",temp);
	if(memcmp(temp,public_key.x,32) == 0)
		Serial.println(" PASS");
}

void ecdsa_gen_signature_TEST()
{
	uint8_t h[32];
	uint8_t k[32];			
	uint8_t d[32];			
	uint8_t r[32];
	uint8_t s[32];
	uint8_t expected_r[32];
	uint8_t expected_s[32];	
	hexstr2bytes("00d007e1b9afcc312eec9cecffa0280752bbd1953182edef12f3fc366e8f4356",d);	
	hexstr2bytes("00c03c3b8b1e40cb328a61d51783356935625884399e26a5828f387c2bde6ebc",k);
	hexstr2bytes("0000000000000000000000000f7b55549fab573c0361b832ad0be8cdeef91b56",h);
	
	ecdsa_gen_signature(d,k,h,r,s);

	
	hexstr2bytes("b5b417619bf9fa89d50b3e22782a2de80a86db67e728114e6e0e91cab1a41612",expected_r);
	hexstr2bytes("e43e8111258bea6f5c96bd6d66715748fbee756da418de90f64066c6b3e072f1",expected_s);
	if(memcmp(expected_r,r,32) == 0)
		Serial.println("\r\n Gen Sig R pass");
	else {
		Serial.println("\r\n Expected r");
		printbyte(expected_r, 32);
	    Serial.println("\r\n Result");
		printbyte(r,32);
	}
		
	if(memcmp(expected_s,s,32) == 0)
		Serial.println("\r\n Gen Sig S pass");	
	else {
		Serial.println("\r\n Expected s");
		printbyte(expected_r, 32);
	    Serial.println("\r\n Result");
		printbyte(s,32);
	}	

}

void ecdsa_verify_signature_test()
{
	uint8_t r[32];
	uint8_t s[32];
	uint8_t h[32];
	point public_key;
	

	hexstr2bytes("cf4897766131aa8b7f80453a15bf90f7517878579d5a4f973aea5bb11542e07f",public_key.y);
	hexstr2bytes("d6606271131e7e7e617a81aa11f09e7ed56311828823367a869b454040b3f905",public_key.x);
//	hexstr2bytes("0000000000000000000000000f7b55549fab573c0361b832ad0be8cdeef91b56",h);

	hexstr2bytes("0000000000000000000000000f7b55549fab573c0361b832ad0be8cdeef91b56",h);
//0000000000000000000000000f7b55549fab573c0361b832ad0be8cdeef91b56
	hexstr2bytes("b5b417619bf9fa89d50b3e22782a2de80a86db67e728114e6e0e91cab1a41612",r);
	hexstr2bytes("e43e8111258bea6f5c96bd6d66715748fbee756da418de90f64066c6b3e072f1",s);
	
	if (ecdsa_verify_signature(&public_key,r,s,h) == 0)
		Serial.println("\r\n TEST PASS");
	else
		Serial.println("\r\n TEST FAIL");

}

int is_sleep()
{
	unsigned int i;
	unsigned char inst = 0x00;
	unsigned char addr[2] = { 0x06, 0x04};
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	unsigned char value0 = 0; 
	unsigned char value1 = 0; 
	for( i=0; i<64; i++)
	{
		tx_data[i] = 0x00;
		rx_data[i] = 0x00;
	}

	//printk("\r\nprint on");
	inst = 0x21;
	tx_data[0] = 0x00;	
	//printk("\r\n ADDRESS 0x10650'S VALUE");
	tspi_interface(cs, inst, RG_SLEEP_TIMER_MSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	value0 = rx_data[0];

	inst = 0x21;
	tx_data[0] = 0x00;	
	//printk("\r\n ADDRESS 0x10651'S VALUE");
	tspi_interface(cs, inst, RG_SLEEP_TIMER_LSB, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	value1 = rx_data[0];
	if(0 == value0 && 0 == value1)
		return 0;
	else
		return 1;

	
}
void CheckSleepMode()
{

	if(check_sleep() == 0)
		Serial.println("\r\nNon Sleep");
	else
		Serial.println("\r\n Sleep");
}


void TEST_AES() {
  unsigned char AES128KEY[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
  unsigned char AES128CT[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
  unsigned char AES128PT[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  unsigned char CT[16] = {0,};
  int i = 0;
  

  Dorca3_SPI_Init(1000*1000);
  Serial.println("\r\n . AES MODE_ECB 128 ENC TEST");
  dorca3_cipher_decipher(RG_ENC,1 /*AES*/,AES128KEY,16,NULL,CT,AES128PT,16,MODE_ECB,LAST);
  for( i = 0; i < 16; i++)
   Serial.println(CT[i], HEX);
  Dorca3_Close();

   
}
/*
void PowerOffOn()
{
	digitalWrite (POWER, HIGH);
	delay(2000);
	
	digitalWrite (POWER, HIGH);


}
*/
int _rsa_pub_enc_2048(unsigned char * pub_key_n,unsigned char * pub_key_e,unsigned char * out, unsigned char *in, size_t len,int padding)
{

	unsigned char buffer[512];
	unsigned char buffer_receive[256];

	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = SIZE_RSA_2048;
	buffer[3] = 0;
	buffer[4] = 0;
	send_data_arm7(buffer,5);
	delay_ms(40);

	memcpy(buffer+5,in,256);	
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PlainText_M;
	buffer[3] = 0x01;
	buffer[4] = 00;
	send_data_arm7(buffer,256+5);
	delay_ms(40);

	memcpy(buffer+5,pub_key_n,256); 
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_Modulus_n;
	buffer[3] = 0x01;
	buffer[4] = 00;
	send_data_arm7(buffer,256+5);
	delay_ms(40);

	memcpy(buffer+5,pub_key_e,256); 
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PublicExpo;
	buffer[3] = 0x01;
	buffer[4] = 00;
	send_data_arm7(buffer,256+5);
	delay_ms(40);

	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Encrypt_RSA;
	buffer[3] = 0;
	buffer[4] = 0;
	send_data_arm7(buffer,5);
	delay_ms(64);
	delay_ms(64);

	buffer[0] = SPI1_READ_DATA;
	buffer[1] = 0;
	buffer[2] = Get_RSA_CipherText_C;
	buffer[3] = 0x01;
	buffer[4] = 0;
	read_data_arm7(buffer,buffer_receive,256);
	
	memcpy(out,buffer_receive,256); 
}

int _rsa_pub_dec_2048(unsigned char * priv_key,unsigned char * pub_key_n,unsigned char * out, unsigned char *in, size_t len,int padding)
{

	unsigned char buffer[512];
	unsigned char buffer_receive[256];

	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = SIZE_RSA_2048;
	buffer[3] = 0;
	buffer[4] = 0;
	send_data_arm7(buffer,5);
	delay_ms(40);

	memcpy(buffer+5,in,256);	
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_CipherText_C;
	buffer[3] = 0x01;
	buffer[4] = 00;
	send_data_arm7(buffer,256+5);
	delay_ms(40);

	memcpy(buffer+5,pub_key_n,256); 
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_Modulus_n;
	buffer[3] = 0x01;
	buffer[4] = 00;
	send_data_arm7(buffer,256+5);
	delay_ms(40);

	memcpy(buffer+5,priv_key,256);	
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PrivateKey_d;
	buffer[3] = 0x01;
	buffer[4] = 00;
	send_data_arm7(buffer,256+5);
	delay_ms(40);

	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Decrypt_RSA;
	buffer[3] = 0;
	buffer[4] = 0;
	send_data_arm7(buffer,5);
	delay_ms(5500);

	buffer[0] = SPI1_READ_DATA;
	buffer[1] = 0;
	buffer[2] = Get_RSA_PlainText_M;
	buffer[3] = 0x01;
	buffer[4] = 0;
	read_data_arm7(buffer,buffer_receive,256);
	
	memcpy(out,buffer_receive,256); 
}


void TEST_RSA_ENCRYPT()
{
	unsigned char PlainText[256];
	unsigned char ModulusN[256];
	unsigned char PrivateKeyD[256];
	unsigned char CypherText[256];
	unsigned char PublicExpo[256];

	unsigned char ExpectedResult[256];	
	//PlainText
	hexstr2bytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011223344", PlainText);//RSA_msg
	//ModulusN
	hexstr2bytes("F748D8D98ED057CF398C437FEFC615D757D3F8ECE6F2C580AE0780768F9EC83AAA081FF09E5317ED6099C63FD15CFE11172F78908CD58C03AEC93A481FF50E172204AFEDFC1F16AFDB990AAB45BE190BC19259BD4A1BFCDFBE2A298B3C0E318F78A33919882328DACAC85CB35A0DE537B16376975217E5A5EAAF98266B588C2DBAFD0BE371C34989CB36E623D75EFFEDBE4A951A6840982BC279B30FCD41DAC87C0074D462F1012900B8973B46ADC7EAC01770DFC632EA967F9471E9789831F3A410730FF914348BE111863C13376301079756A147D80103CE9FA688A338E22B2D916CAD42D673C9D00F08214DE544F5DE812A9A949189078B2BDA14B28CA62F", ModulusN);//Modulus N
	//PulibcExpo
	hexstr2bytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001", PublicExpo);//RSA_expo

	rsa_pub_enc_2048(ModulusN,PublicExpo,CypherText,PlainText,256,0);

	hexstr2bytes("EE69099AFD9F99D6065D65E15F90B9237C16987D4872E2B994ED2B9E5685F9BA489AB936CC1E3DFD15B35FEE21536F8C2220AE43217D91D81C9ED01DE5BAEEF4EFC721D70D67B5166E43D82724F39BF0BD197C31E748518DEE63EC10987A08390B15CC4157677C54226A8B04B47684AEDD02B48C8ED48A44BD135397AC2869769B68C7D3BFACDB72AFCD7442C22517E044996CB68E0A311DF5D6D2D286372556F0193166CC364E654EF405DD22FBE584DBF60F0552960668FB69522C1B5264F194FAC9F35622E98227638FF28B910D8CC90E5011021212C96C64C85820877A7D1559235E99C32ABEF33D95E28E18CCA3442E6E3A432FFFEA10104A8EEE94C362", ExpectedResult);	
	if(memcmp(ExpectedResult,CypherText,256) == 0)
		Serial.println("\r\n PASS RSA ENCRYPTION TEST");
	else
		Serial.println("\r\n FAIL RSA ENCRYPTION TEST");
}

void TEST_RSA_DECRYPT()
{

	unsigned char PlainText[256];
	unsigned char ModulusN[256];

	unsigned char CypherText[256];
	unsigned char PrivateKeyD[256]; 

	unsigned char ExpectedResult[256];	
	//ModulusN
	hexstr2bytes("AE45ED5601CEC6B8CC05F803935C674DDBE0D75C4C09FD7951FC6B0CAEC313A8DF39970C518BFFBA5ED68F3F0D7F22A4029D413F1AE07E4EBE9E4177CE23E7F5404B569E4EE1BDCF3C1FB03EF113802D4F855EB9B5134B5A7C8085ADCAE6FA2FA1417EC3763BE171B0C62B760EDE23C12AD92B980884C641F5A8FAC26BDAD4A03381A22FE1B754885094C82506D4019A535A286AFEB271BB9BA592DE18DCF600C2AEEAE56E02F7CF79FC14CF3BDC7CD84FEBBBF950CA90304B2219A7AA063AEFA2C3C1980E560CD64AFE779585B6107657B957857EFDE6010988AB7DE417FC88D8F384C4E6E72C3F943E0C31C0C4A5CC36F879D8A3AC9D7D59860EAADA6B83BB", ModulusN);//Modulus N
	//Cypher Text		
	hexstr2bytes("53EA5DC08CD260FB3B858567287FA91552C30B2FEBFBA213F0AE87702D068D19BAB07FE574523DFB42139D68C3C5AFEEE0BFE4CB7969CBF382B804D6E61396144E2D0E60741F8993C3014B58B9B1957A8BABCD23AF854F4C356FB1662AA72BFCC7E586559DC4280D160C126785A723EBEEBEFF71F11594440AAEF87D10793A8774A239D4A04C87FE1467B9DAF85208EC6C7255794A96CC29142F9A8BD418E3C1FD67344B0CD0829DF3B2BEC60253196293C6B34D3F75D32F213DD45C6273D505ADF4CCED1057CB758FC26AEEFA441255ED4E64C199EE075E7F16646182FDB464739B68AB5DAFF0E63E9552016824F054BF4D3C8C90A97BB6B6553284EB429FCC", CypherText);//Cypher Text	
	//PrivateKeyD		
	hexstr2bytes("056B04216FE5F354AC77250A4B6B0C8525A85C59B0BD80C56450A22D5F438E596A333AA875E291DD43F48CB88B9D5FC0D499F9FCD1C397F9AFC070CD9E398C8D19E61DB7C7410A6B2675DFBF5D345B804D201ADD502D5CE2DFCB091CE9997BBEBE57306F383E4D588103F036F7E85D1934D152A323E4A8DB451D6F4A5B1B0F102CC150E02FEEE2B88DEA4AD4C1BACCB24D84072D14E1D24A6771F7408EE30564FB86D4393A34BCF0B788501D193303F13A2284B001F0F649EAF79328D4AC5C430AB4414920A9460ED1B7BC40EC653E876D09ABC509AE45B525190116A0C26101848298509C1C3BF3A483E7274054E15E97075036E989F60932807B5257751E79", PrivateKeyD);//PrivateKeyD
	rsa_pub_dec_2048(PrivateKeyD,ModulusN,PlainText,CypherText,256,0);
	hexstr2bytes("009AEFF546462E50BFEC1DC191D5D0CE459069756F33635AD62317FFA3981D2B674ED6E83547E479CA90CEF1EB74CBA8F36004F73B477B159B4FE4F3B5BDA05E51D7C8C674C2B9BD2060C9574E661311F4AD7FFC4C0373F1D987505DE434A32DB898B0D167D188EB9645219D5222EB107A7FAAE431705E1A3DC8F47CD936B96A02D951E997199635E49B523FD01E1D4C00CBD551F395202F771007505E1DD48B7B04A82B892FE728E190B71E6D4128571C9BED19C06123DB3EEA1A4EC645419FC879B98F82B6563B7A2C6280DB9B0434A756502306E0B244459DD012CA7198A6300058121E70917B49F6402EE738A6C60BFEBD3CD130CDFB11392AB73DA9A8CA", ExpectedResult);//RSA_expo 

	if(memcmp(ExpectedResult,PlainText,256) == 0)
		Serial.println("\r\n PASS RSA DECRYPTION TEST");
	else
		Serial.println("\r\n FAIL RSA DECRYPTION TEST");

}

void API_TEST_MAIN()
{
		unsigned char temp ;
		int i = 0;
		int iResult = 0;
		SHA_Test_Main_START:
		
		while(1)
		{
			temp = 'z' ;
	
			Serial.println("\r\n");
			Serial.println("\r\n  *****************************************************");
			Serial.println("\r\n  * 		   API	  TEST MAIN 					 *");
			Serial.println("\r\n  *****************************************************");
			Serial.println("\r\n  * 1. TEST_AES					*");	
			Serial.println("\r\n  * 2. ecdh_gen_pub_key					  		*");
			Serial.println("\r\n  * 3. ecdh_gen_session_key						*");			
			Serial.println("\r\n  * 4. SHA 										*");			
			Serial.println("\r\n  * 5. AES_ARIA_OPERATION_MODE_TEST32			 *");					
			Serial.println("\r\n  * 6. ecdsa_gen_pub_key");
			Serial.println("\r\n  * 7. ecdsa_gen_signature_TEST");
			Serial.println("\r\n  * 8. ecdsa_verify_signature_test");	
			Serial.println("\r\n  * 9. Check sleep mode");	
			Serial.println("\r\n  * a. AES ARIA OPERATION MODE TEST					*");				
			Serial.println("\r\n  * b. rsa_encryption				*");							
			Serial.println("\r\n  * c. rsa_decryption				*");										
			Serial.println("\r\n  -----------------------------------------------------");
			
			Serial.println("\r\n  * m. return to top menu							  *");			
			Serial.println("\r\n");
	
			Serial.println("\r\n");
			Serial.println("\r\n  * Select : ");
	
			while(temp == 'z')
			{
				int HitCnt = 0;
				int MissCnt = 0;
				L_TEMP:
				//while(Serial.available()  == 0 );
				//Serial.println("Looping");
				if(Serial.available() > 0)
					temp = Serial.read();
				else
					goto L_TEMP;
	
				if ( temp != 'z' ) Serial.println( temp);
				Serial.println("\r\n");
				if(temp == 0x0d)
					goto SHA_Test_Main_START;
				if( temp == 'm')
					return;
	
				switch ( temp )
				{
					case 'c':
							Dorca3_CM0_SPI_Init(SPI1_SPEED);
							TEST_RSA_DECRYPT();
							Dorca3_CM0_Close();
							break;
					case 'b':
							Dorca3_CM0_SPI_Init(SPI1_SPEED);
							TEST_RSA_ENCRYPT();
							Dorca3_CM0_Close();
							break;
					case 'a':
							Serial.println("\r\n AES_ARIA_OPERATION_MODE_TEST ");
							Dorca3_SPI_Init(1000*1000);
							AES_ARIA_OPERATION_MODE_TEST();				
							Dorca3_Close();	
						    break;
					case '1':
							Serial.println("\r\n TEST_AES");
							TEST_AES();
							break;
					case '2':
							Serial.println("\r\n ecdh_gen_pub_key TEST");
							Dorca3_CM0_SPI_Init(SPI1_SPEED);
							TEST_ECDH_PUB();
							Dorca3_CM0_Close();
					break;
					case '3':
							Serial.println("\r\n ecdh_gen_pub_key TEST");
							Dorca3_CM0_SPI_Init(SPI1_SPEED);
							TEST_ECDH_SESSION();
							Dorca3_CM0_Close();				
					break;	
					case '4':
							Serial.println("\r\n SHA_TEST_MAIN");
			    			Dorca3_SPI_Init(1000*1000);
		    				SHA_TEST_MAIN();
	    					Dorca3_Close();				
						break;
					case '5':
							Serial.println("\r\n AES_ARIA_OPERATION_MODE_TEST32");
							Dorca3_SPI_Init(1000*1000);;
							AES_ARIA_OPERATION_MODE_TEST32();
							Dorca3_Close();
					break;			
					case '6':
							Serial.println("\r\n ecdsa_gen_pub_key TEST");
							Dorca3_CM0_SPI_Init(SPI1_SPEED);
							ecdsa_gen_public_key_test();
							Dorca3_CM0_Close();
							
						break;

					case '7':
							Serial.println("\r\n ecdsa_gen_signature_TEST TEST");

							Dorca3_CM0_SPI_Init(SPI1_SPEED);
							ecdsa_gen_signature_TEST();
							Dorca3_CM0_Close();
						break;
					case '8':
							Serial.println("\r\n ecdsa_verify_signature_test TEST");
							Dorca3_CM0_SPI_Init(SPI1_SPEED);
							ecdsa_verify_signature_test();
							Dorca3_CM0_Close();
						break;				
					case '9':
							Dorca3_SPI_Init(1000*1000);;
							CheckSleepMode();
							Dorca3_Close();
						break;
				default : temp = 'p'; break;			
				}
	
			}
		}


}

unsigned char ShaBitSize(long long x,unsigned char *bitsize)
{
	int i;
	long long data_size;
	unsigned char hex_size[8];
	data_size = x*8;
	
	hex_size[0] = ((unsigned char) (data_size >> 56)) & 0xff;
	hex_size[1] = ((unsigned char) (data_size >> 48)) & 0xff;
	hex_size[2] = ((unsigned char) (data_size >> 40)) & 0xff;
	hex_size[3] = ((unsigned char) (data_size >> 32)) & 0xff;
	hex_size[4] = ((unsigned char) (data_size >> 24)) & 0xff;
	hex_size[5] = ((unsigned char) (data_size >> 16)) & 0xff;
	hex_size[6] = ((unsigned char) (data_size >>  8)) & 0xff;
	hex_size[7] = ((unsigned char) (data_size >>  0)) & 0xff;
	
	for( i=0; i<8; i++)
	{
		bitsize[i] = hex_size[i];
	}
	return 0;
}
//#define DEBUG_SHA

long long ShaMultiFrameFrame(unsigned char *txdata, long long ByteNo)
{
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	long long i;
	long long j;
	long long temp_cnt = 0; 
	//multi_frame data array
	long long array_no=0, array_cnt=0; 
	unsigned int frame_cnt = 0;
	unsigned char frame_buffer[64];
	tx_data[0] = 2;
	tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x6;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE					, NULL, NULL, NULL, NULL, tx_data, rx_data, 1); 
	tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	

	frame_cnt = (ByteNo/64); // sha operation counter
	
	for( i=0; i<frame_cnt; i++)
	{
		array_cnt = (i+1) * 64;

		for( array_no=0; array_no<64; array_no++)
		{
            temp_cnt = (array_cnt-64) + array_no;
            frame_buffer[array_no] = txdata[temp_cnt];
		}
		#ifdef DEBUG_SHA
		printk("\r\n frame_buffer %d line %d  ShaMultiFrameFrame",gFrameNumber++, __LINE__);
		printbyte(frame_buffer,64);
		#endif
		reversebuffer(tx_data, frame_buffer, 64);
		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
		Delay_us(10);
	}

	return temp_cnt+1;
}


unsigned char ShaSingleFrame(unsigned char *txdata, long long temp_cnt, long long ByteNo, unsigned char frame_type)
{
	int success =  1;
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	int i, j;
	long long last_cnt;
	long long mod55 = 0;
	unsigned char frame_buffer[64] = { 0x00, };
	unsigned char bitsize[8];
	
	last_cnt = ByteNo % 64;			
	ShaBitSize(ByteNo,bitsize);

	
	for( j=0; j<64; j++)
	{
	   frame_buffer[j] = 0x00;
	}

	//last frame input user write last txdata_Bytes
	for( j=0; j<last_cnt; j++)
	{
	  
	  	 frame_buffer[j] = txdata[j]; 
	}
	//txdata last Byte index : write data = 0x80;

	frame_buffer[last_cnt] = 0x80;
				
	if ( last_cnt <= 55 )
	{
	
	tx_data[0] =0;
	tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	tx_data[0] = 0x6;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE 				, NULL, NULL, NULL, NULL, tx_data, rx_data, 1); 
	tx_data[0] = 0x4;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	    for( j=(last_cnt+1); j<64; j++)
	    {
		    frame_buffer[j] = 0x00;
	    }

	    for( j=0; j<8; j++) frame_buffer[j+56] = bitsize[j];

		reversebuffer(tx_data, frame_buffer, 64);
		#ifdef DEBUG_SHA
		printk("\r\n frame_buffer %d line %d ShaSingleFrame <55",gFrameNumber++, __LINE__);
		printbyte(frame_buffer,64);	
		#endif
		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);
    		
	}

	if ( last_cnt >= 56 )
	{
		
		reversebuffer(tx_data, frame_buffer, 64);
		#ifdef DEBUG_SHA
		printk("\r\n frame_buffer %d line %d",gFrameNumber++, __LINE__);
		printbyte(frame_buffer,64);
		#endif
		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
		Delay_us(10);		
		
	    for( j=0; j<64; j++)
	    {
	        frame_buffer[j] = 0x00;
	    }

	    for( j=0; j<8; j++) frame_buffer[j+56] = bitsize[j];
		tx_data[0] = 3;
		tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

		#ifdef DEBUG_SHA
		printk("\r\n frame_buffer %d line %d",gFrameNumber++, __LINE__);

		printk("\r\n frame_buffer %d",gFrameNumber++);
		#endif
		printbyte(frame_buffer,64);		
		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
		Delay_us(10);		
	}



	return 0;
}


unsigned char LastMultiFrame(unsigned char *txdata, long long temp_cnt, long long ByteNo, unsigned char frame_type)
{
	int i, j;
	long long last_cnt;
	long long mod55 = 0;
	unsigned char frame_buffer[64] = { 0x00, };
	unsigned char bitsize[8];
	unsigned char tx_data[64];
	unsigned char rx_data[64];
	
	last_cnt = ByteNo % 64;			
	ShaBitSize(ByteNo,bitsize);

	#ifdef DEBUG_SHA
	printk("\r\n last_cnt %d",last_cnt);
	printk("\r\n temp_cnt %d",temp_cnt);
	#endif

	//last frame input user write last txdata_Bytes
	for( j=0; j<last_cnt; j++)
	{
	  	frame_buffer[j] = txdata[(temp_cnt+j)]; // only single frame operation

	}
	//txdata last Byte index : write data = 0x80;
	frame_buffer[last_cnt] = 0x80;
				



	

	if ( last_cnt <= 55 )
	{
	    for( j=(last_cnt+1); j<64; j++)
	    {
		    frame_buffer[j] = 0x00;
	    }

	    for( j=0; j<8; j++) frame_buffer[j+56] = bitsize[j];


		tx_data[0] = 3;
		tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

		reversebuffer(tx_data, frame_buffer, 64);
		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
		Delay_us(10);		
		#ifdef DEBUG_SHA		
		printk("\r\n frame_buffer %d line %d",gFrameNumber++, __LINE__);
		printbyte(frame_buffer,64);	
		#endif
	}


	if ( last_cnt >= 56 )
	{
		
		reversebuffer(tx_data, frame_buffer, 64);
		#ifdef DEBUG_SHA		
		printk("\r\n frame_buffer %d line %d",gFrameNumber++, __LINE__);

		printbyte(frame_buffer,64);
		#endif
		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
		Delay_us(10);		
		
	    for( j=0; j<64; j++)
	    {
	        frame_buffer[j] = 0x00;
	    }

	    for( j=0; j<8; j++) frame_buffer[j+56] = bitsize[j];
		tx_data[0] = 3;
		tspi_interface(cs, ADDR_NOR_W,RG_SHA_CTRL				   , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);

		reversebuffer(tx_data, frame_buffer, 64);
		#ifdef DEBUG_SHA
		printk("\r\n frame_buffer %d line %d",gFrameNumber++, __LINE__);

		printbyte(frame_buffer,64);		
		#endif
		tspi_interface(cs, ADDR_NOR_W,RG_EEBUF300 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 64);	
		Delay_us(10);		
	}

	return 0;
}


unsigned char STANDARD_SHA_MODE(unsigned char *txdata, unsigned char *rxdata, long long ByteNo)
{
	long long i;
	long long temp_cnt;
	unsigned char frame_type;
	unsigned char tx_data[64];
	unsigned char rx_data[64];

	
	//gene_wake_up();

	if(ByteNo > 55)
	{
		frame_type = 1; // multi-frame set
	}
	else
	{
		frame_type = 0; // single-frame set
	}
	#ifdef DEBUG_SHA
	printk("\r\n ByteNo %d",ByteNo);
	#endif
	if( !frame_type )
	{
		#ifdef DEBUG_SHA
		printk("\r\n SingleFrame");
		#endif
		temp_cnt = 0;		
		ShaSingleFrame(txdata,temp_cnt,ByteNo,frame_type);		
		
	}
	else
	{
		#ifdef DEBUG_SHA
		printk("\r\n MultiFrame");
		#endif
		temp_cnt = ShaMultiFrameFrame(txdata, ByteNo);
		
		//multi frame last single frame make	
		if(temp_cnt == 1)
			temp_cnt = 0;
		LastMultiFrame(txdata,temp_cnt,ByteNo,frame_type);
	}
	
    tspi_interface(cs, ADDR_NOR_R,RG_EEBUF400 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 32);	
    reversebuffer(rxdata,rx_data,32);
    
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST1_STDSPI_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 1;
	tspi_interface(cs, ADDR_NOR_W,RG_ST0_OPMODE 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	tx_data[0] = 0;
	tspi_interface(cs, ADDR_NOR_W,RG_ACCESS 				  , NULL, NULL, NULL, NULL, tx_data, rx_data, 1);	
	endOP();
    
}

void SHA_TEST_MAIN()
{
	unsigned char source[512];
	unsigned char result_hw[32];
	unsigned char result_sw[32];	
	int success = 1;
	int i;
	
	for(i = 0; i < 512; i++)
	{
//	   source[i] = (i+1) % 128;
	source[i] = i+1;


	}
	Serial.println("\r\n SHA_TEST_MAIN");

	for(i = 0; i < 512; i++) {
	gFrameNumber = 0;
	printk("\r\n TEST IDX %d",i+1);
	sha_256_perform(source,result_hw,(long long)i+1);
	MCU_SHA256_EXE(source,result_sw,(unsigned int)i+1);
	
	if(memcmp(result_hw,result_sw,32) == 0)
	 printk("\r\n TEST PASS");
	else {
	 printk("\r\n TEST FAIL");
	 success = 0;
	 }
	
	 printk("\r\nEXPECTED RESULT");
	 printbyte(result_sw,32);
	 printk("\r\n RESULT");
	 printbyte(result_hw,32);
	}
	 
	if(success)
		 Serial.println("\r\nTOTAL TEST PASS");
		else 
		 Serial.println("\r\nTOTAL TEST FAIL");
		 
		

}
void SET_SPI0()
{
	
		unsigned int i;
		unsigned int inst = 0x00;
		unsigned char addr[2] = { 0x06, 0x04};
		unsigned char tx_data[64];
		unsigned char rx_data[64];
	
		for( i=0; i<64; i++)
		{
			tx_data[i] = 0x00;
			rx_data[i] = 0x00;
		}
		SetZero_RG_SLEEP_TIMER();
		printk("\r\n Set RG_AES_CTRL Start"); 
	
		tx_data[0] = 0x00;
		tspi_interface(cs, ADDR_NOR_W, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
		tspi_interface(cs, ADDR_NOR_R, RG_AES_CTRL, NULL, NULL, NULL, NULL, tx_data, rx_data, 1);
	
		printk("\r\n Set RG_ST0_OPMODE Start"); 
	
		endOP();	
		printk("\r\n SET SPI 0");

}

int SPEED = 3;
unsigned char SPI_SPEED_SET(void)
{
	unsigned char temp = 0;
	while(1)
	{
		printk("\r\n\n");
		printk("\r\n  *****************************************************");
		printk("\r\n  *                 SPI_SPEED_SET                     *");
		printk("\r\n  *****************************************************");
		printk("\r\n  * 0. 1.9MHz                                           *");
		printk("\r\n  * 1. 3.9MHz                                           *");
		printk("\r\n  * 2. 7.8MHz                                           *");
		printk("\r\n  * 3. 15.6MHz                                           *");
		printk("\r\n  * 4. 31.25MHz                                           *");
		printk("\r\n  * 5. 62.5MHz                                           *");
		printk("\r\n  * m return to top menu                                          *");	

		printk("\r\n  *****************************************************");
		{
				if(SPEED == 0)
					printk("\r\n  Current Speed. 1.9MHz                                           *");
				if(SPEED == 1)
					printk("\r\n  Current Speed. 3.9MHz                                           *");
				if(SPEED == 2)
					printk("\r\n  Current Speed. 7.8MHz                                           *");
				if(SPEED == 3)
					printk("\r\n  Current Speed. 15.6MHz                                           *");
				if(SPEED == 4)
					printk("\r\n  Current Speed. 32.2MHz                                           *");
				if(SPEED == 5)
					printk("\r\n  Current Speed. 62.5MHz                                           *");

		}
		printk("\r\n");
		printk("\r\n  * Select : ");


		temp = 'z' ;

		while(temp == 'z')
		{
			temp = _uart_get_char();
			if(temp == 0x0d)
				break;
			if(temp != 'z') printk("%c\n", temp);
			
			switch(temp)
			{
			case '0' : Dorca3_Close();Dorca3_SPI_Init(0);SPEED = 0; break ;
			case '1' : Dorca3_Close();Dorca3_SPI_Init(1);SPEED = 1; break ;
			case '2' : Dorca3_Close();Dorca3_SPI_Init(2);SPEED = 2; break ;
			case '3' : Dorca3_Close();Dorca3_SPI_Init(3);SPEED = 3; break ;
			case '4' : Dorca3_Close();Dorca3_SPI_Init(4);SPEED = 4; break ;
			case '5' : Dorca3_Close();Dorca3_SPI_Init(5);SPEED = 5; break ;			
			}
			if(temp == 'm')
				return 0;
		}

	}   
	return 0;
}

