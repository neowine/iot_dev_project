#ifndef __DORCA_20_H__
#define __DORCA_20_H__
void read_data_arm7(unsigned char *tx_buffer,unsigned char *rx_buffer, int size);
void send_data_arm7(unsigned char *buffer,int size);
void Dorca3_SPI_Init( int com_speed );
void Dorca3_Close();
void Dorca3_CM0_Close();
char*  Dorca3_CM0_SPI_Init( int com_speed );

void spi_read (int fd,int inst, int addr, int nbytes, unsigned char *rx_data);
void spi_write(int fd,int inst, int addr, int nbytes, unsigned char *value);


#endif //__DORCA_20_H__
