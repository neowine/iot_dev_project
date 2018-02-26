#ifndef __DORCA_20_H__
#define __DORCA_20_H__
void spi_read (int fd,int inst, int addr, int nbytes, unsigned char *rx_data);
void spi_write(int fd,int inst, int addr, int nbytes, char *value);

#endif //__DORCA_20_H__
