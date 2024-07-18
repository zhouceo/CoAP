#ifndef __MAIN_H_
#define __MAIN_H_

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <pthread.h>
#include <string.h>
#include "stdlib.h"
#include <unistd.h>

// void Hex_to_Str(char *data, int data_len, char *out, int out_len);
int COAPSend_Auth(unsigned char *data, int data_len);
void distill_data(char *buffer, int len);
int COAPSend_Data(unsigned char *data, int data_len);
long long unsigned int Hex_to_Decimal(char *hex_num);
void removeFFFFFF(char *str);
void stringToHex(const char *str, char *hexStr, size_t maxLength);
void HexToNum(char str[]);
void removeSpaces(char *str);

#endif