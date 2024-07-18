#include "stdio.h"
#include "main.h"
#include "coap.h"

#define IP "101.133.196.110"
#define PORT 5682

extern CoAP_CB Auth_CB;
extern CoAP_CB Data_CB;

extern unsigned char CoAPpack[1024];
extern int CoAPpack_len;

int sockfd;
struct sockaddr_in ser_addr, cli_addr;

double TEMP = -40.0;
double HUMI = 10.0;

void sys_err(const char *str)
{
    perror(str);
    exit(1);
}

int main(int argc, char *argv[])
{
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        sys_err("socket");

    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = inet_addr(IP);
    ser_addr.sin_port = htons(PORT);
    iot_Parameter_Init();
    iot_CoAP_Auth(COAP_MESSAGE_TYPE_CON, COAP_MESSAGE_CODE_POST, &Auth_CB); // 初始化认证报文
    COAPSend_Auth(CoAPpack, CoAPpack_len);
    while (1)
    {
        memset(Data_CB.payload, 0, 1024);
        sprintf(Data_CB.payload, "{\"method\":\"thing.event.property.post\",\"id\":\"102271531\",\"params\":{\"CurrentHumidity\":%.1f,\"CurrentTemperature\":%.1f},\"version\":\"1.0.0\"}", HUMI += 0.5, TEMP += 0.5);
        printf("%s\r\n", Data_CB.payload);
        iot_CoAP_Data(COAP_MESSAGE_TYPE_CON, COAP_MESSAGE_CODE_POST, &Data_CB);
        COAPSend_Data(CoAPpack, CoAPpack_len);
        sleep(5);
    }

    //    COAPSend_Data(CoAPpack, CoAPpack_len);
    // while (1)
    // {

    //     sleep(5);
    // }

    return 0;
}

char data_temp1[2048]; // 处理数据时，需要用的缓冲区
char data_temp2[2048]; // 处理数据时，需要用的缓冲区
unsigned int RxCounter;
#define RXBUFF_SIZE 1024
char RxBuff[RXBUFF_SIZE];
/*-------------------------------------------------*/
/*函数名：coAP发送认证数据 包                      */
/*参  数：data:需要发送的数据                      */
/*参  数：data_len:需要发送的数据位数              */
/*返回值：0：正确   其他：错误                     */
int COAPSend_Auth(unsigned char *data, int data_len)
{
    int sendnum = 0;
    int recvnum = 0;

    unsigned char buffer[1024] = {0};
    // Hex_to_Str((char *)data, data_len, data_temp1, 2048);
    memset(RxBuff, 0, RXBUFF_SIZE);
    sendnum = sendto(sockfd, data, data_len, 0, (struct sockaddr *)&ser_addr, sizeof(ser_addr));
    printf("sendnum = %d\r\n", sendnum);
    printf("data_len = %d\r\n", data_len);
    if (sendnum == -1)
    {
        printf("Error sending\r\n");
        return -1;
    }
    if (sendnum == data_len)
    {
        socklen_t len = sizeof(cli_addr);
        recvnum = recvfrom(sockfd, RxBuff, RXBUFF_SIZE, 0, (struct sockaddr *)&cli_addr, &len);
        printf("recvnum = %d\r\n", recvnum);
        if (recvnum == -1 || recvnum < 5)
        {
            printf("Error reading\r\n");
            return -1;
        }
        if (recvnum > 0)
        {
            int ret = Return_code_judgment(RxBuff[1]);
            if (ret == -1)
            {
                printf("读取后的数据错误\r\n");
                return -1;
            }
            else if (ret)
            {
                distill_data(RxBuff, recvnum); // 提取数据放入结构体
            }
        }
    }
}

/*
    @brief 将接收到的数据进行提取，分别提取出random，seqOffset，token的值
    @param buffer:接收到的数组
    @param 接收到的数据长度
 */
void distill_data(char *buffer, int len)
{
    char *str = NULL;
    char random_temp[64] = {0};
    int seqoffset_temp = 0;
    char token_temp[64] = {0};
    unsigned char key_temp[100] = {0};
    unsigned char sha256out[32] = {0};
    str = strstr(&buffer[5], "{\"random\"");
    if (str != NULL)
    {
        printf("服务器发来的数据:\r\n%s\r\n", &buffer[5]);
        sscanf(str, "{\"random\":\"%[^\"]\",\"seqOffset\":%d,\"token\":\"%[^\"]\"}", random_temp, &seqoffset_temp, token_temp);
        memcpy(Data_CB.auth_random, random_temp, strlen(random_temp)); // 拷贝random
        memcpy(Data_CB.auth_token, token_temp, strlen(token_temp));    // 拷贝token
        Data_CB.Initial_seq = seqoffset_temp;
        printf("random:%s\r\n", Data_CB.auth_random);
        printf("seqOffset:%d\r\n", Data_CB.Initial_seq);
        printf("token:%s\r\n", Data_CB.auth_token);
        // 制作2089加密时的第一个明文
        sprintf((char *)key_temp, "%s,%s", DEVICESECRET, Data_CB.auth_random);
        utils_sha256(key_temp, strlen((char *)key_temp), sha256out); // 对此明文进行sha256加密
        memcpy(Data_CB.auth_key, &sha256out[8], 16);                 // 提取中间16字节作为秘钥
        printf("秘钥:");
        for (int i = 0; i < 16; i++)
            printf("%02x", Data_CB.auth_key[i]); //
        printf("\r\n");
    }
}

int COAPSend_Data(unsigned char *data, int data_len)
{
    int sendnum = 0;
    int recvnum = 0;
    char temp[17] = {0};
    char temp1[17] = {0};
    printf("准备发送温湿度数据包... ...\r\n");
    sendnum = sendto(sockfd, data, data_len, 0, (struct sockaddr *)&ser_addr, sizeof(ser_addr));
    printf("sendnum: %d\r\n", sendnum);
    printf("data_len: %d\r\n", data_len);

    if (sendnum == -1)
    {
        printf("Error sending\r\n");
        return -1;
    }
    if (sendnum == data_len)
    {
        memset(RxBuff, 0, RXBUFF_SIZE);
        socklen_t len = sizeof(cli_addr);
        recvnum = recvfrom(sockfd, RxBuff, RXBUFF_SIZE, 0, (struct sockaddr *)&cli_addr, &len);
        printf("recvnum = %d\r\n", recvnum);

        if (recvnum == -1 || recvnum < 5)
        {
            printf("Error reading\r\n");
            return -1;
        }

        if (recvnum > 0)
        {
            int ret = Return_code_judgment(RxBuff[1]);
            if (ret == -1)
            {
                printf("读取后的数据错误\r\n");
                return -1;
            }
            if (ret)
            {
                memcpy(temp, RxBuff + 7, 8);
                temp[8] = '\0';
                stringToHex(temp, temp1, 8);
                printf("转换结果：%s\n", temp1);
                removeSpaces(temp1);
                printf("\r\n");
            }
        }
    }
}

unsigned long long Hex_to_Decimal(char *hex_num)
{
    unsigned long long decimal_num;
    sscanf(hex_num, "%llx", &decimal_num);
    printf("MessageID:%llu", decimal_num);
    return decimal_num;
}
// 删除字符串中的空格
void removeSpaces(char *str)
{
    int i, j;
    for (i = 0, j = 0; str[i]; i++)
    {
        if (str[i] != ' ')
        {
            str[j++] = str[i];
        }
    }
    str[j++] = '\0';
    Hex_to_Decimal(str);
}

void stringToHex(const char *str, char *hexStr, size_t maxLength)
{
    size_t count = 0; // 计数器，用于限制输出的长度
    while (*str && count < maxLength)
    {
        sprintf(hexStr, "%s%02X ", hexStr, (unsigned char)*str);
        str++;
        count++;
        //       hexStr += 3; // 移动到下一个位置，留出空格的位置
    }
    // 如果还有剩余的位置，填充 00
    while (count < maxLength)
    {
        sprintf(hexStr, "%s00 ", hexStr);
        count++;
    }
}

/*********************************************************************************************/

void HexToNum(char str[])
{
    /**********  Begin  **********/
    int i = 0, j = 0, num = 0, len = 0;
    unsigned long long sum = 0;
    // int len = strlen(str);//这种方法会将非16进制数记录在内
    while ((str[i] >= 'a' && str[i] <= 'f') || (str[i] >= 'A' && str[i] <= 'F') || (str[i] >= '0' && str[i] <= '9'))
    {
        len++;
        i++;
    } // 遍历数组记录16进制数的个数，非16进制数不计在内
    i = 0;
    while (str[i] != '\0')
    {
        // 字符转数字
        if (str[i] >= '0' && str[i] <= '9')
            num = str[i] - '0';
        else if (str[i] >= 'a' && str[i] <= 'f')
            num = str[i] - 'a' + 10;
        else if (str[i] >= 'A' && str[i] <= 'F')
            num = str[i] - 'A' + 10;
        else
            break; // 遇到'\0'之前的第一个非十六进制数就停止循环
        for (j = 0; j < len - 1; j++)
        {
            num = num * 16;
        }
        sum += num;
        i++;
        len--; // 每读取一位就使长度-1
    }
    printf("%llu\n", sum);
    /**********  End  **********/
}

// 删除字符串中的 "FFFFFF"
void removeFFFFFF(char *str)
{
    char *pos;

    while ((pos = strstr(str, "FFFFFF")) != NULL)
    {
        memmove(pos, pos + 6, strlen(pos + 6) + 1);
        //        printf("str: %s\n", str);
    }
}

/*********************************************************************************************/