#include "coap.h"

unsigned char ClientID[128];            // 客户端ID的缓冲区
unsigned char Password[128];            // 密码的缓冲区
unsigned char ServerIP[128];            // 服务器IP或是域名的缓冲区
unsigned char Certification[400];       // 发给服务器的认证信息的缓冲区
unsigned char CoAPpack[1024];           // 需要发送的coap协议包数据
int CoAPpack_len;                       // 需要发送的coap协议包数据长度
int ServerPort;                         // 服务器的端口号
unsigned short int Message_ID = 0x0001; // CoAP协议ID从1开始
unsigned char msg[1500];                // AES加密时的明文

AES_CTX AEScontext; // AES加密时结构体
CoAP_CB Auth_CB;    // CoAP认证控制块
CoAP_CB Data_CB;    // CoAP数据控制块

char Data_Path[TOPIC_PATH_NUM][32] = {
    // 上报数据时的Path
    TOPIC_PATH1,
    TOPIC_PATH2,
    TOPIC_PATH3,
    TOPIC_PATH4,
    TOPIC_PATH5,
    TOPIC_PATH6,
    TOPIC_PATH7,
    TOPIC_PATH8,
};
const unsigned char AESiv[16] = {0x35, 0x34, 0x33, 0x79, 0x68, 0x6A, 0x79, 0x39, 0x37, 0x61, 0x65, 0x37, 0x66, 0x79, 0x66, 0x67}; // AES加密时的初始向量

// 初始化参数，得到客户端ID，用户名和密码
void iot_Parameter_Init(void)
{
    unsigned char temp[256];
    // 构造payload中clientid
    memset(ClientID, 0, sizeof(ClientID));
    sprintf((char *)ClientID, "%s&%s", PRODUCTKEY, DEVICENAME); // 设备认证时payload中的clientId
    // 构造payload中sign字段值
    memset(temp, 0, sizeof(temp));
    memset(Password, 0, sizeof(Password));
    sprintf((char *)temp, "clientId%sdeviceName%sproductKey%sseq1", ClientID, DEVICENAME, PRODUCTKEY);
    utils_hmac_md5((char *)temp, strlen((char *)temp), (char *)Password, DEVICESECRET, DEVICESECRET_LEN); // 对上面字符串进行hmacmd5加密,将加密结果放入Password
    // 构造域名和端口号
    memset(ServerIP, 0, sizeof(ServerIP));
    sprintf((char *)ServerIP, "%s.coap.cn-shanghai.link.aliyuncs.com", PRODUCTKEY);
    ServerPort = 5682;
    // 构造认证设备的payload
    sprintf((char *)Certification, "{\"productKey\":\"%s\",\"deviceName\":\"%s\",\"clientId\":\"%s\",\"sign\":\"%s\", \"seq\":\"1\"}", PRODUCTKEY, DEVICENAME, ClientID, Password);
    printf("服 务 器: %s:%d\r\n", ServerIP, ServerPort);
    printf("认证信息: %s\r\n", Certification);

    memset(&Auth_CB, 0, sizeof(CoAP_CB));
    sprintf(Auth_CB.path, "auth");
    sprintf(Auth_CB.host, "%s", ServerIP);
    Auth_CB.port = ServerPort;
    Auth_CB.Accept = 0x32;
    Auth_CB.Content_Format = 0x32;
    sprintf(Auth_CB.payload, "%s", Certification);

    memset(&Data_CB, 0, sizeof(CoAP_CB));
    sprintf(Data_CB.host, "%s", ServerIP);
    Data_CB.port = ServerPort;
    Data_CB.Accept = 0x32;
    Data_CB.Content_Format = 0x32;
}

/*
    函数功能：构造认证信息的报文
    参数：T:报文类型   CON报文，NON报文，ACK报文和RST报文
        Code:功能码   GET、POST、PUT和DELETE
        coap_cb:CoAP控制块
    返回值：无
*/
void iot_CoAP_Auth(unsigned char T, unsigned char Code, CoAP_CB *coap_cb)
{
    memset(CoAPpack, 0, 1024);
    unsigned char CoAP_head[4] = {0};
    unsigned char Host_Option[128] = {0};
    unsigned char Port_Option[3] = {0};
    unsigned char Path_Option[128] = {0};
    unsigned char Accept_Option[2] = {0};
    unsigned char Content_Option[2] = {0};
    unsigned char Payload[256] = {0};
    int Host_Option_len = 0; // Host字段最终长度
    int Path_Option_len = 0;
    int Payload_len = 0;
    CoAP_head[0] = 0x40 | T;
    CoAP_head[1] = Code;
    CoAP_head[2] = Message_ID / 256;
    CoAP_head[3] = Message_ID % 256;
    Message_ID++;
    // Host字段
    memset(Host_Option, 0, sizeof(Host_Option));
    if (strlen(coap_cb->host) <= 12)
    {
        Host_Option[0] = 0x30 | strlen(coap_cb->host);
        memcpy(&Host_Option[1], coap_cb->host, strlen(coap_cb->host));
        Host_Option_len = strlen(coap_cb->host) + 1;
    }
    else if (strlen(coap_cb->host) > 12 && strlen(coap_cb->host) <= 268) // 扩展一个字节
    {
        Host_Option[0] = 0x3D;
        Host_Option[1] = strlen(coap_cb->host) - 13;
        memcpy(&Host_Option[2], coap_cb->host, strlen(coap_cb->host));
        Host_Option_len = strlen(coap_cb->host) + 2;
    }
    else if (strlen(coap_cb->host) > 268) // 扩展两个字节
    {
        Host_Option[0] = 0x3E;
        Host_Option[1] = (strlen(coap_cb->host) - 14 - 255) / 256;
        Host_Option[2] = (strlen(coap_cb->host) - 14 - 255) % 256;
        memcpy(&Host_Option[3], coap_cb->host, strlen(coap_cb->host));
        Host_Option_len = strlen(coap_cb->host) + 3;
    }
    // Port字段
    Port_Option[0] = 0x42;
    Port_Option[1] = (coap_cb->port) / 256;
    Port_Option[1] = (coap_cb->port) % 256;
    // Post字段
    memset(Path_Option, 0, sizeof(Path_Option));
    if (strlen(coap_cb->path) <= 12)
    {
        Path_Option[0] = 0x40 | strlen(coap_cb->path);
        memcpy(&Path_Option[1], coap_cb->path, strlen(coap_cb->path));
        Path_Option_len = strlen(coap_cb->path) + 1;
    }
    else if (strlen(coap_cb->path) > 12 && strlen(coap_cb->path) <= 268) // 扩展一个字节
    {
        Path_Option[0] = 0x4D;
        Path_Option[1] = strlen(coap_cb->path) - 13;
        memcpy(&Path_Option[2], coap_cb->path, strlen(coap_cb->path));
        Path_Option_len = strlen(coap_cb->path) + 2;
    }
    else if (strlen(coap_cb->path) > 268) // 扩展两个字节
    {
        Path_Option[0] = 0x4E;
        Path_Option[1] = (strlen(coap_cb->path) - 14 - 255) / 256;
        Path_Option[2] = (strlen(coap_cb->path) - 14 - 255) % 256;
        memcpy(&Path_Option[3], coap_cb->path, strlen(coap_cb->path));
        Path_Option_len = strlen(coap_cb->path) + 3;
    }
    // Content-Format字段
    Content_Option[0] = 0x11;
    Content_Option[1] = 0x32;
    // Accept字段
    Accept_Option[0] = 0x51;
    Accept_Option[1] = 0x32;
    // payload字段
    memset(Payload, 0, sizeof(Payload));
    Payload[0] = 0xFF;
    memcpy(&Payload[1], coap_cb->payload, strlen(coap_cb->payload));
    Payload_len = strlen(coap_cb->payload) + 1;

    memset(CoAPpack, 0, sizeof(CoAPpack));
    memcpy(&CoAPpack[0], CoAP_head, 4);                                                         // 头
    memcpy(&CoAPpack[4], Host_Option, Host_Option_len);                                         // Host
    memcpy(&CoAPpack[4 + Host_Option_len], Port_Option, 3);                                     // Port
    memcpy(&CoAPpack[4 + Host_Option_len + 3], Path_Option, Path_Option_len);                   // POST
    memcpy(&CoAPpack[4 + Host_Option_len + 3 + Path_Option_len], Content_Option, 2);            // Content-Format
    memcpy(&CoAPpack[4 + Host_Option_len + 3 + Path_Option_len + 2], Accept_Option, 2);         // Accept
    memcpy(&CoAPpack[4 + Host_Option_len + 3 + Path_Option_len + 2 + 2], Payload, Payload_len); // Payload
    CoAPpack_len = 4 + Host_Option_len + 3 + Path_Option_len + 2 + 2 + Payload_len;             // 最终报文长度

    printf("CoAP认证数据报文如下:\r\n");
    for (int i = 0; i < CoAPpack_len; i++)
        printf("%02X ", CoAPpack[i]);
    printf("\r\n\r\n");
}

/*
    函数功能：构造上报数据报文
    参数：T:报文类型   CON报文，NON报文，ACK报文和RST报文
        Code:功能码   GET、POST、PUT和DELETE
        coap_cb:CoAP控制块
    返回值：无
*/
void iot_CoAP_Data(unsigned char T, unsigned char Code, CoAP_CB *coap_cb)
{
    memset(CoAPpack, 0, 1024);
    unsigned char CoAP_head[4] = {0};
    unsigned char Host_Option[128] = {0};
    unsigned char Port_Option[3] = {0};
    unsigned char Path_Option[128] = {0};
    unsigned char Accept_Option[2] = {0};
    unsigned char Content_Option[2] = {0};
    unsigned char CustomOptions2088[35] = {0};
    unsigned char CustomOptions2089[18] = {0};
    unsigned char Payload[1024] = {0};
    int Host_Option_Len = 0;
    int Path_Option_len = 0;
    int Payload_len = 0;
    int CustomOptions2088_Len = 0;
    int temp_len = 0;

    CoAP_head[0] = 0x40 | T;
    CoAP_head[1] = Code;
    CoAP_head[2] = Message_ID / 256;
    CoAP_head[3] = Message_ID % 256;
    Message_ID++;
    // Host
    memset(Host_Option, 0, sizeof(Host_Option));
    if (strlen(coap_cb->host) <= 12)
    {
        Host_Option[0] = 0x30 | strlen(coap_cb->host);
        memcpy(&Host_Option[1], coap_cb->host, strlen(coap_cb->host));
        Host_Option_Len = strlen(coap_cb->host) + 1;
    }
    else if ((strlen(coap_cb->host) > 12) && (strlen(coap_cb->host) <= 268))
    {
        Host_Option[0] = 0x3D;
        Host_Option[1] = strlen(coap_cb->host) - 13;
        memcpy(&Host_Option[2], coap_cb->host, strlen(coap_cb->host));
        Host_Option_Len = strlen(coap_cb->host) + 2;
    }
    else if (strlen(coap_cb->host) > 268)
    {
        Host_Option[0] = 0x3E;
        Host_Option[1] = (strlen(coap_cb->host) - 14 - 255) / 256;
        Host_Option[2] = (strlen(coap_cb->host) - 14 - 255) % 256;
        memcpy(&Host_Option[3], coap_cb->host, strlen(coap_cb->host));
        Host_Option_Len = strlen(coap_cb->host) + 3;
    }
    // Port
    Port_Option[0] = 0x42;
    Port_Option[1] = coap_cb->port / 256;
    Port_Option[2] = coap_cb->port % 256;
    // POST
    memset(Path_Option, 0, sizeof(Path_Option));
    for (int i = 0; i < TOPIC_PATH_NUM; i++)
    {
        if (strlen(Data_Path[i]) <= 12)
        {
            Path_Option[Path_Option_len] = 0x00 | strlen(Data_Path[i]);
            memcpy(&Path_Option[1 + Path_Option_len], Data_Path[i], strlen(Data_Path[i]));
            Path_Option_len += strlen(Data_Path[i]) + 1;
        }
        else if (strlen(Data_Path[i]) > 12 && strlen(Data_Path[i]) <= 268)
        {
            Path_Option[Path_Option_len] = 0x0D;
            Path_Option[Path_Option_len + 1] = strlen(Data_Path[i]) - 13;
            memcpy(&Path_Option[Path_Option_len + 2], Data_Path[i], strlen(Data_Path[i]));
            Path_Option_len += strlen(Data_Path[i]) + 2;
        }
        else if (strlen(Data_Path[i]) > 268)
        {
            Path_Option[Path_Option_len] = 0x0E;
            Path_Option[Path_Option_len + 1] = (strlen(Data_Path[i]) - 14 - 255) / 256;
            Path_Option[Path_Option_len + 2] = (strlen(Data_Path[i]) - 14 - 255) % 256;
            memcpy(&Path_Option[Path_Option_len + 3], Data_Path[i], strlen(Data_Path[i]));
            Path_Option_len += strlen(Data_Path[i]) + 3;
        }
    }
    Path_Option[0] |= 0x40;
    // Content-Format
    Content_Option[0] = 0x11;
    Content_Option[1] = 0x32;
    // Accept
    Accept_Option[0] = 0x51;
    Accept_Option[1] = 0x32;
    // CustomOptions2088
    CustomOptions2088[0] = 0xED;
    CustomOptions2088[1] = 0x07;
    CustomOptions2088[2] = 0x0A;
    CustomOptions2088[3] = 0x12;
    memcpy(&CustomOptions2088[4], coap_cb->auth_token, strlen(coap_cb->auth_token));
    CustomOptions2088_Len = strlen(coap_cb->auth_token) + 4;
    // CustomOptions2089
    CustomOptions2089[0] = 0x1D;
    CustomOptions2089[1] = 0x03;
    memset(msg, 0, sizeof(msg));
    sprintf((char *)msg, "%d", ++(coap_cb->Initial_seq));
    temp_len = strlen((char *)msg);
    if (temp_len % 16 != 0)
    {
        for (int i = 0; i < ((temp_len / 16) + 1) * 16; i++)
        {
            if (msg[i] == 0x00)
            {
                msg[i] = 16 - temp_len % 16;
            }
        }
        temp_len = ((temp_len / 16) + 1) * 16;
    }
    AES_set_key(&AEScontext, coap_cb->auth_key, AESiv, AES_MODE_128); // 初始化AES加密
    AES_cbc_encrypt(&AEScontext, msg, &CustomOptions2089[2], 16);     // AES加密，结果存放到CustomOptions2089[2]开始的位置。共计16字节
    // payload
    memset(Payload, 0, sizeof(Payload));
    Payload[0] = 0xFF;
    memset(msg, 0, sizeof(msg));
    sprintf((char *)msg, "%s", coap_cb->payload);
    temp_len = strlen((char *)msg);
    if ((temp_len % 16 != 0))
    {
        for (int i = 0; i < ((temp_len / 16) + 1) * 16; i++)
        {
            if (msg[i] == 0x00)
            {
                msg[i] = 16 - temp_len % 16;
            }
        }
        temp_len = ((temp_len / 16) + 1) * 16;
    }
    AES_set_key(&AEScontext, coap_cb->auth_key, AESiv, AES_MODE_128); // 初始化AES加密
    AES_cbc_encrypt(&AEScontext, msg, &Payload[1], temp_len);         // AES加密，结果存放到Payload[1]开始的位置。
    Payload_len = temp_len + 1;

    memset(CoAPpack, 0, 1024);
    memcpy(&CoAPpack[0], CoAP_head, 4);
    memcpy(&CoAPpack[4], Host_Option, Host_Option_Len);
    memcpy(&CoAPpack[4 + Host_Option_Len], Port_Option, 3);
    memcpy(&CoAPpack[4 + Host_Option_Len + 3], Path_Option, Path_Option_len);
    memcpy(&CoAPpack[4 + Host_Option_Len + 3 + Path_Option_len], Content_Option, 2);
    memcpy(&CoAPpack[4 + Host_Option_Len + 3 + Path_Option_len + 2], Accept_Option, 2);
    memcpy(&CoAPpack[4 + Host_Option_Len + 3 + Path_Option_len + 2 + 2], CustomOptions2088, CustomOptions2088_Len);
    memcpy(&CoAPpack[4 + Host_Option_Len + 3 + Path_Option_len + 2 + 2 + CustomOptions2088_Len], CustomOptions2089, 18);
    memcpy(&CoAPpack[4 + Host_Option_Len + 3 + Path_Option_len + 2 + 2 + CustomOptions2088_Len + 18], Payload, Payload_len);
    CoAPpack_len = 4 + Host_Option_Len + 3 + Path_Option_len + 2 + 2 + CustomOptions2088_Len + 18 + Payload_len;

    printf("CoAP数据包如下:\r\n");
    for (int i = 0; i < CoAPpack_len; i++)
        printf("%02X ", CoAPpack[i]);
    //    printf("CoAPpack_len = %d", CoAPpack_len);
    printf("\r\n\r\n");
}

// 认证数据发送后服务器返回的返回码判断，第二个字节
int Return_code_judgment(int hexValue)
{
    if (hexToDecimal(hexValue) == CONTENT)
    {
        printf("正确请求\r\n");
        return 1;
    }
    if (hexToDecimal(hexValue) == BAD_REQUEST)
    {
        printf("请求发送的Payload非法\r\n");
        return -1;
    }
    if (hexToDecimal(hexValue) == UNAUTHORIZED)
    {
        printf("未授权的请求\r\n");
        return -1;
    }
    if (hexToDecimal(hexValue) == FORBIDDEN)
    {
        printf("禁止的请求\r\n");
        return -1;
    }
    if (hexToDecimal(hexValue) == NOT_FOUND)
    {
        printf("请求的路径不存在\r\n");
        return -1;
    }
    if (hexToDecimal(hexValue) == METHOD_NOT_ALLOWED)
    {
        printf("请求方法不是指定值\r\n");
        return -1;
    }
    if (hexToDecimal(hexValue) == NOT_ACCEPTABLE)
    {
        printf("Accept不是指定的类型\r\n");
        return -1;
    }
    if (hexToDecimal(hexValue) == UNSUPPORTED_CONTENT_FORMAT)
    {
        printf("请求的content不是指定类型\r\n");
        return -1;
    }
    if (hexToDecimal(hexValue) == INTERNAL_SERVER_ERROR)
    {
        printf("auth服务器超时或错误\r\n");
        return -1;
    }
}

// 一个16进制，前三位表示整数，后5位表示小数，合并后得出小数值
double hexToDecimal(int hexValue)
{
    // 提取整数部分和小数部分
    int integerPart = (hexValue >> 5) & 0x07; // 取前三位
    int fractionalPart = hexValue & 0x1F;     // 取后五位

    // 计算小数部分的值（将后五位转换为小数）
    double decimalFraction = (double)fractionalPart / 100.0;

    // 计算最终的小数值
    double result = integerPart + decimalFraction;

    return result;
}