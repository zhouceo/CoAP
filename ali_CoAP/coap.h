#ifndef __COAP_H_
#define __COAP_H_

#include "utils_sha256.h"
#include "utils_aes.h"
#include "utils_hmac.h"
#include "utils_md5.h"
#include "utils_sha1.h"

#define PRODUCTKEY "i4ijMN8DVcv"
#define DEVICENAME "d0001"
#define DEVICESECRET "6644e84ebd0be6a018df6a24e80c0cf8"
#define DEVICESECRET_LEN strlen(DEVICESECRET)
#define TOPIC_PATH1 "topic\0"
#define TOPIC_PATH2 "sys\0"
#define TOPIC_PATH3 "i4ijMN8DVcv\0"
#define TOPIC_PATH4 "d0001\0"
#define TOPIC_PATH5 "thing\0"
#define TOPIC_PATH6 "event\0"
#define TOPIC_PATH7 "property\0"
#define TOPIC_PATH8 "post\0"
#define TOPIC_PATH_NUM 8

#define CONTENT 2.05                    // 0x45 正确请求
#define BAD_REQUEST 4.00                // 0x80 请求发送的Payload非法。
#define UNAUTHORIZED 4.01               // 0x81 未授权的请求。
#define FORBIDDEN 4.03                  // 0x83 禁止的请求。
#define NOT_FOUND 4.04                  // 0x84 请求的路径不存在。
#define METHOD_NOT_ALLOWED 4.05         // 0x85 请求方法不是指定值。
#define NOT_ACCEPTABLE 4.06             // 0x86 Accept不是指定的类型。
#define UNSUPPORTED_CONTENT_FORMAT 4.15 // 0x8F 请求的content不是指定类型。
#define INTERNAL_SERVER_ERROR 5.00      // 0xA0 auth服务器超时或错误。

typedef struct // CoAP控制块
{
    char path[128];               // url路径    POST
    char host[128];               // 主机名
    int port;                     // 端口号
    unsigned char Accept;         // 接收类型     仅支持application/json和application/cbor两种格式
    unsigned char Content_Format; // 内容格式类型 仅支持application/json和application/cbor两种格式
    int Initial_seq;              // 认证成功后，服务器下发的初始seq值
    char auth_random[64];         // 服务器下发的一个随机数，用于后续上报数据加密
    char auth_token[64];          // 服务器下发的认证信息，每次post数据，需要携带认证信息，否则上报数据认为是非法数据
    unsigned char auth_key[16];   // 根据服务器下发的random和设备秘钥计算出来的，共后续的AES加密使用
    char payload[1024];           // 需要上报的数据
} CoAP_CB;

enum
{
    COAP_MESSAGE_TYPE_CON,
    COAP_MESSAGE_TYPE_NON,
    COAP_MESSAGE_TYPE_ACK,
    COAP_MESSAGE_TYPE_RST
};

enum
{
    COAP_MESSAGE_CODE_GET = 0x01,
    COAP_MESSAGE_CODE_POST,
    COAP_MESSAGE_CODE_PUT,
    COAP_MESSAGE_CODE_DEL
};

void iot_Parameter_Init(void);
void iot_CoAP_Auth(unsigned char T, unsigned char Code, CoAP_CB *coap_cb);
void iot_CoAP_Data(unsigned char T, unsigned char Code, CoAP_CB *coap_cb);
double hexToDecimal(int hexValue);
int Return_code_judgment(int hexValue);

#endif