//
// Created by leo on 17-11-15.
//

#ifndef LEOPING_ICMPTOOL_H
#define LEOPING_ICMPTOOL_H

#include <sys/time.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <zconf.h>

#include <cstdint>
#include <ctime>
#include <cstring>
#include <cstdio>
#include <netdb.h>

//byte
const int IP_HEADER_LEN_NO_OPTION = 20;
const int ICMP_HEADER_LEN = 8;
const int ICMP_DATA_LEN = 4;
const int ICMP_LEN = ICMP_DATA_LEN + ICMP_HEADER_LEN;
const int UDP_HEADER_LEN = 8;

//ping程序中需要用到的ICMP报文类型
enum ICMPTYPE
{
    ECHO_REPLY = 0,
    DESTINATION_UNREACHABLE = 3,
    ECHO_REQUEST = 8,
    ICMP_TIMEOUT = 11
};

// IPv4 首部
typedef struct ip_header
{
//判断大小端端机，网络协议规定接收到得第一个字节是高字节，存放到低地址，所以发送时会首先去低地址取数据的高字节。
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl : 4; //头部长度(header length)(4 bits)
    unsigned int ip_v : 4;  //IP版本(version)(4 bits)
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v : 4;  //头部长度(header length)(4 bits)
    unsigned int ip_hl : 4; //IP版本(version)(4 bits)
#endif
    u_char tos;             // 服务类型(Type of service)
    u_short tlen;           // 总长(Total length)
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char ttl;             // 存活时间(Time to live)
    u_char proto;           // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    uint32_t saddr;         // 源地址(Source address)
    uint32_t daddr;         // 目的地址(Destination address)
    u_int op_pad;           // 选项与填充(Option + Padding)
} ip_header;

typedef struct udp_header
{
    u_int16_t uh_sport;     // source port
    u_int16_t uh_dport;     // destination port
    u_int16_t uh_ulen;      // udp length
    u_int16_t uh_sum;       // udp checksum
} udp_header;

//自定义UDP数据(32 bits);
typedef struct udp_data
{
    u_short rec_seq;
    u_short rec_ttl;
    u_int32_t rec_tv;
} udp_data;

//TODO
//ICMP往返时间计算

//ICMP头部
typedef struct icmp_header
{
    u_int8_t type = 0;      //类型(8 bits)
    u_int8_t code = 0;      //代码(8 bits)
    u_int16_t checksum = 0; //检验和(16 bits)
} icmp_header;

//request&&reply报文
typedef struct icmp_pac_request_reply
{
    u_int8_t type = 0;        //类型(8 bits)
    u_int8_t code = 0;        //代码(8 bits)
    u_int16_t checksum = 0;   //检验和(16 bits)
    u_int16_t identifier = 0; //标志符号(16 bits) 通常是进程ID
    u_int16_t seq_number = 0; //序号(16 bits)
    u_int32_t data = 0;       //自定义数据(32 bits),echo_reply
} icmp_pac_request_reply;

//ICMP timeout报文
typedef struct icmp_pac_timeout
{
    u_int8_t type = 0;      //类型(8 bits)
    u_int8_t code = 0;      //代码(8 bits)
    u_int16_t checksum = 0; //检验和(16 bits)
    u_int32_t unuse = 0;
    u_int32_t data = 0; //自定义数据(32 bits);
} icmp_pac_timeout;

using namespace std;

//ICMP工具类
class IcmpTool
{
  public:
    //虚函数,生成套接字
    virtual void SetSock(const char *){};

    //虚函数,主循环体
    virtual void RecvLoop(){};

    //中断函数
    virtual void sig_int(){};

    //析构函数
    virtual ~IcmpTool(){};

  protected:
    //对ICMP包解码
    virtual bool DecodeIcmpPkg(char *rcvbuf, int length, sockaddr_in *from, icmp_pac_request_reply &icmpp, u_int32_t &msecond){};
    virtual bool DecodeIcmpPkg(char *rcvbuf, int length, sockaddr_in *from, icmp_pac_timeout &icmpp, u_int32_t &msecond){};

    //解析IPv4地址或域名
    bool SolveAddrV4(const char *hostOrIp, struct hostent **remote_host);

    //得出微妙级时间
    static u_int32_t GetTickCount()
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    }

    //校验和算法
    static u_int16_t Checksum(int len, u_int16_t *data)
    {
        u_int32_t sum = 0;

        while (len > 1)
        {
            sum += *data++;
            len -= sizeof(u_int16_t);
        }
        if (len == 1)
        {
            u_int16_t tmp = *data;
            tmp &= 0xff00;
            sum += tmp;
        }
        sum = (sum >> 16) + (sum & 0x0000ffff);
        sum += sum >> 16;

        return ~sum;
    }
};

#endif //LEOPING_ICMPTOOL_H
