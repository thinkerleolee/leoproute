//
// Created by leo on 17-11-15.
//

#ifndef LEOPING_ICMPTOOL_H
#define LEOPING_ICMPTOOL_H

#include <zconf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdint>
#include <ctime>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <cstring>
#include <cstdio>
#include <sys/time.h>

const int IP_HEADER_LEN = 20;
const int ICMP_HEADER_LEN = 8;
const int ICMP_DATA_LEN = 4;
const int ICMP_LEN = ICMP_DATA_LEN + ICMP_HEADER_LEN;

//ping程序中需要用到的ICMP报文类型
enum ICMPTYPE {
    ECHO_REPY = 0,
    DESTINATION_UNREACHABLE = 3,
    ECHO_REQUEST = 8,
};

// IPv4 首部
typedef struct ip_header {
//判断大小端端机，网络协议规定接收到得第一个字节是高字节，存放到低地址，所以发送时会首先去低地址取数据的高字节。
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		//头部长度(header length)(4 bits)
    unsigned int ip_v:4;		//IP版本(version)(4 bits)
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		//头部长度(header length)(4 bits)
    unsigned int ip_hl:4;		//IP版本(version)(4 bits)
#endif
    u_char tos;            // 服务类型(Type of service)
    u_short tlen;           // 总长(Total length)
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char ttl;            // 存活时间(Time to live)
    u_char proto;          // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    uint32_t saddr;      // 源地址(Source address)
    uint32_t daddr;      // 目的地址(Destination address)
    u_int op_pad;         // 选项与填充(Option + Padding)
} ip_header;


//ICMP
typedef struct icmp_pac {
    u_int8_t type = 0;        //类型(8 bits)
    u_int8_t code = 0;        //代码(8 bits)
    u_int16_t checksum = 0;   //检验和(16 bits)
    u_int16_t identifier = 0; //标志符号(16 bits) 通常是进程ID
    u_int16_t seq_number = 0; //序号(16 bits)
    u_int32_t data = 0;      //自定义数据(32 bits) 这里存时间戳
} icmp_pac;

//ICMP工具类
class IcmpTool {
public:
    //对IP包解码，得出ICMP包
    bool DecodeIcmpV4(char *rcvbuf, int length, sockaddr_in *from, icmp_pac& icmpp, u_int32_t &msecond);

    //充填IPV4版本ICMP包数据
    void FillIcmpRquestV4(icmp_pac *icmpp, int seq);

    uint32_t GetTickCount();

private:
    //得到校验码
    u_int16_t Checksum(int len, u_int16_t * data);


};


#endif //LEOPING_ICMPTOOL_H
