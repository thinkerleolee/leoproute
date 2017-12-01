//
// Created by leo on 17-11-15.
//

#ifndef LEOPING_ICMPTOOL_H
#define LEOPING_ICMPTOOL_H

#include <sys/time.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <zconf.h>

#include <cstdint>
#include <ctime>
#include <cstring>
#include <cstdio>

//byte
const int IP_HEADER_LEN_NO_OPTION = 20;
const int ICMP_HEADER_LEN = 8;
const int ICMP_DATA_LEN = 4;
const int ICMP_LEN = ICMP_DATA_LEN + ICMP_HEADER_LEN;
const int UDP_HEADER_LEN = 8;

//ping程序中需要用到的ICMP报文类型
enum ICMPTYPE {
    ECHO_REPLY = 0,
    DESTINATION_UNREACHABLE = 3,
    ECHO_REQUEST = 8,
    ICMP_TIMEOUT = 11
};

// IPv4 首部
typedef struct ip_header {
//判断大小端端机，网络协议规定接收到得第一个字节是高字节，存放到低地址，所以发送时会首先去低地址取数据的高字节。
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;        //头部长度(header length)(4 bits)
    unsigned int ip_v:4;        //IP版本(version)(4 bits)
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

//TODO
//统一ICMP报文格式
//ICMP解码结果

typedef struct icmp_header {
    u_int8_t type = 0;        //类型(8 bits)
    u_int8_t code = 0;        //代码(8 bits)
    u_int16_t checksum = 0;   //检验和(16 bits)
} icmp_header;


//request&&reply报文
typedef struct icmp_pac_request_reply {
    u_int8_t type = 0;        //类型(8 bits)
    u_int8_t code = 0;        //代码(8 bits)
    u_int16_t checksum = 0;   //检验和(16 bits)
    u_int16_t identifier = 0; //标志符号(16 bits) 通常是进程ID
    u_int16_t seq_number = 0; //序号(16 bits)
    u_int32_t data = 0;      //自定义数据(32 bits),echo_reply
} icmp_pac_request_reply;

//timeout报文
typedef struct icmp_pac_timeout {
    u_int8_t type = 0;        //类型(8 bits)
    u_int8_t code = 0;        //代码(8 bits)
    u_int16_t checksum = 0;   //检验和(16 bits)
    u_int32_t unuse = 0;       //未用字段
    u_int16_t identifier = 0; //标志符号(16 bits) 通常是进程ID
    u_int16_t seq_number = 0; //序号(16 bits)
    u_int32_t ip_header_and_raw_icmp_header_8bytes = 0;      //自定义数据(32 bits);

} icmp_pac_timeout;

//ICMP工具类
class IcmpTool {
public:
    //对ICMP包解码，得出ICMP包
    template<typename T>
    bool DecodeIcmpPing(char *rcvbuf, int length, sockaddr_in *from, T &icmpp, u_int32_t &msecond);

    //充填ICMP包数据
    template<typename T>
    void FillIcmpRquest(T &icmpp, int seq);

    //得出微妙级时间
    uint32_t GetTickCount();

private:
    //得到校验码
    u_int16_t Checksum(int len, u_int16_t *data);

};

template<typename T>
bool IcmpTool::DecodeIcmpPing(char *rcvbuf, int length, sockaddr_in *from, T &icmpp, u_int32_t &msecond) {
    //检验数据长度
    if (length < ICMP_LEN + IP_HEADER_LEN_NO_OPTION) {
        printf("Too few databytes from:%s", inet_ntoa(from->sin_addr));
        return false;
    }

    int ip_len = ((ip_header *)rcvbuf)->ip_hl * 4;
    //得出ICMP头部
    icmp_header *picmp_header = (icmp_header *) (rcvbuf + ip_len);

    //选择数据包类型

    //当类型为reply或者request时/
    if(picmp_header->type == ICMPTYPE::ECHO_REPLY || picmp_header->type == ICMPTYPE::ECHO_REQUEST){

        icmp_pac_request_reply *picmp_rr = (icmp_pac_request_reply *) (rcvbuf + ip_len);
        //检验进程
        if (picmp_rr->identifier != getpid()) {
            return false;
        }
        //填充/
        icmpp.type = picmp_rr->type;
        icmpp.code = picmp_rr->code;
        icmpp.checksum = picmp_rr->checksum;
        icmpp.identifier = picmp_rr->identifier;
        icmpp.seq_number = picmp_rr->seq_number;
        icmpp.data = picmp_rr->data;
        msecond = GetTickCount();

        //当类型为timeout时/
    }else if(picmp_header->type == ICMPTYPE::ICMP_TIMEOUT){
        //TODO
        //解析TIMEOUT超时报文

        //得出原始ICMP数据报中的前8字节
        ip_header *ip_ttout = (ip_header *) (rcvbuf + ip_len + ICMP_HEADER_LEN + ip_len + UDP_HEADER_LEN);

        //

    }
}

template<typename T>
void IcmpTool::FillIcmpRquest(T &icmpp, int seq) {
    //充填数据
    icmpp.type = ICMPTYPE::ECHO_REQUEST;
    icmpp.code = 0;
    icmpp.identifier = getpid();
    icmpp.data = GetTickCount();
    icmpp.seq_number = seq;
    //checksum清零
    icmpp.checksum = 0;
    icmpp.checksum = Checksum(ICMP_LEN, (u_int16_t *) &icmpp);
}


#endif //LEOPING_ICMPTOOL_H
