//
// Created by leo on 17-11-19.
//

#ifndef LEOPING_IPTOOL_H
#define LEOPING_IPTOOL_H


#include <zconf.h>
#include <cstdint>

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

class IpTool {

};


#endif //LEOPING_IPTOOL_H
