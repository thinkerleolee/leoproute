//
// Created by leo on 17-11-15.
//

#include <iostream>
#include "IcmpTool.h"

bool IcmpTool::DecodeIcmpV4(char *rcvbuf, int length, sockaddr_in *from, icmp_pac &icmpp,u_int32_t &msecond) {
    //检验数据长度
    if(length < ICMP_LEN + IP_HEADER_LEN){
        printf("Too few databytes from:%s", inet_ntoa(from->sin_addr));
        return false;
    }

    icmp_pac *picmp = (icmp_pac*)(rcvbuf+IP_HEADER_LEN);
    //检验进程
    if(picmp->identifier != getpid()){
        return false;
    }

    //充填数据
    icmpp.type = picmp->type;
    icmpp.code =  picmp->code;
    icmpp.checksum =  picmp->checksum;
    icmpp.identifier =  picmp->identifier;
    icmpp.seq_number =  picmp->seq_number;
    icmpp.data = picmp->data;
    msecond = GetTickCount();
}

void IcmpTool::FillIcmpRquestV4(icmp_pac *icmpp, int seq) {
    //充填数据
    icmpp->type = ICMPTYPE::ECHO_REQUEST;
    icmpp->code = 0;
    icmpp->identifier = getpid();
    icmpp->data = GetTickCount();
    icmpp->seq_number = seq;
    //checksum清零
    icmpp->checksum = 0;
    icmpp->checksum = Checksum(ICMP_LEN, (u_int16_t*)icmpp);
}

u_int16_t IcmpTool::Checksum(int len, u_int16_t *data) {
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

u_int32_t IcmpTool::GetTickCount() {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
