//
// Created by root on 17-11-21.
//

#ifndef LEOPING_TRACEROUTE_H
#define LEOPING_TRACEROUTE_H

#include <vector>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <memory.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <iostream>
#include <netdb.h>
#include <ctime>
#include "IcmpTool.h"

const int MAX_TTL = 30;
const int SEND_TIMES = 3;

using namespace std;

class Traceroute : public IcmpTool
{
  public:
    void SetSock(const char *hostOrIp);
    void RecvLoop();

  private:
    int sendfd;
    int recvfd;
    char send_buff[8];
    char recv_buff[1024];
    //程序开始时间
    u_long start_time;
    //程序中断结束时间
    u_long int_time;
    struct sockaddr_in msockaddr;
    struct hostent *remote_host;

    //发包数
    int send_pak_num = 0;
    //接包数
    int recv_pag_num = 0;

    //解析主机信息
    bool SolveAddrV4(const char *hostOrIp);

    bool DecodeIcmpPkg(char *rcvbuf, int length, sockaddr_in *from, icmp_pac_timeout &icmpp,
                       u_int32_t &msecond);
};

#endif //LEOPING_TRACEROUTE_H
