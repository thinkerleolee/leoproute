//
// Created by leo on 17-11-15.
//

#ifndef LEOPING_PING_H
#define LEOPING_PING_H

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

const u_int32_t TIME_OUT = 2000;

using namespace std;

class Ping : public IcmpTool
{
  private:
    int sockfd;
    char send_buff[ICMP_LEN];
    char recv_buff[1024];
    struct sockaddr_in msockaddr;
    struct hostent *remote_host;
    //程序开始时间
    u_long start_time;
    //程序中断结束时间
    u_long int_time;
    //发包数
    int send_pak_num = 0;
    //接包数
    int recv_pag_num = 0;

    //发送ICMP包
    void SendIcmp(int seq);

    //解析ICMP报文
    bool DecodeIcmpPkg(char *rcvbuf, int length, sockaddr_in *from, icmp_pac_request_reply &icmpp,
                       u_int32_t &msecond);

    //装填ICMP报文
    void FillIcmpPkg(icmp_pac_request_reply &icmpp, int seq);
public:
    //初始化socket
    void SetSock(const char *hostOrIp);

    //接收数据循环
    void RecvLoop();

    //中断函数
    void sig_int();

    //析构函数
    ~Ping(){
        delete(send_buff);
        delete(recv_buff);
        shutdown(sockfd, SHUT_RDWR);
    }
};

#endif //LEOPING_PING_H
