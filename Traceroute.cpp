//
// Created by root on 17-11-21.
//

#include "Traceroute.h"

void Traceroute::SetSock(const char *hostOrIp)
{
    start_time = IcmpTool::GetTickCount();

    //解析地址参数,DNS解析
    if (SolveAddrV4(hostOrIp, &remote_host) == false)
    {
        perror("Domain name resolution failed");
        exit(-1);
    }

    //设置目的IP地址
    string ip(inet_ntoa(*(struct in_addr *)remote_host->h_addr_list[0]));

    //建立数据报套接字
    sendfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sendfd < 0)
    {
        perror("CREATE SOCKET ERROR");
        exit(-2);
    }

    //设置超时
    struct timeval timeout = {2, 0};
    if (setsockopt(sendfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval)) < 0)
    {
        perror("SET TIMEOUT ERROR");
        shutdown(sendfd, SHUT_RDWR);
        exit(-2);
    }
    if (setsockopt(sendfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval)) < 0)
    {

        perror("SET TIMEOUT ERROR");
        shutdown(sendfd, SHUT_RDWR);
        exit(-2);
    }

    //msockaddr置为零
    bzero(&msockaddr, sizeof(msockaddr));
    msockaddr.sin_family = AF_INET;
    msockaddr.sin_addr.s_addr = inet_addr(ip.c_str());
    u_int16_t source_port = (getpid() & 0xffff) | 0x8000;
    msockaddr.sin_port = htons(source_port);

    //建立RAW套接字
    recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recvfd < 0)
    {
        perror("CREATE SOCKET ERROR");
        exit(-2);
    }

    //设置超时
    if (setsockopt(recvfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval)) < 0)
    {
        perror("SET TIMEOUT ERROR");
        shutdown(sendfd, SHUT_RDWR);
        exit(-2);
    }
    if (setsockopt(recvfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval)) < 0)
    {
        perror("SET TIMEOUT ERROR");
        shutdown(sendfd, SHUT_RDWR);
        exit(-2);
    }
    setuid(getuid());
    cout << "Traceroute " << remote_host->h_name << " (" << ip << ")"
         << " max_ttl = " << MAX_TTL << endl;
}

void Traceroute::RecvLoop()
{
    int seq = 0;
    for (int ttl = 1; ttl <= MAX_TTL; ttl++)
    {
        cout << ttl << " ";
        setsockopt(sendfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
        for (int probe = 0, succ = 0; probe < SEND_TIMES && succ <= 0; probe++)
        {
            memset(recv_buff, 0, 8);
            udp_data *sd = (udp_data *)send_buff;
            sd->rec_seq = ++seq;
            sd->rec_ttl = ttl;
            sd->rec_tv = IcmpTool::GetTickCount();
            if (sendto(sendfd, send_buff, 8, 0, (sockaddr *)&msockaddr, sizeof(struct sockaddr)) < 0)
            {
                perror("SEND ERROR");
            }
            else
            {
                //当前时间
                u_int32_t msecond;
                while (1)
                {
                    int bytesnum = 0;
                    char addr[INET_ADDRSTRLEN];
                    sockaddr_in recvaddr;
                    int n = sizeof(recvaddr);
                    int res = recvfrom(recvfd, recv_buff, 1024, 0, reinterpret_cast<struct sockaddr *>(&recvaddr),
                                       reinterpret_cast<socklen_t *>(&n));
                    if (res < 0)
                    {
                        cout << " *";
                        break;
                    }
                    else
                    {
                        ip_header ih;
                        //得出ＩＰ头部
                        memcpy((char *)&ih, recv_buff, IP_HEADER_LEN_NO_OPTION + ICMP_LEN);

                        //IP header length
                        int ip_header_len = ih.ip_hl;
                        icmp_pac_timeout ip;

                        //解析ICMP报文
                        int de = DecodeIcmpPkg(recv_buff, ICMP_LEN + ip_header_len * 4, &recvaddr, ip,
                                               msecond);
                        //解析失败
                        if (de == false)
                        {
                            msecond = 0;
                            break;
                        }
                        else if (ip.type == ICMPTYPE::ICMP_TIMEOUT)
                        { //正常应答
                            bytesnum = sizeof(ip.data);
                            inet_ntop(AF_INET, &recvaddr.sin_addr, addr, sizeof(addr));
                            cout << bytesnum << " bytes from " << addr << " ttl=" << static_cast<u_short>(ih.ttl);
                            ++succ;
                            break;
                        }
                        else if (ip.type == ICMPTYPE::DESTINATION_UNREACHABLE)
                        {
                            inet_ntop(AF_INET, &recvaddr.sin_addr, addr, sizeof(addr));
                            cout << "gateway: " << addr << endl;
                            ++succ;
                            return;
                        }
                    }
                }
            }
        }
        cout << endl;
    }
}

bool Traceroute::DecodeIcmpPkg(char *rcvbuf, int length, sockaddr_in *from, icmp_pac_timeout &icmpp,
                               u_int32_t &msecond)
{
    //检验数据长度
    if (length < ICMP_LEN + IP_HEADER_LEN_NO_OPTION)
    {
        printf("Too few databytes from:%s", inet_ntoa(from->sin_addr));
        return false;
    }
    int ip_len = ((ip_header *)rcvbuf)->ip_hl * 4;
    //得出ICMP头部
    icmp_header *picmp_header = (icmp_header *)(rcvbuf + ip_len);

    //选择数据包类型

    //当类型为timeout时/
    if (picmp_header->type == ICMPTYPE::ICMP_TIMEOUT || picmp_header->type == ICMPTYPE::DESTINATION_UNREACHABLE)
    {
        icmp_pac_timeout *picmp_to = (icmp_pac_timeout *)(rcvbuf + ip_len);
        //填充/
        icmpp.type = picmp_to->type;
        icmpp.code = picmp_to->code;
        icmpp.checksum = picmp_to->checksum;
        icmpp.unuse = picmp_to->unuse;
        icmpp.data = picmp_to->data;
        msecond = IcmpTool::GetTickCount();
        return true;
    }
    return false;
}
