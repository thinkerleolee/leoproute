//
// Created by leo on 17-11-15.
//

#include "Ping.h"

void Ping::SetSock(const char *hostOrIp)
{
    start_time = IcmpTool::GetTickCount();

    //解析地址参数
    if (!SolveAddrV4(hostOrIp, &remote_host))
    {
        perror("Domain name resolution failed");
        exit(-1);
    }
    cout << remote_host->h_addr_list[0];
    //设置目的IP地址
    string ip(inet_ntoa(*(struct in_addr *)remote_host->h_addr_list[0]));
    bzero(&msockaddr, sizeof(sockaddr));

    //ip地址转换网络字节序
    if ((inet_pton(AF_INET, ip.c_str(), &msockaddr.sin_addr)) < 0)
    {
        perror("TRANS IPADDR ERROR");
        exit(-1);
    }
    msockaddr.sin_family = AF_INET;

    //TODO
    //YIBUTAOJIEZI
    //建立socket文件,建立
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
    {
        perror("CREATE SOCKET ERROR");
        exit(-2);
    }

    //回收root权限,设置为当前用户
    setuid(getuid());

    //扩大套接字接收缓冲区到50K这样做主要为了减小接收缓冲区溢出的
    //的可能性,若无意中ping一个广播地址或多播地址,将会引来大量应答
    int size = 60 * 1024;
    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) <0){
        perror("SET TIMEOUT ERROR");
        shutdown(sockfd, SHUT_RDWR);
        exit(-2);
    }

    //设置超时
    struct timeval timeout = {2, 0};
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval)) < 0)
    {
        perror("SET TIMEOUT ERROR");
        shutdown(sockfd, SHUT_RDWR);
        exit(-2);
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval)) < 0)
    {
        perror("SET TIMEOUT ERROR");
        shutdown(sockfd, SHUT_RDWR);
        exit(-2);
    }
    cout << "Ping " << remote_host->h_name << " (" << ip << ")" << ICMP_DATA_LEN
         << " bytes of data" << endl;
    //格式：PING www.a.shifen.com (61.135.169.125) 56(84) bytes of data.
}

void Ping::RecvLoop()
{
    sockaddr_in recvaddr;
    int n = sizeof(recvaddr);
    int bytesnum = 0;
    int seq = 0;
    char addr[INET_ADDRSTRLEN];
    memset(send_buff, 0, ICMP_LEN);
    memset(recv_buff, 0, 1024);
    //当前时间
    u_int32_t msecond;
    while (1)
    {
        SendIcmp(++send_pak_num);
        while (1)
        {
            int res = recvfrom(sockfd, recv_buff, 1024, 0, reinterpret_cast<struct sockaddr *>(&recvaddr),
                               reinterpret_cast<socklen_t *>(&n));
            if (res == 0)
            {
                perror("Remote host closed");
                exit(-5);
            }
            if (res < 0)
            {
                switch (errno)
                {
                case EWOULDBLOCK || errno == EAGAIN:
                {
                    perror("Request timed out");
                    break;
                }
                case ECONNREFUSED:
                {
                    perror("Remote host refused");
                    break;
                }
                default:
                {
                    break;
                }
                };
                break;
            }

            ip_header ih;
            //得出ＩＰ头部
            memcpy((char *)&ih, recv_buff, IP_HEADER_LEN_NO_OPTION + ICMP_LEN);

            //IP header length
            int ip_header_len = ih.ip_hl;
            icmp_pac_request_reply ip;

            //解析ICMP报文
            int de = DecodeIcmpPkg(recv_buff, ICMP_LEN + ip_header_len * 4, &recvaddr, ip,
                                   msecond);
            //解析失败
            if (de == false)
            {
                msecond = 0;
                break;
            }
            else if (ip.type == ICMPTYPE::DESTINATION_UNREACHABLE)
            { //目的地址不可达报文
                cout << "From " << addr << ": icmp_seq=" << seq << " Destination unreachable" << endl;
                break;
            }
            else if (ip.type == ICMPTYPE::ECHO_REPLY)
            { //正常应答
                bytesnum = ICMP_DATA_LEN;
                seq = ip.seq_number;
                inet_ntop(AF_INET, &recvaddr.sin_addr, addr, sizeof(addr));
                ++recv_pag_num;
                cout << bytesnum << " bytes from " << addr << ": icmp_seq=" << seq << " ttl=" << static_cast<u_short>(ih.ttl) << " time=" << msecond - ip.data << " ms" << endl;
                //FORMAT: 64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.027 ms
                break;
            }
        }
        sleep(1);
    }
}

void Ping::SendIcmp(int seq)
{
    //TODO
    memset(send_buff, 0, ICMP_LEN);
    FillIcmpPkg(*reinterpret_cast<icmp_pac_request_reply *>(&send_buff), seq);
    if ((sendto(sockfd, send_buff, ICMP_LEN, 0, (struct sockaddr *)&msockaddr, sizeof(sockaddr))) <= 0)
    {
        perror("Cannot send data");
        shutdown(sockfd, SHUT_RDWR);
        exit(-3);
    }
}

void Ping::sig_int()
{
    int_time = IcmpTool::GetTickCount();
    cout << "--- " << remote_host->h_name << " ping statistics ---" << endl;
    cout << send_pak_num << " packets transmitted, " << recv_pag_num << " received," << (1.0 - static_cast<float>(recv_pag_num) / static_cast<float>(send_pak_num)) * 100 << "% packet loss"
                                                                                                                                                                             " time:"
         << int_time - start_time << " ms" << endl;
    shutdown(sockfd, SHUT_RDWR);
    exit(0);
    //rtt min/avg/max/mdev = 26.739/27.789/28.227/0.637 ms
}

void Ping::FillIcmpPkg(icmp_pac_request_reply &icmpp, int seq)
{
    //充填数据
    icmpp.type = ICMPTYPE::ECHO_REQUEST;
    icmpp.code = 0;
    icmpp.identifier = getpid();
    icmpp.data = IcmpTool::GetTickCount();
    icmpp.seq_number = seq;
    //checksum清零
    icmpp.checksum = 0;
    icmpp.checksum = IcmpTool::Checksum(ICMP_LEN, (u_int16_t *)&icmpp);
}

bool Ping::DecodeIcmpPkg(char *rcvbuf, int length, sockaddr_in *from, icmp_pac_request_reply &icmpp, u_int32_t &msecond)
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

    //当类型为reply或者request时/
    if (picmp_header->type == ICMPTYPE::ECHO_REPLY || picmp_header->type == ICMPTYPE::ECHO_REQUEST)
    {

        icmp_pac_request_reply *picmp_rr = (icmp_pac_request_reply *)(rcvbuf + ip_len);
        //检验进程
        if (picmp_rr->identifier != getpid())
        {
            return false;
        }
        //填充/
        icmpp.type = picmp_rr->type;
        icmpp.code = picmp_rr->code;
        icmpp.checksum = picmp_rr->checksum;
        icmpp.identifier = picmp_rr->identifier;
        icmpp.seq_number = picmp_rr->seq_number;
        icmpp.data = picmp_rr->data;
        msecond = IcmpTool::GetTickCount();
        return true;
    }
    return false;
}
