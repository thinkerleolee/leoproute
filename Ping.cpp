//
// Created by leo on 17-11-15.
//

#include "Ping.h"

int Ping::SetSock(const char *hostOrIp) {
    start_time = it.GetTickCount();
    //欢迎界面
    WelCome();

    //解析地址参数
    if (SolveAddrV4(hostOrIp) == false) {
        cout << "Domain name resolution failed" << endl;
        Usage();
        exit(-1);
    }

    //设置目的IP地址
    string ip(inet_ntoa(*(struct in_addr *) remote_host->h_addr_list[0]));
    bzero(&msockaddr, sizeof(sockaddr));

    //ip地址转换网络字节序
    if ((inet_pton(AF_INET, ip.c_str(), &msockaddr.sin_addr)) < 0) {
        cerr << "TRANS IPADDR ERROR" << endl;
        exit(-1);
    }
    msockaddr.sin_family = AF_INET;

    //TODO
    //YIBUTAOJIEZI
    //建立socket文件,建立
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        cerr << "CREATE SOCKET ERROR" << endl;
        exit(-2);
    }

    //回收root权限,设置为当前用户
    setuid(getuid());

    //扩大套接字接收缓冲区到50K这样做主要为了减小接收缓冲区溢出的
    //的可能性,若无意中ping一个广播地址或多播地址,将会引来大量应答
    int size = 60 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    //设置超时
    struct timeval timeout = {2, 0};
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(struct timeval)) < 0) {
        cerr << "SET TIMEOUT ERROR" << endl;
        shutdown(sockfd, SHUT_RDWR);
        exit(-2);
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(struct timeval)) < 0) {
        cerr << "SET TIMEOUT ERROR" << endl;
        shutdown(sockfd, SHUT_RDWR);
        exit(-2);
    }
    cout << "Ping " << remote_host->h_name << " (" << ip << ")" << ICMP_DATA_LEN
         << " bytes of data" << endl;
    //格式：PING www.a.shifen.com (61.135.169.125) 56(84) bytes of data.
}

void Ping::ReceiveLoop() {
    sockaddr_in recvaddr;
    int n = sizeof(recvaddr);
    int bytesnum = 0;
    int seq = 0;
    char addr[INET_ADDRSTRLEN];
    memset(send_buff, 0, ICMP_LEN);
    memset(recv_buff, 0, 1024);
    //当前时间
    u_int32_t msecond;
    while (1) {
        SendIcmp(++send_pak_num);
        while (1) {
            int res = recvfrom(sockfd, recv_buff, 1024, 0, reinterpret_cast<struct sockaddr *>(&recvaddr),
                               reinterpret_cast<socklen_t *>(&n));
            if(res == 0){
                cout << "Remote host closed" << endl;
                exit(-5);
            }
            if (res < 0) {
                switch (errno){
                    case EWOULDBLOCK || errno == EAGAIN:{
                        cerr << "Request timed out." << endl;
                        break;
                    }
                    case ECONNREFUSED:{
                        cerr << "Remote host refused" << endl;
                        break;
                    }
                    default:{
                        break;
                    }
                };
                break;
            }

            ip_header ih;
            //得出ＩＰ头部
            memcpy((char *) &ih, recv_buff, IP_HEADER_LEN_NO_OPTION + ICMP_LEN);

            //IP header length
            int ip_header_len = ih.ip_hl;
            icmp_pac_request_reply ip;

            //解析ICMP报文
            int de = it.DecodeIcmpPing<icmp_pac_request_reply>(recv_buff, ICMP_LEN + ip_header_len * 4, &recvaddr, ip, msecond);
            //解析失败
            if (de == false) {
                msecond = 0;
                break;
            } else if (ip.type == ICMPTYPE::DESTINATION_UNREACHABLE) {  //目的地址不可达报文
                cout << "From " << addr << ": icmp_seq=" << seq << " Destination unreachable" << endl;
                break;
            } else if (ip.type == ICMPTYPE::ECHO_REPLY) {                  //正常应答
                bytesnum = ICMP_DATA_LEN;
                seq = ip.seq_number;
                inet_ntop(AF_INET, &recvaddr.sin_addr, addr, sizeof(addr));
                ++recv_pag_num;
                cout << bytesnum << " bytes from " << addr << ": icmp_seq=" << seq << " ttl=" <<
                     static_cast<u_short >(ih.ttl) << " time=" << msecond - ip.data << " ms" << endl;
                //FORMAT: 64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.027 ms
                break;
            }
        }
        sleep(1);
    }
}

bool Ping::SolveAddrV4(const char *hostOrIp) {
    //TODO
    //Should use more advanced funcctions(support IPv6)
    if (hostOrIp == NULL) {
        return false;
    }
    if ((remote_host = gethostbyname(hostOrIp)) != NULL) {
        return true;
    }
    in_addr ina;
    ina.s_addr = inet_addr(hostOrIp); //获取主机信息
    if (ina.s_addr == INADDR_NONE) {
        return false;
    }
    if ((remote_host = gethostbyaddr((char *) ina.s_addr, 4, AF_INET)) != NULL) {
        return true;
    }
    return false;
}

void Ping::SendIcmp(int seq) {
    //TODO
    memset(send_buff, 0, ICMP_LEN);
    it.FillIcmpRquest(*reinterpret_cast<icmp_pac_request_reply*>(&send_buff), seq);
    if ((sendto(sockfd, send_buff, ICMP_LEN, 0, (struct sockaddr *) &msockaddr, sizeof(sockaddr))) <= 0) {
        cerr << "Cannot send data" << endl;
        shutdown(sockfd, SHUT_RDWR);
        exit(-3);
    }
}

void Ping::WelCome() {
    cout << "**************************************************************" << endl;
    cout << "**************************************************************" << endl;
    cout << "**             **        ********    *********              **" << endl;
    cout << "**             **        ********    *********              **" << endl;
    cout << "**             **        **          **     **              **" << endl;
    cout << "**             **        ********    **     **              **" << endl;
    cout << "**             **        ********    **     **              **" << endl;
    cout << "**             **        **          **     **              **" << endl;
    cout << "**             ********  ********    *********              **" << endl;
    cout << "**             ********  ********    *********              **" << endl;
    cout << "**************************************************************" << endl;
    cout << "**************************************************************" << endl;
    cout << endl;


}

void Ping::sig_int() {
    int_time = it.GetTickCount();
    cout << "--- " << remote_host->h_name << " ping statistics ---" << endl;
    cout << send_pak_num << " packets transmitted, " << recv_pag_num << " received," <<
         (1.0 - static_cast<float>(recv_pag_num) / static_cast<float>(send_pak_num)) * 100 << "% packet loss"
                 " time:" << int_time - start_time << " ms" << endl;
    shutdown(sockfd, SHUT_RDWR);
    exit(0);
    //rtt min/avg/max/mdev = 26.739/27.789/28.227/0.637 ms
}
