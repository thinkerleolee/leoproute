//
// Created by leo on 17-11-15.
//

#include <iostream>
#include "IcmpTool.h"

bool IcmpTool::SolveAddrV4(const char *hostOrIp, struct hostent **remote_host)
{
    //TODO
    //Should use more advanced funcctions(support IPv6)
    if (hostOrIp == NULL)
    {
        return false;
    }
    if ((*remote_host = gethostbyname(hostOrIp)) != NULL)
    {
        return true;
    }
    in_addr ina;
    ina.s_addr = inet_addr(hostOrIp); //获取主机信息
    if (ina.s_addr == INADDR_NONE)
    {
        return false;
    }
    if ((*remote_host = gethostbyaddr((char *)ina.s_addr, 4, AF_INET)) != NULL)
    {
        return true;
    }
    return false;
}
