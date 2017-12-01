//
// Created by leo on 17-11-15.
//

#include <iostream>
#include "IcmpTool.h"



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
