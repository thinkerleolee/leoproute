//
// Created by leo on 17-11-15.
//

#include "Ping.h"
#include <csignal>

Ping pi;

void sig_int(int){
    pi.sig_int();
    return;
};

int main(int argc, char** argv) {
    signal(SIGINT, sig_int);
    pi.SetSock(argv[1]);
    pi.ReceiveLoop();
}