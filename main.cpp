//
// Created by leo on 17-11-15.
//

#include "Ping.h"
#include "Traceroute.h"
#include <csignal>

IcmpTool *pi = new Ping;
IcmpTool *tr = new Traceroute;

void sig_int(int)
{
    pi->sig_int();
    return;
};

void WelCome()
{
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


void Usage()
{
    cout << "USAGE:" << endl;
    cout << "leoproute <type> <ipaddr>" << endl;
    cout << "type:"
         << " -p : ping "
         << " -r : traceroute" << endl;
    cout << "ipaddr:"
         << " ipaddress" << endl;
    cout << "exm: "
         << "leoproute -p 127.0.0.1" << endl;
}

enum TOOLTYPE
{
    PING = 1,
    TRACEROUTE = 2
};

typedef struct options
{
    TOOLTYPE type;
    char *ip_addr;
} option;

bool SloveOptions(char **argv, options &op)
{
    if (strcmp(argv[1], "-t") == 0)
    {
        op.type = TOOLTYPE::TRACEROUTE;
    }
    else if (strcmp(argv[1], "-p") == 0)
    {
        op.type = TOOLTYPE::PING;
    }else{
        Usage();
        exit(-1);
    }
    op.ip_addr = argv[2];
}

int main(int argc, char **argv)
{
    if(argc < 2){
        Usage();
        exit(1);
    }
    WelCome();
    options op;
    SloveOptions(argv, op);
    switch (op.type)
    {
    case TOOLTYPE::TRACEROUTE:
    {
        tr->SetSock(op.ip_addr);
        tr->RecvLoop();
        break;
    }
    case TOOLTYPE::PING:
    {
        pi->SetSock(op.ip_addr);
        pi->RecvLoop();
        break;
    }
    default:
    {
        Usage();
        break;
    }
    }
}
