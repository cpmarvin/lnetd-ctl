#pragma once

#include <inttypes.h>

struct cmdline
{
    unsigned int offload : 1;
    unsigned int skb : 1;

    char *baddr;
    uint16_t bport;

    char *daddr;
    uint16_t dport;

    char *protocol;
    char *interface;
    unsigned int help : 1;
    unsigned int remove;
};

void parsecmdline(int argc, char *argv[], struct cmdline *cmd);
