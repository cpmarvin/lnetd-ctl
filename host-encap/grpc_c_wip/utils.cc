#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>

#include <bpf.h>
#include <bpf_endian.h>
#include <libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "utils.h"

#define DST_MAP "/sys/fs/bpf/lnetd-host/default_dst"

int bpf_map_get(const char *path)
{
    int fd = -1;

    fd = bpf_obj_get(path);

    return fd;
}

int foo(int lbl)
{


int fwdmap = bpf_map_get(DST_MAP);

struct trie_value
{
	__u32 lbl;
};

struct key_4
{
	__u32 prefixlen;
	__u32 ipv4_addr;
};


   __u32 destaddr;

   struct sockaddr_in sa;
   char str[INET_ADDRSTRLEN];

    // store this IP address in sa:
    inet_pton(AF_INET,"8.8.8.8", &(sa.sin_addr) );
    printf("lbl %d",lbl);

    destaddr =  sa.sin_addr.s_addr;
    //__u32 addr_x = inet_aton("8.0.0.0");
    //destaddr = __bpf_htonl(134217728);
    //destaddr = __bpf_htonl(destaddr);

    struct key_4 fwdkey;
    //struct trie_value fwdinfo;
    __u32 fwdinfo;
    fwdkey.prefixlen = 32;
    fwdkey.ipv4_addr = destaddr;
    //fwdinfo.lbl = 100;
    fwdinfo = __bpf_htonl(lbl);

    if (bpf_map_update_elem(fwdmap, &fwdkey, &fwdinfo, BPF_ANY) != 0)
    {
        fprintf(stderr, "Error adding forwarding rule :: %s\n", strerror(errno));

        return EXIT_FAILURE;
    }

     return 222;
}
