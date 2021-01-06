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



#define PIN_DIR "/sys/fs/bpf/lnetd-host"

#define DST_MAP "/sys/fs/bpf/lnetd-host/default_dst"

static const char *__doc__=
 " LnetD-Host Mpls Encap: command line tool";


static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"add",		no_argument,		NULL, 'a' },
	{"remove",		no_argument,		NULL, 'r' },
	{"interface",		required_argument,	NULL, 'i' },
	{0, 0, NULL,  0 }
};

static void usage(char *argv[])
{
	int i;
	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf("\n");
	printf(" Usage: %s (options-see-below)\n",
	       argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
			       *long_options[i].flag);
		else
			printf(" short-option: -%c",
			       long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

int raise_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


int main(int argc, char *argv[])
{

    // Raise RLimit
    if (raise_rlimit() != 0)
    {
        fprintf(stderr, "Error setting rlimit. Please ensure you're running this program as a privileged user.\n");

        return EXIT_FAILURE;
    }


/*
    // Retrieve command line arguments.
    struct cmdline cmd = {0};

    parsecmdline(argc, argv, &cmd);

    // Check required arguments.
    if (cmd.baddr == NULL)
    {
        fprintf(stderr, "Missing bind address. Please specify bind address with -b <addr>.\n");

        return EXIT_FAILURE;
    }

    if (cmd.daddr == NULL)
    {
        fprintf(stderr, "Missing destination address. Please specify bind address with -b <addr>.\n");

        return EXIT_FAILURE;
    }


int progfd = -1;
const char *bpfprog = "/home/cpetrescu/lnetd-ctl/host-encap/lnetd-host-mpls-encap.o";
struct bpf_object *obj;

int err = 0;
    if ((err = bpf_prog_load(bpfprog, BPF_PROG_TYPE_XDP, &obj, &progfd)))
    {
        fprintf(stderr, "Error loading XDP program. File => %s. Error => %s. Error Number -> %d\n", bpfprog, strerror(-err), err);

        return EXIT_FAILURE;
    }

    // Unpin maps.
    bpf_object__unpin_maps(obj, PIN_DIR);

bpf_object__pin_maps(obj, PIN_DIR);

    int fwdmap = bpf_map_get(FORWARD_MAP);

    if (fwdmap < 0)
    {
        fprintf(stderr, "Coult not retrieve forward map FD. Exiting...\n");
        
        return EXIT_FAILURE;
    }

*/

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
    fwdinfo = __bpf_htonl(1999);

    if (bpf_map_update_elem(fwdmap, &fwdkey, &fwdinfo, BPF_ANY) != 0)
    {
        fprintf(stderr, "Error adding forwarding rule :: %s\n", strerror(errno));

        return EXIT_FAILURE;
    }
}
