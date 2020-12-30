#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <time.h>
#include "bpf_load.h"
#include <bpf/bpf.h>
#include "bpf_util.h"

#include <getopt.h> //for getops long
#include <net/if.h> //for net to index

static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;
static int ifindex = -1;

static __u32 xdp_flags = 0;
int longindex = 0;

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


// unlink the xdp program and exit
static void int_exit(ifindex) {
  printf("stopping\n");
  bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
  exit(0);
}

// An XDP program which filter packets for an IP address
// ./xdp_ip_filter -i <ip>
int main(int argc, char **argv) {
  const char *optstr = "adshi:t:u:";
  char *filename="lnetd-host-mpls-encap.o";
  int opt;
  bool exit_status = false;
  // maps key
  __u32 key = 0;

  //while ((opt = getopt(argc, argv, optstr)) != -1) {
  while ((opt = getopt_long(argc, argv, "arpi:",
				  long_options, &longindex)) != -1) {
    switch(opt)
      {
      case 'i':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --interface name too long\n");
				goto error;
			}
        ifname = (char *)&ifname_buf;
        strncpy(ifname, optarg, IF_NAMESIZE);
        ifindex = if_nametoindex(ifname);
        break;
      case 'r':
        exit_status = true;
        break;
      case 'h':
      error:
      default:
       usage(argv);
       return -1;
    }
  }
	if (ifindex == -1) {
		printf("ERR: required option --dev missing");
		usage(argv);
		return -1 ;
	}
        if (exit_status ) {
          int_exit(ifindex);
}

  // change limits
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
    return 1;
  }

  // load the bpf kern file
  if (load_bpf_file(filename)) {
    printf("error %s", bpf_log_buf);
    return 1;
  }

  if (!prog_fd[0]) {
    printf("load_bpf_file: %s\n", strerror(errno));
    return 1;
  }

  // link the xdp program to the interface
  if (bpf_set_link_xdp_fd(ifindex, prog_fd[0], xdp_flags) < 0) {
    printf("link set xdp fd failed\n");
    return 1;
  }
printf("all done , filename %s active on interface %s\n", filename,ifname);

}
