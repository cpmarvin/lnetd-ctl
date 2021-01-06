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
#include <libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "cmdline.h"
#include "utils.h"

#define PIN_DIR "/sys/fs/bpf/lnetd-host"


/**
 * Raises the RLimit.
 * 
 * @return Returns 0 on success (EXIT_SUCCESS) or 1 on failure (EXIT_FAILURE).
 */
int raise_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param ifidx The index to the interface to attach to.
 * @param progfd A file description (FD) to the BPF/XDP program.
 * @param cmd A pointer to a cmdline struct that includes command line arguments (mostly checking for offload/HW mode set).
 * 
 * @return Returns the flag (int) it successfully attached the BPF/XDP program with or a negative value for error.
 */
int attachxdp(int ifidx, int progfd, struct cmdline *cmd)
{
    int err;

    char *smode;

    uint32_t flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    uint32_t mode = XDP_FLAGS_DRV_MODE;
    
    smode = "DRV/native";

    if (cmd->offload)
    {
        smode = "HW/offload";

        mode = XDP_FLAGS_HW_MODE;
    }
    else if (cmd->skb)
    {
        smode = "SKB/generic";
        mode = XDP_FLAGS_SKB_MODE;
    }

    flags |= mode;

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;
        err = bpf_set_link_xdp_fd(ifidx, progfd, flags);

        if (err || progfd == -1)
        {
            const char *errmode;

            // Decrease mode.
            switch (mode)
            {
                case XDP_FLAGS_HW_MODE:
                    mode = XDP_FLAGS_DRV_MODE;
                    flags &= ~XDP_FLAGS_HW_MODE;
                    errmode = "HW/offload";

                    break;

                case XDP_FLAGS_DRV_MODE:
                    mode = XDP_FLAGS_SKB_MODE;
                    flags &= ~XDP_FLAGS_DRV_MODE;
                    errmode = "DRV/native";

                    break;

                case XDP_FLAGS_SKB_MODE:
                    // Exit program and set mode to -1 indicating error.
                    exit = 1;
                    mode = -err;
                    errmode = "SKB/generic";
                    break;
            }

            if (progfd != -1)
            {
                fprintf(stderr, "Could not attach with %s mode (%s)(%d).\n", errmode, strerror(-err), err);
            }
            
            if (mode != -err)
            {
                smode = (mode == XDP_FLAGS_HW_MODE) ? "HW/offload" : (mode == XDP_FLAGS_DRV_MODE) ? "DRV/native" : (mode == XDP_FLAGS_SKB_MODE) ? "SKB/generic" : "N/A";
                flags |= mode;
            }
        }
        else
        {
            fprintf(stdout, "Loaded XDP program in %s mode.\n", smode);

            break;
        }
    }

    return mode;
}

int main(int argc, char *argv[])
{
    // Raise RLimit
    if (raise_rlimit() != 0)
    {
        fprintf(stderr, "Error setting rlimit. Please ensure you're running this program as a privileged user.\n");
        return EXIT_FAILURE;
    }

    // Parse command line.
    struct cmdline cmd = {0};
    parsecmdline(argc, argv, &cmd);

    // Retrieve interface index.
    int ifidx ;

    if (cmd.interface != NULL){
       ifidx = if_nametoindex(cmd.interface);
    }else{
        fprintf(stderr, "Error retrieving interface index. Interface => %s\n", cmd.interface);
        fprintf(stderr, "You must provide -i <interface> , see lnetd_cmd -h \n");
        return EXIT_FAILURE;
    }

    // Load XDP/BPF map.
    int progfd = -1;
    const char *bpfprog = "lnetd_host_xdp_prog.o";

    struct bpf_object *obj;

    int err = 0;
    if ((err = bpf_prog_load(bpfprog, BPF_PROG_TYPE_XDP, &obj, &progfd)))
    {
        fprintf(stderr, "Error loading XDP program. File => %s. Error => %s. Error Number -> %d\n", bpfprog, strerror(-err), err);

        return EXIT_FAILURE;
    }

    //unload program if -r

    if (cmd.remove != 0){
      attachxdp(ifidx, -1, &cmd);
      // Unpin maps.
      bpf_object__unpin_maps(obj, PIN_DIR);
      return EXIT_SUCCESS;
    }

    //load program
    err = attachxdp(ifidx, progfd, &cmd);

    if (err != XDP_FLAGS_HW_MODE && err != XDP_FLAGS_DRV_MODE && err != XDP_FLAGS_SKB_MODE)
    {
        fprintf(stderr, "Error attaching XDP program :: %s (%d)\n", strerror(err), err);

        return EXIT_FAILURE;
    }

    // Pin maps.
    bpf_object__pin_maps(obj, PIN_DIR);

    return EXIT_SUCCESS;
}
