#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "cmdline.h"

static const char *__doc__=
 " LnetD-Host Mpls Encap: command line tool";

const struct option lopts[] =
{
    {"config", required_argument, NULL, 'c'},
    {"offload mode", no_argument, NULL, 'o'},
    {"skb mode", no_argument, NULL, 's'},
    {"interface", required_argument, NULL, 'i'},
    {"remove", no_argument, NULL, 'r'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

static void usage(char *argv[])
{
	int i;
	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf("\n");
	printf(" Usage: %s (options-see-below)\n",
	       argv[0]);
	printf(" Listing options:\n");
	for (i = 0; lopts[i].name != 0; i++) {
		printf(" --%-12s", lopts[i].name);
		if (lopts[i].flag != NULL)
			printf(" flag (internal value:%d)",
			       *lopts[i].flag);
		else
			printf(" short-option: -%c",
			       lopts[i].val);
		printf("\n");
	}
	printf("\n");
}

/**
 * Parses the command line via getopt.
 * 
 * @param argc The argument count from main().
 * @param argv A pointer to the argument array from main().
 * @param cmd A pointer to a cmdline struct which we'll use to store the argument information in.
 * 
 * @return void
 */
void parsecmdline(int argc, char *argv[], struct cmdline *cmd)
{
    int c = -1;
    int optind = 0;
        while ((c = getopt_long(argc, argv, "i:osrh", lopts, NULL)) != -1)
        {
            switch (c)
            {
                case 'i':
                    cmd->interface = optarg;
                    break;

                case 'o':
                    cmd->offload = 1;

                    break;

                case 's':
                    cmd->skb = 1;

                    break;

                case 'h':
                    usage(argv);
                    exit (EXIT_FAILURE);
                case 'r':
                    cmd->remove = 1;
                    break;

                case '?':
                    fprintf(stderr, "Missing argument.\n");
                    exit (EXIT_FAILURE);
           }
        }
}
