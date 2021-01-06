LIBBPFSRC = libbpf/src

LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/bpf_prog_linfo.o $(LIBBPFSRC)/staticobjs/bpf.o $(LIBBPFSRC)/staticobjs/btf_dump.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/btf.o $(LIBBPFSRC)/staticobjs/hashmap.o $(LIBBPFSRC)/staticobjs/libbpf_errno.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/libbpf_probes.o $(LIBBPFSRC)/staticobjs/libbpf.o $(LIBBPFSRC)/staticobjs/netlink.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/nlattr.o $(LIBBPFSRC)/staticobjs/str_error.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/xsk.o

LOADEROBJS += src/cmdline.o
LOADERSRC += src/lnetd_cmd.c
LOADERFLAGS += -lelf -lz -lconfig

ADDOBJS += src/cmdline.o
ADDSRC +=  src/lnetd_util.c


UTILSOBJ += src/utils.o
UTILSSRC += src/utils.c

#all: utils xdp_prog loader xdp_util
all: utils xdp_prog loader
loader: libbpf utils $(LOADEROBJS)
	clang -I$(LIBBPFSRC) $(LOADERFLAGS) -O3 -o lnetd_cmd $(LIBBPFOBJS) $(LOADEROBJS) $(UTILSOBJ)  $(LOADERSRC)
xdp_util: libbpf utils $(ADDOBJS)
	clang -I$(LIBBPFSRC) $(LOADERFLAGS) -O3 -o lnetd_util $(LIBBPFOBJS) $(ADDOBJS) $(UTILSOBJ) $(ADDSRC)
xdp_prog:
	clang -I$(LIBBPFSRC) -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/lnetd_host_mpls_encap.c -o src/lnetd_host_mpls_encap.bc
	llc -march=bpf -filetype=obj src/lnetd_host_mpls_encap.bc -o lnetd_host_xdp_prog.o
libbpf:
	$(MAKE) -C $(LIBBPFSRC)
utils: libbpf $(LOADEROBJS)
	clang -I$(LIBBPFSRC) -Wno-unused-command-line-argument $(LOADERFLAGS) -c -o $(UTILSOBJ) $(LIBBPFOBJS) $(LOADEROBJS) $(UTILSSRC)
clean:
	$(MAKE) -C $(LIBBPFSRC) clean
	rm -f src/*.o src/*.bc *.o
	rm -f lnetd_cmd lnetd_util
install:
.PHONY: libbpf all
.DEFAULT: all
