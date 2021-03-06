# lnetd-host-encap
PoC host encap using eBPF 

Based on :

https://github.com/Netronome/bpf-samples/blob/master/l4lb

https://github.com/fzakaria/ebpf-mpls-encap-decap



See https://github.com/cpmarvin/lnetd-ctl/blob/main/host-encap/ebpf_mpls_encap.pdf for more details.

1000000 is the first available static label on JNP but you can use any label #define MPLS_STATIC_LABEL <X>.
    
Compile the program and cmd with:

```
git clone https://github.com/cpmarvin/lnetd-ctl.git
git submodule update --init --recursive
make
```
 
Using the lnetd_cmd:

```
- Disable with lnetd_cmd
 % sudo ./lnetd_cmd -i <int_name> -r

- Enable with lnetd_cmd 
 % sudo ./lnetd_cmd -i <int_name>   
```

- Check program id and get map id 

```
 % sudo bpftool map       
411: lpm_trie  name priority_client  flags 0x1
        key 8B  value 4B  max_entries 50  memlock 4096B
412: lpm_trie  name priority_dst  flags 0x1
        key 8B  value 4B  max_entries 50  memlock 4096B
413: lpm_trie  name default_dst  flags 0x1
        key 8B  value 4B  max_entries 50  memlock 4096B

```

- Program map

* add dst 8.0.0.0/8 in default_dst with label 100 0x64
```
 % sudo bpftool map update id 413    key  8 0 0 0     8 0 0 0 value  0 0x0 0x0 0x64 

```
* add dst 8.0.0.0/8 in priority_dst with label 200 0xC8
```
 % sudo bpftool map update id 412    key  8 0 0 0     8 0 0 0 value  0 0x0 0x0 0xC8

```
* add src 192.168.0.26/32 in priority_client 
```
sudo bpftool map update id 411    key  32 0 0 0    192 168 0 26 value  0 0x0 0x0 0x0
```

* expected result 

packet with src * to 8.8.8.8 has label 100 , packet to other destinations has lbl 1000000

packet with src * to 8.8.8.8 has label 100 and not 200 , packet to other destinations has lbl 1000000

packet with src 192.168.0.26 to 8.8.8.8 has label 200 , packet to other destinations has lbl 1000000


Checkig with filter applied on lo 

```
 % sudo tcpdump -i lo mpls -n 
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes

17:28:12.294998 MPLS (label 200, exp 0, [S], ttl 64) IP 192.168.0.26 > 8.8.8.8: ICMP echo request, id 82, seq 2192, length 64
17:28:13.004606 MPLS (label 1000000, exp 0, [S], ttl 64) IP 127.0.0.1.47106 > 127.0.0.53.53: 29684+ A? stadia.google.com. (35)
17:28:14.001457 MPLS (label 1000000, exp 0, [S], ttl 64) IP 127.0.0.1.57106 > 127.0.0.53.53: 46502+ A? stadia.google.com. (35)
17:28:14.708666 MPLS (label 100, exp 0, [S], ttl 64) IP 127.0.0.1 > 8.8.8.8: ICMP echo request, id 83, seq 1, length 64

```


    
Future updates with JNP LAB:

![LnetD-HOST](/images/lnetd-host-ctl.png)

```
R5:
lab@gb-pe5-lon> show configuration protocols source-packet-routing                  
segment-list SR1-W70 {
    R3 label 201003;
}
segment-list SR1-W30 {
    R7 label 201007;
    R3 label 201003;
}
source-routing-path POC {
    to 10.3.3.3;
    color 0;
    binding-sid 1000000;
    primary {
        SR1-W70 weight 70;
        SR1-W30 weight 30;
    }
}
lab@gb-pe5-lon> show route 8.8.8.8 

inet.0: 23 destinations, 35 routes (23 active, 0 holddown, 0 hidden)
@ = Routing Use Only, # = Forwarding Use Only
+ = Active Route, - = Last Active, * = Both

8.8.8.0/24         *[BGP/170] 01:06:15, localpref 100, from 10.10.10.10
                      AS path: I, validation-state: unverified
                    > to 192.168.1.2 via ge-0/0/3.0


lab@gb-pe5-lon> show route table mpls.0 label 1000000 detail                        

mpls.0: 21 destinations, 21 routes (21 active, 0 holddown, 0 hidden)
1000000 (1 entry, 1 announced)
        *SPRING-TE Preference: 8
                Next hop type: Indirect, Next hop index: 0
                Address: 0xc41cf10
                Next-hop reference count: 1
                Next hop type: Router, Next hop index: 610
                Next hop: 10.5.8.8 via ge-0/0/2.0 weight 0x1, selected
                Label operation: Swap 201003
                Load balance label: Label 201003: None; 
                Label element ptr: 0xc6327a0
                Label parent element ptr: 0x0
                Label element references: 2
                Label element child references: 0
                Label element lsp id: 0
                Session Id: 0x146
                Next hop type: Router, Next hop index: 618
                Next hop: 10.5.8.8 via ge-0/0/2.0 weight 0x1
                Label operation: Push 201007
                Label TTL action: prop-ttl
                Load balance label: Label 201007: None; 
                Label element ptr: 0xc633640
                Label parent element ptr: 0x0
                Label element references: 2
                Label element child references: 0
                Label element lsp id: 0
                Session Id: 0x146
                Protocol next hop: 201003 Balance: 70%
                Composite next hop: 0xdc07650 636 INH Session ID: 0x0
                Indirect next hop: 0xb23c700 1048576 INH Session ID: 0x0 Weight 0x1
                Protocol next hop: 201007 
                Label operation: Swap 201003
                Load balance label: Label 201003: None; 
                 Balance: 30%
                Composite next hop: 0xdc07760 635 INH Session ID: 0x0
                Indirect next hop: 0xb23d180 1048575 INH Session ID: 0x0 Weight 0x1
                State: <Active>
                Local AS:    25 
                Age: 19:28      Metric: 1       Metric2: 60 
                Validation State: unverified 
                ORR Generation-ID: 0 
                Task: SPRING-TE
                Announcement bits (3): 1-KRT 2-rt-export-service 4-RT 
                AS path: I 
                
```

Traffic flow from a client behind R5 

SRV->R5->eBPF-Server->R5(mpls encap with BSID)

```
lab@lab-dev:~$ traceroute 8.8.8.8 -n -e 
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  192.168.200.1  0.966 ms  1.768 ms  1.733 ms
 2  192.168.1.1 <MPLS:L=1000000,E=0,S=1,T=1>  7.734 ms  7.695 ms  7.663 ms
 3  10.5.8.8 <MPLS:L=201003,E=0,S=1,T=1>  7.644 ms  7.604 ms  7.567 ms
 4  10.8.10.10 <MPLS:L=201007,E=0,S=0,T=1/L=201003,E=0,S=1,T=2>  7.445 ms  7.434 ms  7.395 ms
 5  10.177.77.7 <MPLS:L=201003,E=0,S=1,T=1>  7.362 ms  7.324 ms 10.7.10.7 <MPLS:L=201003,E=0,S=1,T=1>  7.292 ms
 6  10.6.7.6 <MPLS:L=201003,E=0,S=1,T=1>  7.227 ms  6.710 ms  5.900 ms
 7  10.2.6.2 <MPLS:L=201003,E=0,S=1,T=1>  6.906 ms  7.982 ms  7.949 ms
 8  8.8.8.8  11.526 ms  11.522 ms  11.484 ms
lab@lab-dev:~$ traceroute 8.8.8.8 -n -e 
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  192.168.200.1  61.245 ms  61.194 ms  61.144 ms
 2  192.168.1.1 <MPLS:L=1000000,E=0,S=1,T=1>  65.623 ms  65.739 ms  65.691 ms
 3  10.5.8.8 <MPLS:L=201003,E=0,S=1,T=1>  6.475 ms  6.429 ms  6.382 ms
 4  10.8.10.10 <MPLS:L=201007,E=0,S=0,T=1/L=201003,E=0,S=1,T=2>  6.299 ms 10.8.10.10 <MPLS:L=201003,E=0,S=1,T=1>  6.279 ms 10.8.10.10 <MPLS:L=201007,E=0,S=0,T=1/L=201003,E=0,S=1,T=2>  6.231 ms
 5  10.177.77.7 <MPLS:L=201003,E=0,S=1,T=1>  7.040 ms  6.992 ms 10.7.10.7 <MPLS:L=201003,E=0,S=1,T=1>  6.946 ms
 6  10.6.7.6 <MPLS:L=201003,E=0,S=1,T=1>  6.608 ms  6.002 ms  5.963 ms
 7  10.2.6.2 <MPLS:L=201003,E=0,S=1,T=1>  20.591 ms  20.558 ms  20.558 ms
 8  8.8.8.8  5.877 ms  5.992 ms  5.814 ms
lab@lab-dev:~$
```

