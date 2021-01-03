Based on: 

https://github.com/Netronome/bpf-samples/tree/master/l4lb

https://github.com/openconfig/public/blob/master/doc/oc_by_example.md


Using grpc:

```
- Disable with lnetd_cmd
 % sudo ./lnetd_cmd -i <int> -r
stopping
- Enable with lnetd_cmd 
 % sudo ./lnetd_cmd -i <int>   
all done , filename lnetd-host-mpls-encap.o active on interface <int>
 % sudo python3 server.py 
gRPC server listening on port 50051
```

- Check maps on interface

```
 % python3 client.py -i docker0 -p
map_info {
  id: 25
  name: "priority_client"
}
map_info {
  id: 26
  name: "priority_dst"
}
map_info {
  id: 27
  name: "default_dst"
}
```

- Program priority_dst map with 8.0.0.0/8 and lbl 100
```
 % python3 client.py -a -m 26 -s 8.0.0.0/8 -l 100    
message: "OK sudo bpftool map update id  26  key  0x08 0x0 0x0 0x0 0x08 0x00 0x00 0x00  value  0x00 0x00 0x00 0x64"

 % python3 client.py -i docker0 -p               
map_info {
  id: 25
  name: "priority_client"
}
map_info {
  id: 26
  name: "priority_dst"
  entries: 1
}
map_info {
  id: 27
  name: "default_dst"
}

```

