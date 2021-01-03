from mutils import *

t = get_map_names("virbr0")
print(t)

import counters_pb2
import counters_pb2_grpc

t1 = counters_pb2.MappaketReply()
print(dir(t1))

result = [{"map_info": {}}]
result[0]["map_info"] = t
print(result)

def update_map(map_id,subnet,lbl):
    ip = subnet.split('/')[0].split('.')
    subnet = subnet.split('/')[1]
    ip_hex = '0x{:02X} 0x{:02X} 0x{:02X} 0x{:02X}'.format( int(ip[0]),int(ip[1]),int(ip[2]),int(ip[3]) )
    ip_hex =  ''.join([ip for ip in ip_hex])
    mask_hex = '0x{:02x} 0x0 0x0 0x0'.format( int(subnet))
    lbl_hex = '%08X' % lbl
    BPF_RUN = ([' sudo bpftool map update id ', str(map_id), ' key ', mask_hex ,ip_hex, ' value ' ,'0x'+lbl_hex[0:2] , '0x'+lbl_hex[2:4] ,'0x'+lbl_hex[4:6] ,'0x'+lbl_hex[6:8] ])
    BPF_RUN = ' '.join(BPF_RUN)
    print(BPF_RUN)

update_map(13,'8.8.8.0/24',15)
