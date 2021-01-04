import json
import subprocess
import struct
import sys


def hex_list_to_int(hex_list):
    hex_str = ''.join([byte.replace('0x', '') for byte in hex_list])
    return (int.from_bytes(bytes.fromhex(hex_str), byteorder='little'))

def check_output_json(cmd):
    return json.loads(subprocess.check_output(cmd, shell=True).decode("utf-8"))


def get_xdp_prog(interface):
    cmd_iplink = "ip -j link show %s" % interface
    iplink = check_output_json(cmd_iplink)
    if len(iplink) > 0:
        if iplink[0].get("xdp"):
            return iplink[0]["xdp"]["prog"]["id"]
    return "None"


def get_map_ids(interface):
    try:

        prog_id = get_xdp_prog(interface)
        cmd_progshow = "bpftool prog show id %d -p" % prog_id
        prog_info = check_output_json(cmd_progshow)

        maps = check_output_json("bpftool map -p")
        map_ids = []

        for m in maps:
            if m["id"] in prog_info["map_ids"]:
                map_ids.append(str(m["id"]))
        return map_ids
    except Exception as e:
        return str(e)


def get_map_names(interface):
    """return map name from interface"""
    try:

        prog_id = get_xdp_prog(interface)
        cmd_progshow = "bpftool prog show id %d -p" % prog_id
        prog_info = check_output_json(cmd_progshow)

        maps = check_output_json("bpftool map -p")
        map_ids = []

        for m in maps:
            if m["id"] in prog_info["map_ids"]:
                entry = {"id": None, "name": None, "entries": None}
                entry["id"] = m["id"]
                entry["name"] = m["name"]
                entry["entries"] = get_map_entries_count(m["id"])
                #entry["entries"] = [{'subnet':24,'ipaddress':19216811,'lbl':10}]
                map_ids.append(entry)
        return map_ids
    except Exception as e:
        return str(e)


def get_map_entries_count(map_id):
    """return number of entries in the map"""
    try:
        cmd_progshow = "bpftool map dump id %d -j" % map_id
        total_entries = check_output_json(cmd_progshow)
        entries = []
        for n in total_entries:
            mask_hex = n['key'][0:4]
            mask_dec = [int(x, 16) for x in mask_hex][0]
            dest_ip = [int(byte.replace('0x',''), 16) for byte in n['key'][4:8]]
            ip = '%s.%s.%s.%s' % (dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3])
            lbl_hex = n['value'][0:4]
            lbl_hex_full = ''.join(x.replace('0x','') for x in lbl_hex)
            lbl = int(lbl_hex_full,16)
            full_entry  = {'subnet':mask_dec,'ipaddress':ip,'lbl':lbl}
            entries.append(full_entry)
        return entries
    except Exception as e:
        return []

def update_map(map_id,subnet,lbl):
    ip = subnet.split('/')[0].split('.')
    subnet = subnet.split('/')[1]
    ip_hex = '0x{:02X} 0x{:02X} 0x{:02X} 0x{:02X}'.format( int(ip[0]),int(ip[1]),int(ip[2]),int(ip[3]) )
    ip_hex =  ''.join([ip for ip in ip_hex])
    mask_hex = '0x{:02x} 0x0 0x0 0x0'.format( int(subnet))
    lbl_hex = '%08X' % lbl
    BPF_RUN = ([' sudo bpftool map update id ', str(map_id), ' key ', mask_hex ,ip_hex, ' value ' ,'0x'+lbl_hex[0:2] , '0x'+lbl_hex[2:4] ,'0x'+lbl_hex[4:6
] ,'0x'+lbl_hex[6:8] ])
    BPF_RUN = ' '.join(BPF_RUN)
    try:
        result = subprocess.check_output(BPF_RUN, shell=True)
        return 'OK' + BPF_RUN
    except:
        return 'NOK'

