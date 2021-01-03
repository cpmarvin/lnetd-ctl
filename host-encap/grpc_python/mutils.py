import json
import subprocess
import struct
import sys


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
                map_ids.append(entry)
        return map_ids
    except Exception as e:
        return str(e)


def get_map_entries_count(map_id):
    """return number of entries in the map"""
    try:
        cmd_progshow = "bpftool map dump id %d -j" % map_id
        total_entries = check_output_json(cmd_progshow)
        return len(total_entries)
    except Exception as e:
        return str(e)

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

