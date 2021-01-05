import logging
import threading
import time
import csv

import grpc
import counters_pb2
import counters_pb2_grpc

channel = grpc.insecure_channel("127.0.0.1:50051")

def update_ebpf_maps(subnet,lbl):
    logging.info("Thread %s: starting", lbl)
    stub2 = counters_pb2_grpc.int_UpdateMapStub(channel)
    response2  = stub2.UpdateMap(counters_pb2.UpdateMapRequest(map_id=42,subnet=subnet,lbl=lbl))
    logging.info("Thread %s: finishing", lbl)

if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO,
                        datefmt="%H:%M:%S") 
    try:
        dest_file = open('bgp_table/prefixes.csv', 'r')
        dest_hosts = list(csv.reader(dest_file))
        dest_count = len(dest_hosts)
    except:
        print("Error reading file")
        sys.exit(1)

    threads = list()
    for index,subnet, in enumerate(dest_hosts):
        logging.info("Main    : create and start thread %d.", index)
        x = threading.Thread(target=update_ebpf_maps, args=(subnet[0],index+1000,))
        threads.append(x)
        x.start()
    '''
    for index, thread in enumerate(threads):
        logging.info("Main    : before joining thread %d.", index)
        thread.join()
        logging.info("Main    : thread %d done", index)
    '''
