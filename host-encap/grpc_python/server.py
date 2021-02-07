from concurrent import futures
import time
import os
import grpc
import counters_pb2
import counters_pb2_grpc
from mutils import get_map_ids, get_map_names, update_map, get_map_counters
import ipdb


class int_UpdateMap(counters_pb2_grpc.int_UpdateMapServicer):
    def UpdateMap(self, request, context):
        map_id = request.map_id
        subnet = request.subnet
        lbl = request.lbl
        result = update_map(map_id, subnet, lbl, action="add")
        return counters_pb2.UpdateMapReply(message=result)

    def DeleteMap(self, request, context):
        map_id = request.map_id
        subnet = request.subnet
        lbl = request.lbl
        result = update_map(map_id, subnet, lbl, action="delete")
        return counters_pb2.UpdateMapReply(message=result)


class int_map(counters_pb2_grpc.int_mapServicer):
    def GetMaps(self, request, context):
        interface = request.interface
        result = get_map_names(interface)
        return counters_pb2.MappaketReply(map_info=result)

    def GetMapCounters(self, request, context):
        interface = request.interface
        result = get_map_counters(interface)
        # result = [{"src": "1", "dst": "1", "bbytes": 1, "pkts": 1}]
        return counters_pb2.countersReply(entries=result)


server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

counters_pb2_grpc.add_int_mapServicer_to_server(int_map(), server)
counters_pb2_grpc.add_int_UpdateMapServicer_to_server(int_UpdateMap(), server)

server.add_insecure_port("127.0.0.1:50051")
server.start()
print("gRPC server listening on port 50051")
try:  # Have the server listen for about a day
    while True:
        time.sleep(99999)
except KeyboardInterrupt:
    server.stop(0)
