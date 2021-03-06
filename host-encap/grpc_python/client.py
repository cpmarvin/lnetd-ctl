import argparse
import sys
import grpc
import counters_pb2
import counters_pb2_grpc


parser = argparse.ArgumentParser(description="Initialize load balancer map")

group1 = parser.add_argument_group("interface specific")
group2 = parser.add_argument_group("map specific")

group1.add_argument("-i", action="store", required=False, help="xdp network interface")

group1.add_argument("-p", action="store_true", required=False, help="List current maps")

group1.add_argument("-c", action="store_true", required=False, help="List counters")

group2.add_argument("-a", action="store_true", required=False, help="Add entry to map")

group2.add_argument(
    "-r", action="store_true", required=False, help="Remove entry from map"
)

group2.add_argument("-m", action="store", required=False, type=int, help="map id")

group2.add_argument(
    "-s",
    action="store",
    required=False,
    type=str,
    help="ip subnet example: -s 192.168.0.0/24",
)

group2.add_argument("-l", action="store", required=False, type=int, help="label")

args = parser.parse_args()

channel = grpc.insecure_channel("127.0.0.1:50051")


if args.a:
    if not args.m or not args.s or not args.l:
        print("-a -s and -l must be given together when using remove")
    else:
        stub2 = counters_pb2_grpc.int_UpdateMapStub(channel)
        response2 = stub2.UpdateMap(
            counters_pb2.UpdateMapRequest(map_id=args.m, subnet=args.s, lbl=args.l)
        )
        print(response2)

if args.r:
    if not args.m or not args.s:
        print("-m and -s must be given together when using remove")
    else:
        stub3 = counters_pb2_grpc.int_UpdateMapStub(channel)
        response3 = stub3.DeleteMap(
            counters_pb2.UpdateMapRequest(map_id=args.m, subnet=args.s, lbl=100)
        )
        print(response3)

if args.i:

    if (args.p or args.c) == False:
        parser.error("-i and -p must be given together")
    elif args.p == True:
        xdp_interface = args.i
        stub1 = counters_pb2_grpc.int_mapStub(channel)
        response1 = stub1.GetMaps(
            counters_pb2.MappacketRequest(interface=xdp_interface)
        )
        print(response1)
    elif args.c == True:
        xdp_interface = args.i
        stub1 = counters_pb2_grpc.int_mapStub(channel)
        response1 = stub1.GetMapCounters(
            counters_pb2.MappacketRequest(interface=xdp_interface)
        )
        print(response1)
