#include <string>



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>

#include <linux/bpf.h>
//#include <libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <arpa/inet.h>



#include <grpcpp/grpcpp.h>
#include "mathtest.grpc.pb.h"

#define DST_MAP "/sys/fs/bpf/lnetd-host/default_dst"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

using mathtest::MathTest;
using mathtest::MathRequest;
using mathtest::MathReply;

class MathServiceImplementation final : public MathTest::Service {
    Status sendRequest(
        ServerContext* context, 
        const MathRequest* request, 
        MathReply* reply
    ) override {
        int a = request->a();
        int b = request->b();

        reply->set_result(a * b);

        return Status::OK;
    } 
};

int bpf_map_get(const char *path)
{
    int fd = -1;

    fd = bpf_obj_get(path);

    return fd;
}

void ebpf_update(){

int fwdmap = bpf_map_get(DST_MAP);
bpf_map_update_elem(fwdmap, &fwdkey, &fwdinfo, BPF_ANY)

}
void Run() {
    std::string address("0.0.0.0:5000");
    MathServiceImplementation service;

    ServerBuilder builder;

    builder.AddListeningPort(address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on port: " << address << std::endl;

    server->Wait();
}

int main(int argc, char** argv) {
    Run();
    return 0;
}
