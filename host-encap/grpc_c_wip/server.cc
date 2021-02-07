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

#include <bpf.h>
#include <libbpf.h>

#include <linux/if_link.h>
#include <net/if.h>
#include <arpa/inet.h>



#include <grpcpp/grpcpp.h>
#include "mathtest.grpc.pb.h"

extern "C" {
  #include "utils.h" //a C header, so wrap it in extern "C" 
}

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
        int c = foo(100);

        reply-> set_result(c);
        //reply-> foo();

        return Status::OK;
    } 
};




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
