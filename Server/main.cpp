//
// Created by aokblast on 2022/9/27.
//

#include "Server.h"
#include <seal/seal.h>


int main() {
	Server server(4096, 1024, seal::scheme_type::bfv);
	server.add_worker("127.0.0.1", 5000);
	server.add_worker("127.0.0.1", 5001);


	server.run({5, 11});
}

