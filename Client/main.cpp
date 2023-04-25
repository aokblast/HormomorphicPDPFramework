#include "Client.h"
#include <boost/asio.hpp>

namespace asio = boost::asio;

int main(int argc, char *argv[]) {
    Client client(asio::ip::tcp::endpoint(
                      asio::ip::address::from_string("127.0.0.1"), std::stoi(argv[1])));
    client.run();


    return 0;
}
