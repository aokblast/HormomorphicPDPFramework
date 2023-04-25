//
// Created by aokblast on 2022/9/13.
//

#include <future>
#include <chrono>
#include <boost/array.hpp>
#include "Client.h"
#include "../common.h"

namespace asio = boost::asio;


const seal::Evaluator
&Client::get_evaluator() const {
    return *evaluator;
}

void
Client::run() {
    while (true) {
        auto socket = std::make_unique<asio::ip::tcp::socket>(service);
        acceptor.accept(*socket);
        print_time();
        std::cout << "Server Connected: " << socket->remote_endpoint() << '\n';
        std::async(std::launch::async, client_handler, std::move(socket));
    }
}

void
Client::client_handler(std::unique_ptr<asio::ip::tcp::socket> socket) {
    using namespace std::chrono_literals;

    boost::array<char, 319530> buf;

    std::this_thread::sleep_for(100ms);
    std::stringstream stream;

    size_t len = socket->receive(asio::buffer(buf));
    std::cout << len << '\n';
    stream.write(buf.data(), len);
    seal::EncryptionParameters parameters(seal::scheme_type::bfv);
    parameters.load(stream);

    seal::SEALContext context(parameters);
    print_time();
    std::cout << "Client Status: " << context.parameter_error_message() << '\n';
    seal::Evaluator evaluator(context);

    seal::Ciphertext ciphertext, two_cipher;
    ciphertext.load(context, stream);
    two_cipher.load(context, stream);


    evaluator.multiply_inplace(ciphertext, two_cipher);

    stream.clear();
    len = ciphertext.save(stream);

    stream.read(buf.data(), len);

    socket->send(boost::asio::buffer(buf, len));
    print_time();
    std::cout << "Client successfully calculate!" << '\n';
}
