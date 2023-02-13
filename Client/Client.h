//
// Created by aokblast on 2022/9/13.
//

#ifndef MD5CHECKERINCPP_CLIENT_H
#define MD5CHECKERINCPP_CLIENT_H
#include <seal/seal.h>
#include <memory>
#include <boost/asio.hpp>

class Client {
	std::unique_ptr<seal::Evaluator> evaluator;
	boost::asio::io_service service;
	boost::asio::ip::tcp::acceptor acceptor;
	const static size_t DEFAULT_PORT = 25565;
	static void client_handler(std::unique_ptr<boost::asio::ip::tcp::socket> socket);
public:

	Client() = delete;
	Client& operator=(const Client&) = delete;
	Client(const Client&) = delete;
	Client(const boost::asio::ip::tcp::endpoint &endpoint) : service(), acceptor(service, endpoint){}
	void run();

	const seal::Evaluator &get_evaluator() const;
};


#endif //MD5CHECKERINCPP_CLIENT_H
