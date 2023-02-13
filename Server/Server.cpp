//
// Created by aokblast on 2022/9/13.
//

#include "Server.h"
#include "../common.h"
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <sstream>
#include <chrono>
#include <memory>


using namespace seal;
using namespace boost::asio;

Server::Server(size_t poly_module_degree, size_t plain_module, seal::scheme_type type) {
	seal::EncryptionParameters parameters(type);
	parameters.set_poly_modulus_degree(poly_module_degree);
	parameters.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_module_degree));
	parameters.set_plain_modulus(plain_module);
	parameters.save(param_stream);

	context = std::make_unique<seal::SEALContext>(parameters);
	print_time();
	std::cout << "Server Create Status: " << context->parameter_error_message() << '\n';

	keygen = std::make_unique<seal::KeyGenerator>(*context);
	secret_key = keygen->secret_key();
	decryptor = std::make_unique<seal::Decryptor>(*context, secret_key);
}

seal::Plaintext Server::decrypt(std::istream &text_file) const {
	Ciphertext text;
	Plaintext p;
	text.load(*context, text_file);
	decryptor->decrypt(text, p);
	return p;
}

void Server::run(const std::vector<uint64_t> &vals) {

	assert(workers.size() >= vals.size());

	for(int i = 0; auto worker : workers)
		worker->thread = std::make_unique<std::thread>(&Worker::work, worker, vals[i++]);

	for(int i = 0; const auto& worker : workers) {
		print_time();
		std::cout << "Calculate " << vals[i] << " * 2 " << "for worker " << i << '\n';
		worker->thread->join();
		auto res = worker->get_res();
		std::stringstream ss;
		ss.write(res.first.data(), res.second);

		auto plaintext = decrypt(ss);
		print_time();

		std::cout << "Result of worker " << i << ": " << plaintext.to_string()  << '\n';
		++i;
	}
}

seal::PublicKey Server::handshake() const {
	PublicKey key;
	keygen->create_public_key(key);
	return key;
}

void Server::add_worker(const std::string &address, size_t port_number) {
	ip::tcp::endpoint endpoint(ip::address::from_string(address), port_number);
	auto key = handshake();

	try {
		print_time();
		std::cout << "Try to connect to client: " <<  endpoint.address() << ":" << endpoint.port() << '\n';
		auto worker = Worker::build(param_stream, *context, key, endpoint);
		workers.push_back(worker);
	} catch(boost::system::error_code e) {
		std::cerr << e << '\n';
	}
	print_time();
	std::cout << "Connect to " << endpoint.address() << ":" << endpoint.port() << " success!\n";
}

seal::Serializable<seal::Ciphertext> Server::Worker::encrypt(const seal::Plaintext &text) const{
	return encryptor->encrypt(text);
}

void Server::Worker::encrypt(const seal::Plaintext &text, seal::Ciphertext &ciphertext) const {
	encryptor->encrypt(text, ciphertext);
}

void Server::Worker::work(const uint64_t x) {
	using namespace std::chrono_literals;

	auto x_cipher = encrypt(uint64_to_hex_string(x));
	auto two_cipher = encrypt(uint64_to_hex_string(2));
	std::stringstream ss;
	x_cipher.save(ss);
	two_cipher.save(ss);
	sock.send(buffer(ss.str()));
	std::this_thread::sleep_for(500ms);
	buf_len = sock.receive(buffer(buf));
	ss.write(buf.data(), buf_len);

}

const std::pair<boost::array<char, 319530>&, size_t>Server::Worker::get_res() {
	return {buf, buf_len};
}


std::shared_ptr<Server::Worker> Server::Worker::build(std::stringstream& params_stream, const seal::SEALContext &context, const seal::PublicKey &key,
									 const asio::ip::tcp::endpoint &endpoint)  {
	boost::system::error_code err;
	auto result = std::make_shared<Server::Worker>(context, key);

	auto &sock = result->get_socket();
	sock.connect(endpoint, err);

	if(err)
		throw err;

	sock.send(buffer(params_stream.str(), params_stream.str().length()));
	return result;
}


