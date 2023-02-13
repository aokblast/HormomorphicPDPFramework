//
// Created by aokblast on 2022/9/13.
//

#ifndef MD5CHECKERINCPP_SERVER_H
#define MD5CHECKERINCPP_SERVER_H
#include <seal/seal.h>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <memory>
#include <boost/system/error_code.hpp>

namespace asio = boost::asio;

class Server {

	class Worker{

		std::unique_ptr<seal::Encryptor> encryptor;
		std::unique_ptr<std::thread> thread;

		boost::array<char, 319530> buf;
		size_t buf_len;
		asio::io_service service;
		asio::ip::tcp::socket sock;



		[[nodiscard]] seal::Serializable<seal::Ciphertext> encrypt(const seal::Plaintext &text) const;
		void encrypt(const seal::Plaintext &text, seal::Ciphertext &ciphertext) const;
	public:
		explicit Worker(const seal::SEALContext &context, const seal::PublicKey& key) : service(), sock(service){
			boost::system::error_code err;
			encryptor = std::make_unique<seal::Encryptor>(context, key);
		}

		friend class Server;
		static std::shared_ptr<Worker> build(std::stringstream& params_stream, const seal::SEALContext &context, const seal::PublicKey& key, const asio::ip::tcp::endpoint &endpoint);
		void work(uint64_t data);
		const std::pair<boost::array<char, 319530>&, size_t> get_res();


		inline asio::ip::tcp::socket &get_socket() {
			return sock;
		}
	};

	const static size_t DEFAULT_PORT_NUMBER = 8787;

	seal::SecretKey secret_key;
	std::stringstream param_stream;
	std::unique_ptr<seal::SEALContext> context;
	std::unique_ptr<seal::KeyGenerator> keygen;
	std::unique_ptr<seal::Decryptor> decryptor;
	std::vector<std::shared_ptr<Worker>> workers;

	seal::PublicKey handshake() const;

public:
	Server() = delete;
	Server& operator=(const Server&) = delete;
	Server(const Server&) = delete;
	explicit Server(size_t poly_module_degree, size_t plain_module, seal::scheme_type type);


	seal::Plaintext decrypt(std::istream &text) const;
	void add_worker(const std::string &address, size_t port_number = DEFAULT_PORT_NUMBER);
	void run(const std::vector<uint64_t>&);

};


#endif //MD5CHECKERINCPP_SERVER_H
