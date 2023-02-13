//
// Created by aokblast on 2023/1/6.
//


#include <iostream>
#include <sstream>
#include "libtfhe_core.h"
#include "MD5.h"

using namespace TFHE;

int main() {
	std::vector<CipherText<8>> text;
	Parameter parameter(110);

	KeyGenerator keyGenerator(parameter);
	auto secretKey = keyGenerator.generate_secret_key();
	auto cloudKey = secretKey.get_cloud_key();
	Encryptor<8> byte_encryptor(secretKey, parameter);
	Encryptor<32> word_encryptor(secretKey, parameter);


	for(const auto c : "") {
		text.push_back(byte_encryptor.encrypt((uint8_t)c));
	}

	text.pop_back();


	auto res = MD5::hash(text, cloudKey);

	std::stringstream ss;

	for(const auto &num : res)
		std::cout << std::hex << word_encryptor.decrypt(num), ss << num;

	std::cout << '\n';
	ss.seekp(0, std::ios::end);
	std::cout << "Size: " << ss.tellp() << '\n';
}
