//
// Created by aokblast on 2022/12/25.
//

#include "SHA256.h"
#include <iostream>
#include <vector>

using namespace TFHE;

int main() {
	std::vector<CipherText<8>> text;
	Parameter parameter(110);

	KeyGenerator keyGenerator(parameter);
	auto secretKey = keyGenerator.generate_secret_key();
	auto cloudKey = secretKey.get_cloud_key();
	Encryptor<8> byte_encryptor(secretKey, parameter);
	Encryptor<32> word_encryptor(secretKey, parameter);


	for(const auto c : "Hello World!") {
		text.push_back(byte_encryptor.encrypt((uint8_t)c));
	}

	text.pop_back();

	auto res = SHA256::hash(text, cloudKey);

	for(const auto &num : res)
		std::cout << std::hex << word_encryptor.decrypt(num);

	std::cout << '\n';
}
