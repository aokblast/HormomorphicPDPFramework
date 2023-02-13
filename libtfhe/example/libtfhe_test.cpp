//
// Created by aokblast on 2022/12/8.
//

#include "libtfhe_core.h"
#include "sstream"

using namespace TFHE;

constexpr	size_t bit = 32;

int main() {
	Parameter parameter(110);

	KeyGenerator keyGenerator(parameter);


	auto secretKey = keyGenerator.generate_secret_key();
	std::stringstream ss;

	auto cloudKey = secretKey.get_cloud_key();

	Encryptor<bit> encryptor(secretKey, parameter);

	auto fifty_encrypt = encryptor.encrypt(50);
	auto six_encrypt = encryptor.encrypt(6);
	auto five_encrypt = encryptor.encrypt(5);

	Evaluator<bit> evaluator(cloudKey);

	// auto oao = evaluator.left_shift(eight_encrypt, 4);
	auto eight_encrypt = evaluator.multiply(fifty_encrypt, six_encrypt);

	std::cout << encryptor.decrypt(eight_encrypt) << '\n';


	// auto fifty_six = evaluator.multiply(fifty_encrypt, six_encrypt);
	// auto msg = encryptor.decrypt(fifty_six);

	// std::cout << msg << '\n';

	// msg = encryptor.decrypt(fifty_six);

	// std::cout << msg << '\n';

}