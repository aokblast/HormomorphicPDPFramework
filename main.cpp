//
// Created by aokblast on 2022/10/18.
//

#include <fstream>
#include <libtfhe_core.h>
#include "common.h"
#include "libhashtree.hpp"
#include "libtfhe/include/Encryptor.hpp"
#include "libtfhe/include/KeyGenerator.hpp"
#include "libtfhe/include/Parameter.hpp"

using namespace TFHE;

static std::istream &
operator>>(std::istream &is, HashTree::hash_value_t &hash_value) {
		for(auto &i : hash_value)
				is >> i;

		return is;
}

int main(int argc, char *argv[]) {
		Parameter parameter;
		SecretKey secretKey;
		CloudKey cloudKey;

		std::ifstream secret_key_file("key.secret");
		std::ifstream cloud_key_file("key.cloud");
		std::ifstream parameter_file("parameter");

		parameter_file >> parameter;
		secret_key_file >> secretKey;
		cloud_key_file >> cloudKey;

		Encryptor<8> byte_encryptor(secretKey, parameter);
		Encryptor<32> word_encryptor(secretKey, parameter);

		std::stringstream file_names_file;

		if (argc == 2) {
				std::fstream fs(argv[1]);
				file_names_file << fs.rdbuf();
		} else {
				std::string files;
				std::cin >> files;
				std::fstream fs(files);
				file_names_file << fs.rdbuf();
		}

		std::vector<HashTree::hash_value_t> hash_values;

		for(std::string file_name; std::getline(file_names_file, file_name); ) {
				std::ifstream file(file_name + ".MD5");
				std::cout << "File name: " << file_name << std::endl;

				HashTree::hash_value_t hash_value;

				for(auto &hash: hash_value)
						hash = CipherText<32>(parameter);

				file >> hash_value;

				hash_values.emplace_back(std::move(hash_value));
		}

		HashTree t(std::move(hash_values), cloudKey);

		for (const auto &num: t.query())
				std::cout << std::hex << word_encryptor.decrypt(num);

		std::cout << '\n';
}
