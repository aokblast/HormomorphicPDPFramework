//
// Created by aokblast on 2023/5/2.
//

#include <fstream>
#include <libtfhe_core.h>
#include "common.h"
#include "libhashtree.hpp"
#include "libtfhe/include/Encryptor.hpp"
#include "libtfhe/include/KeyGenerator.hpp"
#include "libtfhe/include/Parameter.hpp"

using namespace TFHE;

static std::ostream &
operator<<(std::ostream &os, const HashTree::hash_value_t &hash_value) {
		for(const auto &i : hash_value)
				os << i;
		return os;
}

static std::ostream &
operator<<(std::ostream &os, const HashTree::file_stream_t &file_stream) {
	for(const auto &ch : file_stream)
			os << ch;
	return os;
}

int main(int argc, char *argv[]) {
		std::vector<CipherText <8>> text;
		Parameter parameter(110);
		KeyGenerator keyGenerator(parameter);
		auto secretKey = keyGenerator.generate_secret_key();
		auto cloudKey = secretKey.get_cloud_key();
		Encryptor<8> byte_encryptor(secretKey, parameter);

		std::stringstream file_names_stream;
		std::vector<std::string> file_names;

		if (argc == 2) {
				std::fstream fs(argv[1]);
				file_names_stream << fs.rdbuf();
		} else {
				std::string filename_file_path;
				std::cin >> filename_file_path;
				std::fstream fs(filename_file_path);
				file_names_stream << fs.rdbuf();
		}

		std::vector<HashTree::file_stream_t> files;

		std::ofstream secret_key_file("key.secret");
		std::ofstream cloud_key_file("key.cloud");
		std::ofstream parameter_file("parameter");

		secret_key_file << secretKey;
		cloud_key_file << cloudKey;
		parameter_file << parameter;

		for(std::string file_name; std::getline(file_names_stream, file_name); ) {
				std::ifstream file(file_name);
				std::cout << "File name: " << file_name << std::endl;

				for (std::istreambuf_iterator<char> iter(file), e; iter != e; ++iter) {
						text.push_back(byte_encryptor.encrypt((uint8_t) *iter));
				}

				files.emplace_back(std::move(text));
				file_names.push_back(file_name);
				text.clear();
		}

		std::cout << files.size() << std::endl;
		auto hash_values = HashTree::hash_files(files, cloudKey);

		for(int i = 0; i < file_names.size(); ++i) {
			std::ofstream hash_file(file_names[i] + ".MD5");
			std::ofstream encrypted_file(file_names[i] + ".enc");

			hash_file << hash_values[i];
			encrypted_file << files[i];
		}

		std::cout << '\n';
}
