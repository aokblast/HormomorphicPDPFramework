//
// Created by aokblast on 2023/1/6.
//


#include <iostream>
#include <fstream>
#include <sstream>
#include "MD5.h"

using namespace TFHE;

int main(int argc, char *argv[]) {
    std::vector<CipherText <8>> text;
    Parameter parameter(110);

    KeyGenerator keyGenerator(parameter);
    auto secretKey = keyGenerator.generate_secret_key();
    auto cloudKey = secretKey.get_cloud_key();
    Encryptor<8> byte_encryptor(secretKey, parameter);
    Encryptor<32> word_encryptor(secretKey, parameter);

    std::fstream fs(argv[1]);
    std::stringstream buffer;

    buffer << fs.rdbuf();

    for (const auto c: buffer.str()) {
        text.push_back(byte_encryptor.encrypt((uint8_t) c));
    }

    std::array<CipherText<32>, 4> res = MD5::hash(text, cloudKey);

    for (const auto &num: res)
        std::cout << std::hex << word_encryptor.decrypt(num);

    std::cout << '\n';
}
