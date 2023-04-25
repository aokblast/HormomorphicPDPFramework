//
// Created by aokblast on 2022/10/18.
//

#include <memory>
#include <seal/seal.h>
#include <libtfhe_core.h>
#include "common.h"
#include "libtfhe/include/Encryptor.hpp"
#include "libtfhe/include/Evaluator.hpp"
#include "libtfhe/include/KeyGenerator.hpp"
#include "libtfhe/include/Parameter.hpp"


int main() {
    auto tfhe_param = TFHE::Parameter(110);
    auto tfhe_keygen = TFHE::KeyGenerator(tfhe_param);
    auto tfhe_key = tfhe_keygen.generate_secret_key();
    auto tfhe_cloud_key = tfhe_key.get_cloud_key();
    auto tfhe_encryptor = TFHE::Encryptor<32>(tfhe_key, tfhe_param);
    auto tfhe_evaluator = TFHE::Evaluator<32>(tfhe_cloud_key);

    auto tfhe_cip1 = tfhe_encryptor.encrypt(5);
    auto tfhe_cip2 = tfhe_encryptor.encrypt(10);

    tfhe_evaluator.add_inplace(tfhe_cip1, tfhe_cip2);
    std::cout << std::to_string(tfhe_encryptor.decrypt(tfhe_cip1)) << '\n';
}
