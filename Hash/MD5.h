//
// Created by aokblast on 2023/1/6.
//

#ifndef HORMOMORPHICHASHCHECKER_MD5_H
#define HORMOMORPHICHASHCHECKER_MD5_H

#include <string_view>
#include <array>
#include "libtfhe_core.h"

namespace MD5 {
    std::array<TFHE::CipherText<32>, 4>
    hash(const std::vector<TFHE::CipherText<8>> &_message, const TFHE::CloudKey &key);
}


#endif //HORMOMORPHICHASHCHECKER_MD5_H
