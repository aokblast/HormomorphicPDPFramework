//
// Created by aokblast on 2022/10/18.
//

#ifndef HORMOMORPHICHASHCHECKER_SHA256_H
#define HORMOMORPHICHASHCHECKER_SHA256_H

#include <cstdint>
#include <array>
#include <string_view>
#include "libtfhe_core.h"


namespace SHA256 {
		using hash_value_t = std::array<TFHE::CipherText<32>, 8>;

		hash_value_t
    hash(const std::vector<TFHE::CipherText<8>>&, const TFHE::CloudKey &key);
}


#endif //HORMOMORPHICHASHCHECKER_SHA256_H
