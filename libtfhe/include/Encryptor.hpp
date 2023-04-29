#pragma once

#include <utility>

#include "SecretKey.hpp"
#include "Ciphertext.hpp"

namespace TFHE {
    template<std::size_t SZ>
    class Encryptor {
    private:
        SecretKey _key;
        Parameter _param;
    public:
        Encryptor(SecretKey &key, const Parameter &param) : _key(key) {
            _param = param;
        }

        CipherText<SZ>
        encrypt(uint64_t msg) const {
            CipherText<SZ> text(_param);
            for (size_t i = 0; i < SZ; ++i)
                bootsSymEncrypt(text._sample.get() + i, msg & 1ull, _key._key.get()), msg >>= 1;
            return text;
        }

        uint64_t
        decrypt(const CipherText<SZ> &cip) const {
            uint64_t res = 0;
            for (size_t i = SZ - 1; i >= 0; --i)
                res <<= 1, res |= bootsSymDecrypt(cip._sample.get() + i, _key._key.get());
            return res;
        }
    };
}
