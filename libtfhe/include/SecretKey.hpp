#pragma once

#include <iostream>
#include <memory>
#include "Parameter.hpp"
#include "CloudKey.hpp"

namespace TFHE {
    class SecretKey;
}


std::istream &operator>>(std::istream &is, TFHE::SecretKey &rhs);

std::ostream &operator<<(std::ostream &os, const TFHE::SecretKey &rhs);

namespace TFHE {
    class SecretKey {
    private:
        std::shared_ptr<TFheGateBootstrappingSecretKeySet> _key;

        explicit SecretKey(TFheGateBootstrappingSecretKeySet *key);

    public:
        friend class KeyGenerator;

        template<std::size_t SZ> friend
        class Encryptor;

        friend std::istream &(::operator>>)(std::istream &is, TFHE::SecretKey &key);

        friend std::ostream &(::operator<<)(std::ostream &os, const TFHE::SecretKey &key);

        [[nodiscard]] CloudKey get_cloud_key() const;
    };
}

