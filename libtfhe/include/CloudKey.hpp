#pragma once

#include <memory>
#include "Parameter.hpp"
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_core.h>

namespace TFHE {
    class CloudKey;
}

std::ostream &
operator<<(std::ostream &os, const TFHE::CloudKey &param);

std::istream &
operator>>(std::istream &is, TFHE::CloudKey &param);

namespace TFHE {
    class CloudKey {
    private:
        std::shared_ptr<TFheGateBootstrappingCloudKeySet> _key;

        explicit CloudKey(const TFheGateBootstrappingCloudKeySet *key);

        explicit CloudKey(TFheGateBootstrappingCloudKeySet *key);

    public:
        friend class SecretKey;

        template<size_t SZ> friend
        class Evaluator;

        template<size_t SZ> friend
        class CipherText;

        Parameter get_parameter() const;

        friend std::ostream &
        (::operator<<)(std::ostream &os, const TFHE::CloudKey &param);

        friend std::istream &
        (::operator>>)(std::istream &is, TFHE::CloudKey &param);
    };
}
