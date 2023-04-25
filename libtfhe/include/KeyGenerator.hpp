#pragma once

#include <iostream>
#include "Parameter.hpp"
#include "SecretKey.hpp"

namespace TFHE {
    class KeyGenerator {
    private:
        Parameter _param;
    public:
        explicit KeyGenerator(const Parameter &param);

        SecretKey
        generate_secret_key() const;
    };
}
