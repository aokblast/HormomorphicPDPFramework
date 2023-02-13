#pragma once

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_core.h>
#include <tfhe/tfhe_io.h>
#include <memory>
#include <iostream>

namespace TFHE {
  class Parameter;
}

std::ostream &operator<<(std::ostream &os, const TFHE::Parameter &param);
std::istream &operator>>(std::istream &is, TFHE::Parameter &param);

namespace TFHE {
  class Parameter {
  private:
    std::shared_ptr<TFheGateBootstrappingParameterSet> _param;

  public:
    friend std::ostream &(::operator<<)(std::ostream &os, const TFHE::Parameter &param);
    friend std::istream &(::operator>>)(std::istream &is, TFHE::Parameter &param);
    friend class KeyGenerator;
    template <std::size_t SZ> friend class CipherText;
    Parameter() = default;
    explicit Parameter(int lambda);
		explicit Parameter(const TFheGateBootstrappingParameterSet *);
  };
}

