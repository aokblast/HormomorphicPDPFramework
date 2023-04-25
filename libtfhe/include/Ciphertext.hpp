#pragma once

#include "Parameter.hpp"
#include "CloudKey.hpp"
#include <cstddef>
#include <iostream>
#include <memory>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_core.h>
#include <tfhe/tfhe_gate_bootstrapping_functions.h>
#include <tfhe/tfhe_io.h>

namespace TFHE {
    template<std::size_t SZ>
    class CipherText;
}

template<std::size_t SZ> std::istream &
(operator>>)(std::istream &is, TFHE::CipherText<SZ> &text) {
    for (int i = 0; i < SZ; ++i)
        import_gate_bootstrapping_ciphertext_fromStream(is, text[i], text.get_raw_parameter());
    return is;
}

template<std::size_t SZ> std::ostream
&(operator<<)(std::ostream &os, const TFHE::CipherText<SZ> &text) {
    for (int i = 0; i < SZ; ++i)
        export_gate_bootstrapping_ciphertext_toStream(os, text[i], text.get_raw_parameter());
    return os;
}

namespace TFHE {
    template<std::size_t SZ>
    class CipherText {
    private:
        std::unique_ptr<LweSample, void (*)(LweSample *)> _sample;
        Parameter _p;

        TFheGateBootstrappingParameterSet
        *get_raw_parameter() const {
            return _p._param.get();
        }

        LweSample
        *operator[](size_t idx) {
            return _sample.get() + idx;
        }

        const LweSample
        *operator[](size_t idx) const {
            return _sample.get() + idx;
        }

    public:
        explicit CipherText(const Parameter &p) : _sample(new_gate_bootstrapping_ciphertext_array(SZ, p._param.get()),
                                                          [](LweSample *sample) {
                                                              delete_gate_bootstrapping_ciphertext_array(SZ, sample);
                                                          }) {
            _p = p;
        }

        explicit CipherText(const CipherText<SZ> &cip, const TFHE::CloudKey &key) : _sample(new_gate_bootstrapping_ciphertext_array(SZ, cip.get_raw_parameter()),
                                                          [](LweSample *sample) {
                                                              delete_gate_bootstrapping_ciphertext_array(SZ, sample);
                                                          }) {
            _p = cip.get_raw_parameter();
            for(int i = 0; i < SZ; ++i)
                bootsCOPY((*this)[i], cip[i], key._key.get());
        }

        CipherText(CipherText<SZ> &&) = default;

        CipherText<SZ> &
        operator=(CipherText<SZ> &&) = default;

        explicit CipherText() : _sample(nullptr, [](LweSample *sample) {}) {}

        void
        set(uint64_t val, const CloudKey &key) {
            for (size_t i = 0; i < SZ; ++i)
                bootsCONSTANT(_sample.get() + i, val & 1ull, key._key.get()), val >>= 1;
        }

        template<std::size_t T> friend
        class Encryptor;

        template<std::size_t T> friend
        class Evaluator;

        template<std::size_t T> friend std::istream &
        (::operator>>)(std::istream &is, TFHE::CipherText<T> &text);

        template<std::size_t T> friend std::ostream &
        (::operator<<)(std::ostream &os, const TFHE::CipherText<T> &text);
    };


}
