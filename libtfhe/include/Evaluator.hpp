#pragma once

#include "Ciphertext.hpp"
#include "CloudKey.hpp"
#include <cassert>
#include <iostream>
#include <utility>

namespace TFHE {
    template<std::size_t SZ>
    class Evaluator {
    private:
        CloudKey _key;
        std::shared_ptr<CipherText<SZ>> zero, one;

        void binary_mux_inplace(const LweSample *cond, const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            for (size_t i = 0; i < SZ; ++i)
                bootsMUX(lhs[i], cond, lhs[i], rhs[i]);
        }

        CipherText<SZ> binary_mux(const LweSample *cond, const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> res(_key.get_parameter());
            res.set(0, _key);

            for (size_t i = 0; i < SZ; ++i)
                bootsMUX(res[i], cond, lhs[i], rhs[i], _key._key.get());

            return res;
        }

    public:

        explicit Evaluator(const CloudKey &cloudKey) : _key(cloudKey),
                                                       zero(std::make_shared<CipherText<SZ>>(_key.get_parameter())),
                                                       one(std::make_shared<CipherText<SZ>>(_key.get_parameter())) {
            zero->set(0, cloudKey);
            one->set(1, cloudKey);
        }

        [[nodiscard]] Parameter get_parameter() const {
            return _key.get_parameter();
        }


        CipherText<SZ> constant(uint64_t val) const {
            CipherText<SZ> res(_key.get_parameter());

            for (size_t i = 0; i < SZ; ++i)
                bootsCONSTANT(res[i], val & 1ull, _key._key.get()), val >>= 1;

            return res;
        }


        void assign(CipherText<SZ> &text, uint64_t val) const {
            for (size_t i = 0; i < SZ; ++i)
                bootsCONSTANT(text[i], val & 1ull, _key._key.get()), val >>= 1;
        }

        void not_gate_inplace(CipherText<SZ> &lhs) const {
            for (size_t i = 0; i < SZ; ++i)
                bootsNOT(lhs[i], lhs[i], _key._key.get());
        }

        CipherText<SZ> not_gate(const CipherText<SZ> &lhs) const {
            CipherText<SZ> res(_key.get_parameter());

            for (int i = 0; i < SZ; ++i)
                bootsNOT(res[i], lhs[i], _key._key.get());

            return res;
        }

        void copy_inplace(CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            for (size_t i = 0; i < SZ; ++i)
                bootsCOPY(lhs[i], rhs[i], _key._key.get());
        }

        CipherText<SZ> copy(const CipherText<SZ> &lhs) const {
            CipherText<SZ> res(_key.get_parameter());
            res.set(0, _key);

            for (size_t i = 0; i < SZ; ++i)
                bootsCOPY(res[i], lhs[i], _key._key.get());

            return res;
        }

        void nand_gate_inplace(CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            for (size_t i = 0; i < SZ; ++i)
                bootsNAND(lhs[i], lhs[i], rhs[i], _key._key.get());
        }

        CipherText<SZ> nand_gate(const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> res(_key.get_parameter());
            res.set(0, _key);

            for (size_t i = 0; i < SZ; ++i)
                bootsNAND(res[i], lhs[i], rhs[i], _key._key.get());

            return res;
        }

        void or_gate_inplace(CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            for (size_t i = 0; i < SZ; ++i)
                bootsOR(lhs[i], lhs[i], rhs[i], _key._key.get());
        }

        CipherText<SZ> or_gate(const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> res(_key.get_parameter());
            res.set(0, _key);

            for (size_t i = 0; i < SZ; ++i)
                bootsOR(res[i], lhs[i], rhs[i], _key._key.get());

            return res;
        }

        void and_gate_inplace(CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            for (size_t i = 0; i < SZ; ++i)
                bootsAND(lhs[i], lhs[i], rhs[i], _key._key.get());
        }

        CipherText<SZ> and_gate(const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> res(_key.get_parameter());
            res.set(0, _key);

            for (size_t i = 0; i < SZ; ++i)
                bootsAND(res[i], lhs[i], rhs[i], _key._key.get());

            return res;
        }

        void xor_gate_inplace(CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            for (size_t i = 0; i < SZ; ++i)
                bootsXOR(lhs[i], lhs[i], rhs[i], _key._key.get());
        }

        CipherText<SZ> xor_gate(const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> res(_key.get_parameter());
            res.set(0, _key);

            for (size_t i = 0; i < SZ; ++i)
                bootsXOR(res[i], lhs[i], rhs[i], _key._key.get());

            return res;
        }

        void mux_inplace(const CipherText<SZ> &cond, CipherText<SZ> &lhs, const CipherText<SZ> &rhs) {
            for (size_t i = 0; i < SZ; ++i)
                bootsMUX(lhs[i], cond[i], lhs[i], rhs[i], _key._key.get());
        }

        CipherText<SZ> mux(const CipherText<SZ> &cond, const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> res(_key.get_parameter());
            res.set(0, _key);

            for (size_t i = 0; i < SZ; ++i)
                bootsMUX(res[i], cond[i], lhs[i], rhs[i], _key._key.get());

            return res;
        }

        CipherText<SZ> binary_mux_inplace(const CipherText<1> &cond, CipherText<SZ> &lhs, const CipherText<SZ> &rhs) {
            for (size_t i = 0; i < SZ; ++i)
                bootsMUX(lhs[i], cond[0], lhs[i], rhs[i], _key._key.get());

            return lhs;
        }

        CipherText<SZ>
        binary_mux(const CipherText<1> &cond, const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> res(_key.get_parameter());
            res.set(0, _key);

            for (size_t i = 0; i < SZ; ++i)
                bootsMUX(res[i], cond[0], lhs[i], rhs[i], _key._key.get());

            return res;
        }

        void left_shift_inplace(CipherText<SZ> &lhs, uint64_t shift) const {
            assert(SZ >= shift);

            for (size_t i = SZ - 1; i >= shift; --i)
                bootsCOPY(lhs[i], lhs[i - shift], _key._key.get());

            for (size_t i = 0; i < shift; ++i)
                bootsCONSTANT(lhs[i], 0, _key._key.get());
        }

        CipherText<SZ> left_shift(const CipherText<SZ> &lhs, uint64_t shift) const {
            assert(SZ >= shift);
            CipherText<SZ> res(_key.get_parameter());
            res.set(0, _key);

            for (size_t i = shift; i < SZ; ++i)
                bootsCOPY(res[i], lhs[i - shift], _key._key.get());

            return res;
        }

        void right_shift_inplace(CipherText<SZ> &lhs, uint64_t shift) const {
            assert(SZ >= shift);

            for (size_t i = 0; i < SZ - shift; ++i)
                bootsCOPY(lhs[i], lhs[i + shift], _key._key.get());

            for (size_t i = SZ - shift; i < SZ; ++i)
                bootsCONSTANT(lhs[i], 0, _key._key.get());
        }

        CipherText<SZ> right_shift(const CipherText<SZ> &lhs, uint64_t shift) const {
            assert(SZ >= shift);

            CipherText<SZ> res(_key.get_parameter());
            res.set(0, _key);

            for (size_t i = shift; i < SZ; ++i)
                bootsCOPY(res[i - shift], lhs[i], _key._key.get());

            return res;
        }

        CipherText<1> extractBit(const CipherText<SZ> &lhs, uint64_t bit) const {
            CipherText<1> res(_key.get_parameter());

            bootsCOPY(res[0], lhs[bit], _key._key.get());

            return res;
        }

        void setBit(CipherText<SZ> &lhs, const CipherText<1> &rhs, uint64_t bit) const {
            bootsCOPY(lhs[bit], rhs[0], _key._key.get());
        }

        void add_inplace(CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<2> carry(_key.get_parameter());
            CipherText<2> tmp(_key.get_parameter());
            carry.set(false, _key);
            auto cc = carry[0];
            auto cp = carry[1];
            auto t1 = tmp[0];
            auto t2 = tmp[1];

            for (size_t i = 0; i < SZ; ++i) {
                bootsOR(t1, lhs[i], rhs[i], _key._key.get());
                bootsAND(t2, lhs[i], rhs[i], _key._key.get());
                bootsMUX(cc, cp, t1, t2, _key._key.get());
                bootsXOR(lhs[i], lhs[i], cp, _key._key.get());
                bootsXOR(lhs[i], lhs[i], rhs[i], _key._key.get());
                bootsCOPY(cp, cc, _key._key.get());
            }

        }

        CipherText<SZ> add(const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> res(_key.get_parameter());
            copy_inplace(res, lhs);
            add_inplace(res, rhs);
            return res;
        }

        void subtract_inplace(CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> lead(_key.get_parameter());
            CipherText<SZ> tmp(_key.get_parameter());
            lead.set(0, _key);
            auto lp = lead[0], lc = lead[1];
            auto t1 = tmp[0], t2 = tmp[1];

            for (size_t i = 0; i < SZ; ++i) {
                bootsOR(t1, lp, rhs[i], _key._key.get());
                bootsAND(t2, lp, rhs[i], _key._key.get());
                bootsMUX(lc, lhs[i], t2, t1, _key._key.get());
                bootsXOR(lhs[i], lhs[i], lp, _key._key.get());
                bootsXOR(lhs[i], lhs[i], rhs[i], _key._key.get());
                bootsCOPY(lp, lc, _key._key.get());
            }
        }

        CipherText<SZ> subtract(const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> res(_key.get_parameter());
            copy_inplace(res, lhs);
            subtract_inplace(res, rhs);
            return res;
        }

        void multiply_inplace(CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            auto tmp = copy(lhs);
            lhs.set(0, _key);

            for (size_t i = 0; i < SZ; ++i)
                add_inplace(lhs, binary_mux(rhs[i], left_shift(tmp, i), *zero));
        }

        CipherText<SZ> multiply(const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> res(_key.get_parameter());
            copy_inplace(res, lhs);
            multiply_inplace(res, rhs);
            return res;
        }

        CipherText<1> compare(const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            auto l = copy(lhs);
            CipherText<SZ> lead(_key.get_parameter());
            CipherText<SZ> tmp(_key.get_parameter());
            lead.set(0, _key);
            auto lp = lead[0], lc = lead[1];
            auto t1 = tmp[0], t2 = tmp[1];

            for (size_t i = 0; i < SZ; ++i) {
                bootsOR(t1, lp, rhs[i], _key._key.get());
                bootsAND(t2, lp, rhs[i], _key._key.get());
                bootsMUX(lc, l[i], t2, t1, _key._key.get());
                bootsXOR(l[i], l[i], lp, _key._key.get());
                bootsXOR(l[i], l[i], rhs[i], _key._key.get());
                bootsCOPY(lp, lc, _key._key.get());
            }

            CipherText<1> res(_key.get_parameter());

            bootsCOPY(res[0], lc, _key._key.get());
            bootsNOT(res[0], res[0], _key._key.get());

            return res;
        }

        CipherText<1> overflow(const CipherText<SZ> &lhs, size_t shift) const {
            CipherText<1> res(_key.get_parameter());
            res.set(0, _key);

            for (size_t i = SZ - shift; i < SZ; ++i)
                bootsOR(res[0], res[0], lhs[i], _key._key.get());

            return res;
        }

        CipherText<SZ> divide_inplace(CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> tmp(_key.get_parameter());
            CipherText<1> cmpVal(_key.get_parameter());
            tmp.set(0, _key);
            for (int i = SZ - 1; i >= 0; --i) {
                auto ovf = overflow(rhs, i);
                auto left_shift_val = left_shift(rhs, i);
                bootsMUX(cmpVal[0], compare(lhs, left_shift_val)[0], (*one)[0], (*zero)[0], _key._key.get());
                bootsMUX(tmp[i], ovf[0], (*zero)[0], cmpVal[0], _key._key.get());
                subtract_inplace(lhs, binary_mux(ovf[0], (*zero),
                                                 binary_mux(compare(lhs, left_shift_val), left_shift_val, (*zero))));
            }
            auto tmp2 = copy(lhs);
            copy_inplace(lhs, tmp);
            return tmp2;
        }

        CipherText<SZ> divide(const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            CipherText<SZ> res(_key.get_parameter());
            copy_inplace(res, lhs);
            auto mod = divide_inplace(res, rhs);
            return res;
        }

        void module_inplace(CipherText<SZ> &lhs, const CipherText<SZ> &rhs) const {
            auto res = divide_inplace(lhs, rhs);
            copy_inplace(lhs, res);
        }

        CipherText<SZ> module(const CipherText<SZ> &lhs, const CipherText<SZ> &rhs) {
            CipherText<SZ> res(_key.get_parameter());
            copy_inplace(res, lhs);
            module_inplace(res, rhs);
            return res;
        }

    };
}
