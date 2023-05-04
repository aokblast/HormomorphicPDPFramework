//
// Created by aokblast on 2023/1/6.
//

#include <array>
#include <vector>
#include <algorithm>
#include "MD5.h"
#include "Common.h"

using namespace TFHE;
using namespace std;

namespace MD5 {
    constexpr static std::array<uint32_t, 64> _r = {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    constexpr static std::array<uint32_t, 64> _k = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                                                    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                                                    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                                                    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                                                    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                                                    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                                                    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                                                    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                                                    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                                                    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                                                    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                                                    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                                                    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                                                    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                                                    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                                                    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

    template<size_t Sz> inline static CipherText <Sz>
    left_rotate(const CipherText <Sz> &num, size_t offset, const Evaluator <Sz> &eval) {
        return eval.or_gate(eval.left_shift(num, offset), eval.right_shift(num, Sz - offset));
    }


    static void
    swapByteOrder(CipherText<32> &cip, const Evaluator<32> &word_eval) {
        cip = word_eval.or_gate(word_eval.right_shift(cip, 24), word_eval.or_gate(
                word_eval.and_gate(word_eval.left_shift(cip, 8), word_eval.constant(0x00FF0000)),
                word_eval.or_gate(word_eval.and_gate(word_eval.right_shift(cip, 8), word_eval.constant(0x0000FF00)),
                                  word_eval.left_shift(cip, 24))));
    }


    hash_value_t
    hash(const vector<CipherText<8>> &_message, const CloudKey &key) {
        const Evaluator<32> word_eval(key);
        const Evaluator<8> byte_eval(key);

        array<CipherText<32>, 64> k;

        for (int i = 0; i < 64; ++i)
            k[i] = word_eval.constant(_k[i]);

        std::array<CipherText<32>, 4> h = {word_eval.constant(0x67452301), word_eval.constant(0xEFCDAB89),
                                           word_eval.constant(0x98BADCFE), word_eval.constant(0x10325476)};

        std::vector<CipherText<8>> msg;

        for (const auto &c: _message)
            msg.emplace_back(byte_eval.copy(c));


        msg.emplace_back(byte_eval.constant(0x80));
        uint64_t msg_len = msg.size();
        uint64_t padding_len = ((msg_len % 64ull) > 56ull) ? (56ull + (64ull - msg_len % 64ull)) : (56ull -
                                                                                                    msg_len % 64ull);

        for (size_t i = 0; i < padding_len; ++i)
            msg.emplace_back(byte_eval.constant(0));

        const auto len = to_littleEndian((msg_len - 1) * 8);

        for (int i = 0; i < 8; ++i)
            msg.emplace_back(byte_eval.constant(len[i]));

        msg_len = msg.size();

        const auto byteToWordEncryptText = [&](CipherText<8> &byte) {
            CipherText<32> word(key.get_parameter());

            word_eval.assign(word, 0);

            for (int i = 0; i < 8; ++i) {
                word_eval.setBit(word, byte_eval.extractBit(byte, i), i);
            }

            return word;
        };

        for (size_t i = 0; i < msg_len; i += 64) {

            std::array<CipherText<32>, 16> w;

            for (int j = 0; j < 64; j += 4) {
                auto m0 = byteToWordEncryptText(msg[i + j]), m1 = word_eval.left_shift(
                        byteToWordEncryptText(msg[i + j + 1]), 8)
                , m2 = word_eval.left_shift(byteToWordEncryptText(msg[i + j + 2]), 16), m3 = word_eval.left_shift(
                        byteToWordEncryptText(msg[i + j + 3]), 24);
                w[j / 4] = word_eval.or_gate(m0, word_eval.or_gate(m1, word_eval.or_gate(m2, m3)));
            }
            auto a = word_eval.copy(h[0]);
            auto b = word_eval.copy(h[1]);
            auto c = word_eval.copy(h[2]);
            auto d = word_eval.copy(h[3]);

            for (int j = 0; j < 64; ++j) {
                CipherText<32> f;
                uint32_t g;
                switch (j / 16) {
                    case 0:
                        f = word_eval.or_gate(word_eval.and_gate(b, c), word_eval.and_gate(word_eval.not_gate(b), d));
                        g = j;
                        break;
                    case 1:
                        f = word_eval.or_gate(word_eval.and_gate(d, b), word_eval.and_gate(word_eval.not_gate(d), c));
                        g = (5 * j + 1) % 16;
                        break;
                    case 2:
                        f = word_eval.xor_gate(b, word_eval.xor_gate(c, d));
                        g = (3 * j + 5) % 16;
                        break;
                    case 3:
                        f = word_eval.xor_gate(c, word_eval.or_gate(b, word_eval.not_gate(d)));
                        g = (7 * j) % 16;
                        break;
                }

                CipherText<32> tmp(key.get_parameter());
                word_eval.copy_inplace(tmp, d);
                word_eval.copy_inplace(d, c);
                word_eval.copy_inplace(c, b);

                b = word_eval.add(left_rotate(
                        word_eval.add(a,
                                      word_eval.add(f,
                                                    word_eval.add(k[j], w[g]))), _r[j], word_eval), b);
                word_eval.copy_inplace(a, tmp);
            }

            word_eval.add_inplace(h[0], a);
            word_eval.add_inplace(h[1], b);
            word_eval.add_inplace(h[2], c);
            word_eval.add_inplace(h[3], d);
        }

        for (auto &c: h)
            swapByteOrder(c, word_eval);

        return h;
    }

}
