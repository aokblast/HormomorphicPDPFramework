//
// Created by aokblast on 2022/10/18.
//

#include "SHA256.h"
#include <vector>
#include <algorithm>
#include "Common.h"

using namespace std;
using namespace TFHE;

namespace SHA256 {
	constexpr static array<uint32_t, 8> INIT_HASH =
			{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
			,0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

	constexpr static array<uint32_t, 64> SEG =
			{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};


	template<size_t Sz> inline static CipherText<Sz> right_rotate(const CipherText<Sz> &num, size_t offset, const Evaluator<Sz> &eval) {
		return eval.or_gate(eval.right_shift(num, offset), eval.left_shift(num, Sz - offset));
	}

	array<CipherText<32>, 8> hash(const vector<CipherText<8>>& _message, const CloudKey &key) {
		array<CipherText<32>, 8> res;
		array<CipherText<32>, 64> SEGMENT;

		const Evaluator<32> word_eval(key);
		const Evaluator<8> byte_eval(key);

		for(int i = 0; i < 8; ++i)
			res[i] = word_eval.constant(INIT_HASH[i]);


		for(int i = 0; i < 64; ++i)
			SEGMENT[i] = word_eval.constant(SEG[i]);


		vector<CipherText<8>> msg;

		for(const auto & i : _message)
			msg.emplace_back(byte_eval.copy(i));

		msg.emplace_back(byte_eval.constant(0x80));
		uint64_t msg_len = msg.size();
		uint64_t padding_len = ((msg_len % 64ull) > 56ull) ? (56ull + (64ull - msg_len % 64ull)) : (56ull - msg_len % 64ull);

		for(int i = 0; i < padding_len; ++i)
			msg.emplace_back(byte_eval.constant(0));

		const auto len = to_bigEndian((msg_len - 1) * 8);

		for(unsigned char i : len)
			msg.emplace_back(byte_eval.constant(i));


		const auto byteToWordEncryptText = [&](CipherText<8> &byte) {
			CipherText<32> word(word_eval.get_parameter());

			word_eval.assign(word, 0);

			for(int i = 0; i < 8; ++i) {
				word_eval.setBit(word, byte_eval.extractBit(byte, i), i);
			}

			return word;
		};

		msg_len = msg.size();

		for(int i = 0; i < msg_len; i += 64) {
			array<CipherText<32>, 64> w;


			for(int j = 0; j < 64; j += 4) {
				auto m0 = word_eval.left_shift(byteToWordEncryptText(msg[i + j]), 24), m1 = word_eval.left_shift(byteToWordEncryptText(msg[i + j + 1]), 16)
								, m2 = word_eval.left_shift(byteToWordEncryptText(msg[i + j + 2]), 8), m3 = byteToWordEncryptText(msg[i + j + 3]);

				w[j / 4] = word_eval.or_gate(m0, word_eval.or_gate(m1, word_eval.or_gate(m2, m3)));
			}


			for(int j = 16; j < 64; ++j) {

				const auto s0 = word_eval.xor_gate(right_rotate(w[j - 15], 7, word_eval)
								, word_eval.xor_gate(right_rotate(w[j - 15], 18, word_eval), word_eval.right_shift(w[j - 15], 3)));
				const auto s1 = word_eval.xor_gate(right_rotate(w[j - 2], 17, word_eval)
								, word_eval.xor_gate(right_rotate(w[j - 2], 19, word_eval), word_eval.right_shift(w[j - 2], 10)));

				w[j] = word_eval.add(w[j - 16], word_eval.add(s0, word_eval.add(w[j - 7], s1)));
			}

			auto a = word_eval.copy(res[0]);
			auto b = word_eval.copy(res[1]);
			auto c = word_eval.copy(res[2]);
			auto d = word_eval.copy(res[3]);
			auto e = word_eval.copy(res[4]);
			auto f = word_eval.copy(res[5]);
			auto g = word_eval.copy(res[6]);
			auto h = word_eval.copy(res[7]);


			for(int j = 0; j < 64; ++j) {
				const auto s0 = word_eval.xor_gate(right_rotate(a, 2, word_eval), word_eval.xor_gate(right_rotate(a, 13, word_eval), right_rotate(a, 22, word_eval)));
				const auto maj = word_eval.xor_gate(word_eval.and_gate(a, b), word_eval.xor_gate(word_eval.and_gate(a, c), word_eval.and_gate(b, c)));
				const auto t2 = word_eval.add(s0, maj);
				const auto s1 = word_eval.xor_gate(right_rotate(e, 6, word_eval), word_eval.xor_gate(right_rotate(e, 11, word_eval), right_rotate(e, 25, word_eval)));
				const auto ch = word_eval.xor_gate(word_eval.and_gate(e, f), word_eval.and_gate(word_eval.not_gate(e), g));
				const auto t1 = word_eval.add(h, word_eval.add(s1, word_eval.add(ch, word_eval.add(SEGMENT[j], w[j]))));
				word_eval.copy_inplace(h, g);
				word_eval.copy_inplace(g, f);
				word_eval.copy_inplace(f, e);
				e = word_eval.add(d, t1);
				word_eval.copy_inplace(d, c);
				word_eval.copy_inplace(c, b);
				word_eval.copy_inplace(b, a);
				a = word_eval.add(t1, t2);
			}

			word_eval.add_inplace(res[0], a);
			word_eval.add_inplace(res[1], b);
			word_eval.add_inplace(res[2], c);
			word_eval.add_inplace(res[3], d);
			word_eval.add_inplace(res[4], e);
			word_eval.add_inplace(res[5], f);
			word_eval.add_inplace(res[6], g);
			word_eval.add_inplace(res[7], h);

		}

		return res;
	}


}