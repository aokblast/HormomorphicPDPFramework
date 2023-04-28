#include <queue>
#include <algorithm>
#include "MD5.h"
#include "libtfhe_core.h"
#include "libhashtree.hpp"

HashTree::_Node::_Node(hash_value_t &&value): hash_value(std::forward<hash_value_t>(value)), left(nullptr), right(nullptr) {
}

std::vector<HashTree::hash_value_t> &&
HashTree::_hash_files(const std::vector<file_stream_t> &files, const TFHE::CloudKey &key) {
		std::vector<HashTree::hash_value_t> res;

		for (const auto &file: files)
				res.emplace_back(MD5::hash(file, key));

		return std::move(res);
}

static std::array<TFHE::CipherText<8>, 4> &&
word_to_byte(const TFHE::CipherText<32> &cip, const TFHE::CloudKey &key) {
		std::array<TFHE::CipherText<8>, 4> res;
		TFHE::Evaluator<32> word_eval(key);
		TFHE::Evaluator<8> byte_eval(key);

		for(int i = 0; i < 4; ++i) {
				TFHE::CipherText<8> tmp(key.get_parameter());

				for (int j = 0; j < 8; ++j)
						byte_eval.setBit(tmp, word_eval.extractBit(cip, i * 8 + j), 8);

				res[i] = std::move(tmp);
		}
		return std::move(res);
}


HashTree::_Node
HashTree::_build_tree(std::vector<hash_value_t> hashes, const TFHE::CloudKey &key) {
		std::queue<_Node> q;
		std::for_each(std::make_move_iterator(hashes.begin()), std::make_move_iterator(hashes.end())
									, [&q](hash_value_t &&hash){q.emplace(std::forward<hash_value_t>(hash));});

		while(q.size() > 1) {
				int sz = q.size();
				while((sz -= 2) > 1) {
						auto left = std::move(q.front()); q.pop();
						auto right = std::move(q.front()); q.pop();
						file_stream_t msg;

						auto replace_func = [&key, &msg](const TFHE::CipherText<32> &cip) {
								auto byte = word_to_byte(cip, key);
								msg.insert(msg.end(), std::make_move_iterator(byte.begin()), std::make_move_iterator(byte.end()));
						};

						std::for_each(left.hash_value.begin(), left.hash_value.end(), replace_func);

						std::for_each(right.hash_value.begin(), right.hash_value.end(), replace_func);

						_Node new_node(MD5::hash(msg, key));
						new_node.left = &left;
						new_node.right = &right;

						q.emplace(std::move(new_node));
				}
		}

		return std::move(q.front());
}


HashTree::HashTree(const std::vector<file_stream_t> &files, const TFHE::CloudKey &key)
    : _root(_build_tree(_hash_files(files, key), key)), _key(key) {
}

HashTree::hash_value_t &
HashTree::query() {
    return _root.hash_value;
}
